#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Claude Proxy Server — deploy script
# Устанавливает Docker, nginx, доставляет SSL-сертификаты,
# собирает и запускает контейнер, настраивает reverse proxy.
# Идемпотентен — безопасно запускать повторно.
#
# Использование: sudo bash deploy.sh
# ============================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -------------------- helpers --------------------

log()  { echo -e "\n\033[1;32m[deploy]\033[0m $*"; }
warn() { echo -e "\n\033[1;33m[deploy]\033[0m $*"; }
err()  { echo -e "\n\033[1;31m[deploy]\033[0m $*" >&2; }

# -------------------- step 0: root check --------------------

if [[ $EUID -ne 0 ]]; then
    err "Скрипт должен быть запущен от root: sudo bash deploy.sh"
    exit 1
fi

# -------------------- step 1: install dependencies --------------------

log "Проверка зависимостей..."

# Docker Engine
if ! command -v docker &>/dev/null; then
    log "Установка Docker..."
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
else
    log "Docker уже установлен"
fi

# Docker Compose plugin
if ! docker compose version &>/dev/null; then
    log "Установка docker-compose-plugin..."
    apt-get update -qq
    apt-get install -y -qq docker-compose-plugin
else
    log "Docker Compose уже установлен"
fi

# nginx
if ! command -v nginx &>/dev/null; then
    log "Установка nginx..."
    apt-get update -qq
    apt-get install -y -qq nginx
    systemctl enable nginx
else
    log "nginx уже установлен"
fi

# -------------------- step 2: validate .env --------------------

log "Проверка .env..."

ENV_FILE="$PROJECT_DIR/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    warn "Файл .env не найден. Создаю из env.example — заполните его и запустите скрипт снова."
    cp "$PROJECT_DIR/env.example" "$ENV_FILE"
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

missing=()
for var in ANTHROPIC_API_KEY PROXY_API_KEY PROXY_BASE_URL \
           DEPLOY_DOMAIN DEPLOY_SSL_SOURCE_HOST DEPLOY_SSL_SOURCE_CERT DEPLOY_SSL_SOURCE_KEY; do
    val="${!var:-}"
    if [[ -z "$val" || "$val" == *"your_"* || "$val" == *"YOUR_"* || "$val" == *"/path/to/"* ]]; then
        missing+=("$var")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    err "В .env не заполнены обязательные переменные:"
    for v in "${missing[@]}"; do echo "  - $v"; done
    exit 1
fi

# Defaults for optional deploy vars
DEPLOY_UPSTREAM_PORT="${DEPLOY_UPSTREAM_PORT:-7070}"
DEPLOY_SSL_CERT="${DEPLOY_SSL_CERT:-/etc/nginx/ssl/${DEPLOY_DOMAIN}.crt}"
DEPLOY_SSL_KEY="${DEPLOY_SSL_KEY:-/etc/nginx/ssl/${DEPLOY_DOMAIN}.key}"

log ".env валиден (домен: $DEPLOY_DOMAIN)"

# -------------------- step 3: SSL certificates via SCP --------------------

log "Доставка SSL-сертификатов..."

mkdir -p /etc/nginx/ssl

if [[ -f "$DEPLOY_SSL_CERT" && -f "$DEPLOY_SSL_KEY" ]]; then
    log "Сертификаты уже на месте: $DEPLOY_SSL_CERT"
else
    log "Копирование сертификатов с $DEPLOY_SSL_SOURCE_HOST..."
    scp -o StrictHostKeyChecking=accept-new \
        "${DEPLOY_SSL_SOURCE_HOST}:${DEPLOY_SSL_SOURCE_CERT}" "$DEPLOY_SSL_CERT"
    scp -o StrictHostKeyChecking=accept-new \
        "${DEPLOY_SSL_SOURCE_HOST}:${DEPLOY_SSL_SOURCE_KEY}" "$DEPLOY_SSL_KEY"
fi

chmod 640 "$DEPLOY_SSL_CERT" "$DEPLOY_SSL_KEY"
chown root:root "$DEPLOY_SSL_CERT" "$DEPLOY_SSL_KEY"

if [[ ! -s "$DEPLOY_SSL_CERT" || ! -s "$DEPLOY_SSL_KEY" ]]; then
    err "SSL-сертификаты пусты или не читаемы"
    exit 1
fi

log "SSL-сертификаты готовы"

# -------------------- step 4: build & start container --------------------

log "Сборка и запуск контейнера..."

cd "$PROJECT_DIR"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

# Wait for the container to start
log "Ожидание запуска контейнера..."
for i in $(seq 1 15); do
    if curl -so /dev/null -w "%{http_code}" "http://127.0.0.1:${DEPLOY_UPSTREAM_PORT}/" 2>/dev/null | grep -qE "^[0-9]"; then
        log "Контейнер запущен (порт $DEPLOY_UPSTREAM_PORT)"
        break
    fi
    if [[ $i -eq 15 ]]; then
        warn "Контейнер не ответил за 15 секунд — проверьте: docker compose logs"
    fi
    sleep 1
done

# -------------------- step 5: configure nginx --------------------

log "Настройка nginx..."

export DOMAIN="$DEPLOY_DOMAIN"
export SSL_CERT_PATH="$DEPLOY_SSL_CERT"
export SSL_KEY_PATH="$DEPLOY_SSL_KEY"
export UPSTREAM_PORT="$DEPLOY_UPSTREAM_PORT"

# envsubst with explicit var list to preserve nginx $host, $request_uri, etc.
envsubst '${DOMAIN} ${SSL_CERT_PATH} ${SSL_KEY_PATH} ${UPSTREAM_PORT}' \
    < "$PROJECT_DIR/deploy/nginx/claude-proxy.conf.template" \
    > /etc/nginx/conf.d/claude-proxy.conf

# Remove default site if present
rm -f /etc/nginx/sites-enabled/default

if nginx -t 2>&1; then
    systemctl reload nginx
    log "nginx перезагружен"
else
    err "Ошибка в конфигурации nginx — проверьте /etc/nginx/conf.d/claude-proxy.conf"
    exit 1
fi

# -------------------- step 6: verify & summary --------------------

log "Проверка..."

if curl -sk --max-time 5 "https://127.0.0.1/admin" \
    --resolve "${DEPLOY_DOMAIN}:443:127.0.0.1" \
    -o /dev/null -w "%{http_code}" | grep -qE "^(200|302)$"; then
    log "End-to-end проверка пройдена"
else
    warn "HTTPS-проверка не прошла — возможно нужно подождать или проверить DNS"
fi

echo ""
echo "========================================"
echo "  Развёртывание завершено"
echo "========================================"
echo "  Контейнер:  claude-proxy-server"
echo "  Порт:       127.0.0.1:${DEPLOY_UPSTREAM_PORT}"
echo "  HTTPS:      https://${DEPLOY_DOMAIN}"
echo "  Админка:    https://${DEPLOY_DOMAIN}/admin"
echo "========================================"
