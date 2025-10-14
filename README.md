# Claude Proxy Server

## Описание проекта

Claude Proxy Server - это прокси-сервер для API Anthropic и OpenAI, реализованный
на FastAPI. Сервер обеспечивает безопасный доступ к API Claude и OpenAI с дополнительным
уровнем аутентификации, rate limiting и мониторингом.

### Основные возможности:

- Проксирование запросов к API Claude (Anthropic)
- Проксирование запросов к API OpenAI (Chat Completions и Responses)
- Аутентификация по API ключу
- Rate limiting и блокировка IP после неудачных попыток
- Административная панель с мониторингом
- Поддержка потоковой передачи данных
- Сбор статистики использования

## Развертывание

### Предварительные требования:

- Docker
- Python 3.8+
- .env файл с настройками

### Настройка окружения

1. Создайте файл `.env` на основе `env.example`:

```bash
cp env.example .env
```

2. Отредактируйте `.env` файл со своими параметрами:

```env
ANTHROPIC_API_KEY='your_anthropic_api_key'
OPENAI_API_KEY='your_openai_api_key'
PROXY_BASE_URL='your_proxy_base_url'
PROXY_API_KEY='your_proxy_api_key'
ADMIN_USERNAME='admin'
ADMIN_PASSWORD='secure_password'
```

**Примечание:** `OPENAI_API_KEY` требуется только если вы планируете использовать проксирование для OpenAI API.

### Запуск через Docker

1. Соберите Docker образ:
```bash
docker build -t claude-proxy-server .
```

2. Запустите контейнер:
```bash
docker run -d -p 8000:8000 claude-proxy-server
```

### Локальный запуск

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Запустите сервер:
```bash
python claude-proxy-server.py
```

## Использование

### Клиентский код

Для использования API нужно обратиться к серверу по адресу, указанному в PROXY_BASE_URL с ключом PROXY_API_KEY.

#### aiChat
В папке aichat-config есть пример конфигурации для aiChat.

#### Cline (VSCode extension)
В папке cline-config есть пример конфигурации для Cline.

#### Пример использования Anthropic API в Python
```python
import anthropic
from dotenv import load_dotenv
import os

load_dotenv()
PROXY_API_KEY = os.getenv("PROXY_API_KEY")
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL")

client = anthropic.Anthropic(
    base_url=PROXY_BASE_URL,
    api_key=PROXY_API_KEY
)

message = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "hello"}
    ]
)
```

#### Пример использования OpenAI API в Python

OpenAI endpoints поддерживают два способа аутентификации:
1. **Через заголовок `Authorization: Bearer`** (стандартный для OpenAI SDK)
2. **Через заголовок `x-api-key`** (как для Anthropic)

##### Chat Completions (через OpenAI SDK)
```python
import openai
from dotenv import load_dotenv
import os

load_dotenv()
PROXY_API_KEY = os.getenv("PROXY_API_KEY")
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL")

# OpenAI SDK автоматически отправит api_key как "Authorization: Bearer {PROXY_API_KEY}"
client = openai.OpenAI(
    base_url=PROXY_BASE_URL,
    api_key=PROXY_API_KEY
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Hello!"}
    ]
)
```

##### Responses API через requests
```python
import requests
from dotenv import load_dotenv
import os

load_dotenv()
PROXY_API_KEY = os.getenv("PROXY_API_KEY")
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL")

# Можно использовать x-api-key заголовок
response = requests.post(
    f"{PROXY_BASE_URL}/responses",
    headers={
        "x-api-key": PROXY_API_KEY,
        "Content-Type": "application/json"
    },
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
)

# Или Authorization Bearer заголовок
response = requests.post(
    f"{PROXY_BASE_URL}/responses",
    headers={
        "Authorization": f"Bearer {PROXY_API_KEY}",
        "Content-Type": "application/json"
    },
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
)
```

### Доступные endpoints

#### Anthropic API
- `POST /v1/messages` - проксирование к Anthropic API
- `POST /v1/{path}` - любые другие пути Anthropic API

**Аутентификация:** заголовок `x-api-key`

#### OpenAI API
- `POST /chat/completions` - проксирование к OpenAI Chat Completions API
- `POST /responses` - проксирование к OpenAI Responses API (Projects)

**Аутентификация:** заголовок `x-api-key` или `Authorization: Bearer`

> **Примечание:** OpenAI endpoints поддерживают оба метода аутентификации для совместимости с OpenAI SDK, который использует `Authorization: Bearer` по умолчанию.

### Тестирование

#### Тест Anthropic API
```bash
python claude-client-test.py
```

#### Тест OpenAI API
```bash
python openai-client-test.py
```

Тестовые скрипты проверяют работу прокси-сервера и выводят результаты запросов.

### Административная панель

Доступ к панели мониторинга:
```
http://your-server:8000/admin
```

В .env файле нужно указать логин и пароль для админки.

## Безопасность

- Используется rate limiting для защиты от брутфорса
- Блокировка IP после превышения лимита неудачных попыток
- Безопасная аутентификация администратора
- Логирование всех запросов

## Мониторинг

В административной панели доступна следующая статистика:
- Общее количество запросов
- Количество ошибок
- Активные блокировки
- Среднее время ответа
- Top IP-адресов по количеству запросов
- История последних запросов

## Генерация API ключей

Для генерации безопасных API ключей используйте скрипт:
```python
python generate_api_key.py
```