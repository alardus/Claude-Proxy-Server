# Claude Proxy Server

## Описание проекта

Claude Proxy Server - это прокси-сервер для API Anthropic, реализованный
на FastAPI. Сервер обеспечивает безопасный доступ к API Claude с дополнительным
уровнем аутентификации, rate limiting и мониторингом.

### Основные возможности:

- Проксирование запросов к API Claude
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

1. Создайте файл `.env` со следующими параметрами:

```env
ANTHROPIC_API_KEY='your_anthropic_api_key'
PROXY_BASE_URL='your_proxy_base_url'
PROXY_API_KEY='your_proxy_api_key'
ADMIN_USERNAME='admin'
ADMIN_PASSWORD='secure_password'
```

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

#### Пример использования в Python
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

### Административная панель

Доступ к панели мониторинга:
```
http://your-server:8000/admin
```

Логин и пароль можно указать в .env файле.

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