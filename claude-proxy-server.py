from fastapi import FastAPI, Request, HTTPException, Depends, Form, Response
from fastapi.security import APIKeyHeader
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import httpx
import uvicorn
from collections import defaultdict
import time
from dotenv import load_dotenv
import os
import logging
from datetime import datetime
from typing import Dict, Optional
import re
import traceback
import psutil
import gc
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from uvicorn.logging import AccessFormatter
from contextlib import asynccontextmanager
from uvicorn.logging import DefaultFormatter

# Добавляем словарь для хранения метрик
system_metrics = {
    "cpu_usage": 0,
    "memory_usage": 0,
    "disk_io": {"read_bytes": 0, "write_bytes": 0},
    "network_io": {"bytes_sent": 0, "bytes_recv": 0},
    "rps": 0,
    "errors_4xx": 0,
    "errors_5xx": 0,
    "thread_count": 0,
    "python_memory": 0,
    "gc_stats": {"collections": 0, "collected": 0, "time": 0},
    "open_connections": 0,
    "uvicorn_workers": 0,
    "request_processing_time": 0,
    "worker_status": [],
    # Добавляем метрики Uvicorn
    "uvicorn_stats": {
        "total_requests": 0,
        "success_requests": 0,  # 200-299
        "redirect_requests": 0,  # 300-399
        "client_errors": 0,     # 400-499
        "server_errors": 0,     # 500-599
        "requests_by_status": defaultdict(int),  # детальная статистика по кодам
        "requests_by_path": defaultdict(int),    # статистика по путям
        "last_requests": []     # последние 50 запросов
    }
}

# Добавляем новые переменные для статистики
request_stats = {
    "total_requests": 0,
    "failed_requests": 0,
    "blocked_ips": set(),
    "requests_by_ip": defaultdict(int),
    "last_requests": [],  # список последних запросов
    "start_time": datetime.now(),
    "average_response_time": 0,
    "total_response_time": 0
}

# Функция для обновления системных метрик
async def update_system_metrics():
    while True:
        try:
            current_time = datetime.now()

            # Рассчитываем RPS за последнюю минуту
            time_window = 60
            recent_requests = [
                req for req in request_stats["last_requests"]
                if (current_time - datetime.strptime(req["timestamp"], "%Y-%m-%d %H:%M:%S")).seconds <= time_window
            ]
            system_metrics["rps"] = len(recent_requests) / time_window if recent_requests else 0
            
            # Обновляем среднее время ответа
            if request_stats["total_requests"] > 0:
                system_metrics["request_processing_time"] = (
                    request_stats["total_response_time"] / request_stats["total_requests"]
                )

            # Системные метрики
            system_metrics["cpu_usage"] = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            system_metrics["memory_usage"] = memory.percent
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            system_metrics["disk_io"]["read_bytes"] = disk_io.read_bytes
            system_metrics["disk_io"]["write_bytes"] = disk_io.write_bytes
            
            # Network I/O
            net_io = psutil.net_io_counters()
            system_metrics["network_io"]["bytes_sent"] = net_io.bytes_sent
            system_metrics["network_io"]["bytes_recv"] = net_io.bytes_recv
            
            # Python-специфичные метрики
            current_process = psutil.Process()
            system_metrics["thread_count"] = threading.active_count()
            system_metrics["python_memory"] = current_process.memory_info().rss / 1024 / 1024  # MB
            
            # GC статистика
            gc.collect()
            gc_stats = gc.get_stats()
            system_metrics["gc_stats"]["collections"] = sum(s["collections"] for s in gc_stats)
            system_metrics["gc_stats"]["collected"] = sum(s["collected"] for s in gc_stats)
            
            # Uvicorn метрики
            workers = []
            total_processing_time = 0
            
            # Получаем все процессы Uvicorn
            for proc in current_process.children():
                try:
                    if "uvicorn" in proc.name().lower():
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                        workers.append({
                            "pid": proc.pid,
                            "cpu": f"{cpu_percent:.1f}%",
                            "memory": f"{memory_percent:.1f}%",
                            "connections": len(proc.connections()),
                            "threads": len(proc.threads())
                        })
                        # Время обработки берем как среднее время CPU
                        total_processing_time += cpu_percent
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            system_metrics["uvicorn_workers"] = len(workers)
            system_metrics["worker_status"] = workers
            if workers:
                system_metrics["request_processing_time"] = total_processing_time / len(workers)
            else:
                # Если нет отдельных воркеров, берем метрики основного процесса
                system_metrics["request_processing_time"] = current_process.cpu_percent()
            
            # Обновляем количество открытых соединений
            system_metrics["open_connections"] = sum(len(proc.connections()) 
                for proc in [current_process] + current_process.children() 
                if "uvicorn" in proc.name().lower())
            
        except Exception as e:
            logger.error(f"Error updating system metrics: {str(e)}")
        
        await asyncio.sleep(5)  # Обновляем каждые 5 секунд

# Создаем менеджер жизненного цикла приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализируем статистику Uvicorn
    system_metrics["uvicorn_stats"] = {
        "total_requests": 0,
        "success_requests": 0,  # 200-299
        "redirect_requests": 0,  # 300-399
        "client_errors": 0,     # 400-499
        "server_errors": 0,     # 500-599
        "requests_by_status": defaultdict(int),  # детальная статистика по кодам
        "requests_by_path": defaultdict(int),    # статистика по путям
        "last_requests": []     # последние 50 запросов
    }
    
    # Запускаем сборщик метрик
    metrics_task = asyncio.create_task(update_system_metrics())
    
    yield  # Здесь работает приложение
    
    # Очистка при завершении
    metrics_task.cancel()
    try:
        await metrics_task
    except asyncio.CancelledError:
        pass

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# Добавляем в начало файла после импортов
class CustomAccessFormatter(DefaultFormatter):
    def get_path(self, scope):
        """Get full path from scope."""
        return scope.get("path", "")

    def format(self, record):
        if record.name == "uvicorn.access":
            record.client_addr = "-"
            record.request_line = "-"
            record.status_code = "-"

            if hasattr(record, "scope"):
                scope = record.scope
                client = scope.get("client")
                method = scope.get("method", "-")
                status_code = scope.get("status_code", "-")
                
                # Получаем IP из заголовков
                headers = dict(scope.get("headers", []))
                if b'x-forwarded-for' in headers:
                    record.client_addr = headers[b'x-forwarded-for'].decode().split(',')[0].strip()
                elif b'x-real-ip' in headers:
                    record.client_addr = headers[b'x-real-ip'].decode()
                elif client:
                    record.client_addr = f"{client[0]}:{client[1]}"

                record.request_line = f"{method} {self.get_path(scope)}"
                record.status_code = status_code

        return super().format(record)

# Настройка логирования
logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": f"{__name__}.CustomAccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO"},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
        "app": {"handlers": ["default"], "level": "INFO", "propagate": False},
    },
}

logger = logging.getLogger("app")

# Конфигурация из .env
load_dotenv()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_API_BASE = "https://api.anthropic.com"
PROXY_API_KEY = os.getenv("PROXY_API_KEY")

# Настройки rate limiting
MAX_FAILED_ATTEMPTS = 2  # Максимальное количество неудачных попыток
BLOCK_DURATION = 3600  # Время блокировки в секундах (1 час)

# Словари для отслеживания попыток
failed_attempts = defaultdict(int)  # IP -> количество попыток
block_until = defaultdict(float)  # IP -> время окончания блокировки

# Определяем заголовок для верификации PROXY_API ключа
api_key_header = APIKeyHeader(name="x-api-key")

# Добавляем константы для безопасности
SCAN_PATTERNS = [
    r"\.php$", r"\.asp[x]?$", r"\.jsp$", r"\.env$", r"\.git", r"\.bak$",
    r"wp-", r"wordpress", r"login", r"shell", r"setup", r"install",
    r"backup", r"config", r"phpmy", r"sql", r"test", r"tmp", r"temp"
]
BLOCKED_USER_AGENTS = [
    "zgrab", "masscan", "nmap", "sqlmap", "nikto", "dirbuster",
    "wpscan", "vulnerability", "scanner", "testing", "python-requests"
]
BLOCKED_METHODS = ["CONNECT", "TRACE", "OPTIONS"]

# Добавляем учетные данные для страницы мониторинга
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "your_secure_password")

# Добавляем новые константы для работы с куки
COOKIE_NAME = "admin_session"
COOKIE_MAX_AGE = 3600  # 1 час

def get_client_ip(request: Request) -> str:
    """Получаем реальный IP клиента из заголовков X-Forwarded-For или Real-IP"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Берем первый IP из списка (реальный IP клиента)
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host

# Функция для проверки подозрительных запросов
def is_suspicious_request(request: Request) -> bool:
    path = request.url.path.lower()
    user_agent = request.headers.get("user-agent", "").lower()
    method = request.method.upper()
    
    # Проверяем метод запроса
    if method in BLOCKED_METHODS:
        return True
    
    # Проверяем паттерны сканирования
    for pattern in SCAN_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    
    # Проверяем User-Agent
    for blocked_ua in BLOCKED_USER_AGENTS:
        if blocked_ua in user_agent:
            return True
    
    return False

# Middleware для проверки безопасности
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = get_client_ip(request)
    
    try:
        # Проверяем подозрительные запросы
        if is_suspicious_request(request):
            logger.warning(f"Suspicious request detected from {client_ip}")
            failed_attempts[client_ip] += 1
            
            if failed_attempts[client_ip] >= MAX_FAILED_ATTEMPTS:
                block_until[client_ip] = time.time() + BLOCK_DURATION
                failed_attempts[client_ip] = 0
                request_stats["blocked_ips"].add(client_ip)
                logger.warning(f"Blocking suspicious IP {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied",
                        "detail": f"IP blocked for {BLOCK_DURATION/3600} hours due to suspicious activity"
                    }
                )
        
        # Проверяем, не заблокирован ли IP
        if time.time() < block_until[client_ip]:
            remaining_time = int(block_until[client_ip] - time.time())
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "detail": f"IP is blocked. Try again in {remaining_time} seconds"
                }
            )
        
        response = await call_next(request)
        
        # Добавляем заголовки безопасности
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Server"] = "Protected Server"
        
        return response
        
    except Exception as e:
        logger.error(f"Error in security middleware: {str(e)}\nTraceback: {traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": "An error occurred while processing your request"
            }
        )

# Функция проверки API ключа
async def verify_api_key(request: Request, api_key: str = Depends(api_key_header)):
    client_ip = get_client_ip(request)
    
    # Проверяем, не заблокирован ли IP
    if time.time() < block_until[client_ip]:
        logger.warning(f"Too many failed attempts from {client_ip}")
        raise HTTPException(
            status_code=403,
            detail=f"Too many failed attempts. Try again in {int(block_until[client_ip] - time.time())} seconds"
        )
    
    # Проверяем ключ
    if api_key != PROXY_API_KEY:
        logger.warning(f"Invalid API key from {client_ip}")
        failed_attempts[client_ip] += 1
        
        if failed_attempts[client_ip] >= MAX_FAILED_ATTEMPTS:
            block_until[client_ip] = time.time() + BLOCK_DURATION
            failed_attempts[client_ip] = 0
            logger.warning(f"Blocking IP {client_ip} for {BLOCK_DURATION/3600} hours")
            raise HTTPException(
                status_code=403,
                detail=f"Too many failed attempts. IP blocked for {BLOCK_DURATION/3600} hours"
            )
            
        raise HTTPException(
            status_code=403,
            detail=f"Invalid API key. {MAX_FAILED_ATTEMPTS - failed_attempts[client_ip]} attempts remaining"
        )
    
    failed_attempts[client_ip] = 0
    return api_key

# Обновляем функцию verify_admin для работы с куки
async def verify_admin(request: Request):
    client_ip = get_client_ip(request)
    
    # Проверяем существующую куки
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie == ADMIN_PASSWORD:  # В реальном приложении используйте более безопасный метод
        return True
        
    # Если нет куки, проверяем rate limit
    if time.time() < block_until[client_ip]:
        logger.warning(f"Admin login attempt from blocked IP {client_ip}")
        raise HTTPException(
            status_code=403,
            detail=f"Too many failed attempts. Try again in {int(block_until[client_ip] - time.time())} seconds"
        )
    
    raise HTTPException(status_code=401, detail="Unauthorized")

# Маршрут для входа в админку
@app.get("/admin", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    # Проверяем, авторизован ли уже пользователь
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie == ADMIN_PASSWORD:  # В реальном приложении используйте более безопасный метод
        return RedirectResponse(url="/admin/dashboard")
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )

# Маршрут для обработки формы входа
@app.post("/admin/login")
async def admin_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip = get_client_ip(request)
    
    if time.time() < block_until[client_ip]:
        raise HTTPException(
            status_code=403,
            detail=f"Too many failed attempts. Try again in {int(block_until[client_ip] - time.time())} seconds"
        )

    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        failed_attempts[client_ip] += 1
        
        if failed_attempts[client_ip] >= MAX_FAILED_ATTEMPTS:
            block_until[client_ip] = time.time() + BLOCK_DURATION
            failed_attempts[client_ip] = 0
            logger.warning(f"Blocking IP {client_ip} after failed admin login attempts")
            raise HTTPException(
                status_code=403,
                detail=f"Too many failed attempts. IP blocked for {BLOCK_DURATION/3600} hours"
            )
            
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    failed_attempts[client_ip] = 0
    response = RedirectResponse(url="/admin/dashboard", status_code=303)
    response.set_cookie(
        key=COOKIE_NAME,
        value=ADMIN_PASSWORD,  # В реальном приложении используйте токен
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=True
    )
    return response

# Маршрут дашборда
@app.get("/admin/dashboard")
async def admin_dashboard(
    request: Request,
    _: bool = Depends(verify_admin)
):
    uptime = datetime.now() - request_stats["start_time"]
    avg_response_time = (
        request_stats["average_response_time"] 
        if request_stats["total_requests"] > 0 
        else 0
    )
    
    # Рассчитываем RPS
    time_window = 60  # последняя минута
    current_time = datetime.now()
    recent_requests = [
        req for req in request_stats["last_requests"]
        if (current_time - datetime.strptime(req["timestamp"], "%Y-%m-%d %H:%M:%S")).seconds <= time_window
    ]
    rps = len(recent_requests) / time_window if recent_requests else 0
    
    stats = {
        # Существующая статистика
        "total_requests": request_stats["total_requests"],
        "failed_requests": request_stats["failed_requests"],
        "active_blocks": len(request_stats["blocked_ips"]),
        "uptime": str(uptime).split('.')[0],
        "avg_response_time": f"{avg_response_time:.2f}ms",
        "top_ips": sorted(
            request_stats["requests_by_ip"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10],
        "recent_requests": request_stats["last_requests"][-10:],
        
        # Системные метрики
        "system": {
            "cpu_usage": f"{system_metrics['cpu_usage']:.1f}%",
            "memory_usage": f"{system_metrics['memory_usage']:.1f}%",
            "disk_io": {
                "read": f"{system_metrics['disk_io']['read_bytes'] / 1024 / 1024:.1f} MB",
                "write": f"{system_metrics['disk_io']['write_bytes'] / 1024 / 1024:.1f} MB"
            },
            "network_io": {
                "sent": f"{system_metrics['network_io']['bytes_sent'] / 1024 / 1024:.1f} MB",
                "received": f"{system_metrics['network_io']['bytes_recv'] / 1024 / 1024:.1f} MB"
            }
        },
        
        # Метрики производительности
        "performance": {
            "rps": f"{rps:.1f}",
            "avg_response_time": f"{avg_response_time:.2f}ms",
            "errors_4xx": system_metrics["errors_4xx"],
            "errors_5xx": system_metrics["errors_5xx"]
        },
        
        # Python метрики
        "python": {
            "threads": system_metrics["thread_count"],
            "memory_usage": f"{system_metrics['python_memory']:.1f} MB",
            "gc_stats": {
                "collections": system_metrics["gc_stats"]["collections"],
                "objects_collected": system_metrics["gc_stats"]["collected"],
                "time": f"{system_metrics['gc_stats']['time']:.2f}ms"
            },
            "connections": system_metrics["open_connections"]
        },
        
        # Uvicorn метрики
        "uvicorn": {
            "workers": system_metrics["uvicorn_workers"],
            "processing_time": f"{system_metrics['request_processing_time']:.2f}ms",
            "worker_status": system_metrics["worker_status"]
        },
        
        # Добавляем статистику Uvicorn
        "uvicorn_stats": system_metrics["uvicorn_stats"]
    }
    
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "stats": stats}
    )

# Добавляем отдельный маршрут для API метрик
@app.get("/admin/api/metrics")
async def get_metrics(
    request: Request,
    _: bool = Depends(verify_admin)
):
    return JSONResponse(content=system_metrics)

# Добавляем маршрут для получения общей статистики
@app.get("/admin/api/stats")
async def get_stats(
    request: Request,
    _: bool = Depends(verify_admin)
):
    uptime = datetime.now() - request_stats["start_time"]
    avg_response_time = (
        request_stats["average_response_time"] 
        if request_stats["total_requests"] > 0 
        else 0
    )
    
    # Рассчитываем RPS
    time_window = 60  # последняя минута
    current_time = datetime.now()
    recent_requests = [
        req for req in request_stats["last_requests"]
        if (current_time - datetime.strptime(req["timestamp"], "%Y-%m-%d %H:%M:%S")).seconds <= time_window
    ]
    rps = len(recent_requests) / time_window if recent_requests else 0
    
    return JSONResponse(content={
        "total_requests": request_stats["total_requests"],
        "failed_requests": request_stats["failed_requests"],
        "active_blocks": len(request_stats["blocked_ips"]),
        "uptime": str(uptime).split('.')[0],
        "avg_response_time": f"{avg_response_time:.2f}ms",
        "recent_requests": request_stats["last_requests"][-10:],
        "rps": f"{rps:.1f}"
    })

# Маршрут для выхода
@app.get("/admin/logout")
async def admin_logout(response: Response):
    response = RedirectResponse(url="/admin")
    response.delete_cookie(COOKIE_NAME)
    return response

# Модифицируем основной обработчик для сбора статистики
@app.post("/v1/{path:path}")
async def proxy_request(
    request: Request,
    path: str,
    api_key: str = Depends(verify_api_key)
):
    start_time = time.time()
    client_ip = get_client_ip(request)
    
    try:
        request_stats["total_requests"] += 1
        request_stats["requests_by_ip"][client_ip] += 1
        
        body = await request.json()
        headers = {
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        async def stream_response():
            try:
                async with httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        f"{ANTHROPIC_API_BASE}/v1/{path}",
                        headers=headers,
                        json=body,
                        timeout=None
                    ) as response:
                        # Проверяем статус ответа
                        if 400 <= response.status_code < 500:
                            system_metrics["errors_4xx"] += 1
                        elif response.status_code >= 500:
                            system_metrics["errors_5xx"] += 1
                            
                        async for chunk in response.aiter_bytes():
                            yield chunk
                            
                # Обновляем статистику после успешного запроса
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # в миллисекундах
                request_stats["total_response_time"] += response_time
                request_stats["average_response_time"] = (
                    request_stats["total_response_time"] / request_stats["total_requests"]
                )
                
                request_stats["last_requests"].append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": client_ip,
                    "path": path,
                    "response_time": f"{response_time:.2f}ms",
                    "status": "success"
                })
                
            except Exception as e:
                request_stats["failed_requests"] += 1
                system_metrics["errors_5xx"] += 1
                request_stats["last_requests"].append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": client_ip,
                    "path": path,
                    "status": "error",
                    "error": str(e)
                })
                raise
                
        return StreamingResponse(
            stream_response(),
            media_type="text/event-stream"
        )
        
    except Exception as e:
        request_stats["failed_requests"] += 1
        raise

# Добавляем middleware для отслеживания запросов Uvicorn
@app.middleware("http")
async def uvicorn_stats_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000

    # Получаем реальный IP клиента
    client_ip = get_client_ip(request)

    # Обновляем статистику
    stats = system_metrics["uvicorn_stats"]
    stats["total_requests"] += 1
    stats["requests_by_status"][response.status_code] += 1
    stats["requests_by_path"][request.url.path] += 1

    # Классифицируем ответ
    if 200 <= response.status_code < 300:
        stats["success_requests"] += 1
    elif 300 <= response.status_code < 400:
        stats["redirect_requests"] += 1
    elif 400 <= response.status_code < 500:
        stats["client_errors"] += 1
    elif 500 <= response.status_code < 600:
        stats["server_errors"] += 1

    # Добавляем в историю
    stats["last_requests"].append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "process_time": f"{process_time:.2f}ms",
        "client_ip": client_ip,
        "forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "real_ip": request.headers.get("X-Real-IP", "")
    })
    # Ограничиваем историю последними 50 запросами
    stats["last_requests"] = stats["last_requests"][-50:]

    return response

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_config=logging_config
    )