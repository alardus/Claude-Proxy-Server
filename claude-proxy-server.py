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
from typing import Dict
import re
import traceback

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    r"admin", r"wp-", r"wordpress", r"login", r"shell", r"setup", r"install",
    r"backup", r"config", r"phpmy", r"sql", r"test", r"tmp", r"temp"
]
BLOCKED_USER_AGENTS = [
    "zgrab", "masscan", "nmap", "sqlmap", "nikto", "dirbuster",
    "wpscan", "vulnerability", "scanner", "testing", "python-requests"
]
BLOCKED_METHODS = ["CONNECT", "TRACE", "OPTIONS"]

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

# Добавляем учетные данные для страницы мониторинга
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "your_secure_password")

# Добавляем новые константы для работы с куки
COOKIE_NAME = "admin_session"
COOKIE_MAX_AGE = 3600  # 1 час

# Глобальный обработчик исключений
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(time.time())
    client_ip = request.client.host
    
    # Логируем детали ошибки
    logger.error(
        f"Error ID: {error_id}\n"
        f"Client IP: {client_ip}\n"
        f"Path: {request.url.path}\n"
        f"Method: {request.method}\n"
        f"Error: {str(exc)}\n"
        f"Traceback: {traceback.format_exc()}"
    )
    
    # Обновляем статистику
    request_stats["failed_requests"] += 1
    request_stats["last_requests"].append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": client_ip,
        "path": request.url.path,
        "status": "error",
        "error": str(exc),
        "error_id": error_id
    })
    
    # Возвращаем разные ответы в зависимости от типа ошибки
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "error_id": error_id
            }
        )
    
    # Для всех остальных ошибок возвращаем 500
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_id": error_id
        }
    )

# Middleware для проверки безопасности
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host
    
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
    client_ip = request.client.host
    
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
        # Увеличиваем счетчик неудачных попыток
        failed_attempts[client_ip] += 1
        
        # Если превышен лимит попыток, блокируем IP
        if failed_attempts[client_ip] >= MAX_FAILED_ATTEMPTS:
            block_until[client_ip] = time.time() + BLOCK_DURATION
            failed_attempts[client_ip] = 0  # Сбрасываем счетчик
            logger.info(f"Blocking IP {client_ip} for {BLOCK_DURATION/3600} hours")
            raise HTTPException(
                status_code=403,
                detail=f"Too many failed attempts. IP blocked for {BLOCK_DURATION/3600} hours"
            )
            
        raise HTTPException(
            status_code=403,
            detail=f"Invalid API key. {MAX_FAILED_ATTEMPTS - failed_attempts[client_ip]} attempts remaining"
        )
    
    # Если ключ верный, сбрасываем счетчик попыток
    failed_attempts[client_ip] = 0
    return api_key

# Обновляем функцию verify_admin для работы с куки
async def verify_admin(
    request: Request,
    response: Response,
    username: str = Form(None),
    password: str = Form(None)
):
    client_ip = request.client.host
    
    # Проверяем существующую куки
    if not username and not password:
        cookie = request.cookies.get(COOKIE_NAME)
        if cookie == ADMIN_PASSWORD:  # В реальном приложении используйте более безопасный метод
            return True
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Проверяем rate limit перед проверкой учетных данных
    if time.time() < block_until[client_ip]:
        logger.warning(f"Admin login attempt from blocked IP {client_ip}")
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
    response.set_cookie(
        key=COOKIE_NAME,
        value=ADMIN_PASSWORD,  # В реальном приложении используйте токен
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=True
    )
    return True

# Обновляем маршрут входа в админку
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

# Обновляем маршрут дашборда
@app.post("/admin/dashboard")
async def admin_dashboard(
    request: Request,
    response: Response,
    _: bool = Depends(verify_admin)
):
    uptime = datetime.now() - request_stats["start_time"]
    avg_response_time = (
        request_stats["average_response_time"] 
        if request_stats["total_requests"] > 0 
        else 0
    )
    
    stats = {
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
        "recent_requests": request_stats["last_requests"][-10:]
    }
    
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "stats": stats}
    )

# Добавляем новый маршрут для GET-запросов к дашборду
@app.get("/admin/dashboard")
async def admin_dashboard_get(
    request: Request,
    response: Response,
    _: bool = Depends(verify_admin)
):
    return await admin_dashboard(request, response, _)

# Добавляем маршрут для выхода
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
    client_ip = request.client.host
    
    try:
        request_stats["total_requests"] += 1
        request_stats["requests_by_ip"][client_ip] += 1
        
        # Остальной код обработчика...
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)