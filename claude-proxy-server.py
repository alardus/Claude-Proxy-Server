from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.security import APIKeyHeader
from fastapi.responses import StreamingResponse, HTMLResponse
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

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Настройка логирования
logging.basicConfig(level=logging.INFO)
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

# Функция для аутентификации админа
async def verify_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip = request.client.host
    
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
    return True

@app.get("/admin", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )

@app.post("/admin/dashboard")
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