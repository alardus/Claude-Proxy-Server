#!/usr/bin/env python3
"""
Тестовый скрипт для проверки работы прокси-сервера с OpenAI API
"""

import os
import requests
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

PROXY_API_KEY = os.getenv("PROXY_API_KEY")
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL", "http://localhost:8000")

def test_chat_completions():
    """Тестирует endpoint /chat/completions с x-api-key"""
    print("=" * 60)
    print("Тестирование OpenAI Chat Completions API через прокси")
    print("(Аутентификация: x-api-key)")
    print("=" * 60)
    
    url = f"{PROXY_BASE_URL}/chat/completions"
    headers = {
        "x-api-key": PROXY_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Hello from OpenAI proxy!' if you receive this."}
        ],
        "max_tokens": 50
    }
    
    try:
        print(f"\nОтправка запроса на: {url}")
        print(f"Модель: {payload['model']}")
        print(f"Сообщение: {payload['messages'][-1]['content']}")
        print("\nОжидание ответа...\n")
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        print(f"Статус код: {response.status_code}")
        
        if response.status_code == 200:
            print("✓ Запрос выполнен успешно!")
            print("\nОтвет от сервера:")
            print(response.text[:500])  # Первые 500 символов
        else:
            print("✗ Ошибка при выполнении запроса")
            print(f"Ответ: {response.text}")
            
    except Exception as e:
        print(f"✗ Произошла ошибка: {str(e)}")


def test_chat_completions_bearer():
    """Тестирует endpoint /chat/completions с Authorization Bearer"""
    print("\n" + "=" * 60)
    print("Тестирование OpenAI Chat Completions API через прокси")
    print("(Аутентификация: Authorization Bearer)")
    print("=" * 60)
    
    url = f"{PROXY_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {PROXY_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Hello from OpenAI proxy with Bearer auth!' if you receive this."}
        ],
        "max_tokens": 50
    }
    
    try:
        print(f"\nОтправка запроса на: {url}")
        print(f"Модель: {payload['model']}")
        print(f"Сообщение: {payload['messages'][-1]['content']}")
        print("\nОжидание ответа...\n")
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        print(f"Статус код: {response.status_code}")
        
        if response.status_code == 200:
            print("✓ Запрос выполнен успешно!")
            print("\nОтвет от сервера:")
            print(response.text[:500])  # Первые 500 символов
        else:
            print("✗ Ошибка при выполнении запроса")
            print(f"Ответ: {response.text}")
            
    except Exception as e:
        print(f"✗ Произошла ошибка: {str(e)}")


def test_responses_api():
    """Тестирует endpoint /responses (OpenAI Projects API)"""
    print("\n" + "=" * 60)
    print("Тестирование OpenAI Responses API через прокси")
    print("(Аутентификация: x-api-key)")
    print("=" * 60)
    
    url = f"{PROXY_BASE_URL}/responses"
    headers = {
        "x-api-key": PROXY_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "gpt-4",
        "messages": [
            {"role": "user", "content": "Test message for responses API"}
        ],
        "max_tokens": 50
    }
    
    try:
        print(f"\nОтправка запроса на: {url}")
        print(f"Модель: {payload['model']}")
        print(f"Сообщение: {payload['messages'][-1]['content']}")
        print("\nОжидание ответа...\n")
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        print(f"Статус код: {response.status_code}")
        
        if response.status_code == 200:
            print("✓ Запрос выполнен успешно!")
            print("\nОтвет от сервера:")
            print(response.text[:500])  # Первые 500 символов
        else:
            print("✗ Ошибка при выполнении запроса")
            print(f"Ответ: {response.text}")
            
    except Exception as e:
        print(f"✗ Произошла ошибка: {str(e)}")


def main():
    """Основная функция"""
    if not PROXY_API_KEY:
        print("✗ Ошибка: PROXY_API_KEY не установлен в .env файле")
        return
    
    print("\n🚀 Запуск тестов для OpenAI API через прокси-сервер")
    print(f"📍 Прокси сервер: {PROXY_BASE_URL}")
    print(f"🔑 API ключ: {'*' * (len(PROXY_API_KEY) - 4)}{PROXY_API_KEY[-4:]}")
    
    # Тестируем все варианты
    test_chat_completions()
    test_chat_completions_bearer()
    test_responses_api()
    
    print("\n" + "=" * 60)
    print("Тестирование завершено!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

