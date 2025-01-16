import secrets
import base64

def generate_secure_api_key(length=32):
    # Генерация безопасного API ключа
    random_bytes = secrets.token_bytes(length)
    
    # Преобразование байтов в base64
    api_key_base64 = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    
    return api_key_base64

# Example usage
api_key = generate_secure_api_key()
print(api_key)