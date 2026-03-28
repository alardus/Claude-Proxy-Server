import anthropic
import os
from dotenv import load_dotenv

# Конфигурация из .env
load_dotenv()
PROXY_API_KEY = os.getenv("PROXY_API_KEY")
PROXY_BASE_URL = os.getenv("PROXY_BASE_URL")

client = anthropic.Anthropic(
    base_url=PROXY_BASE_URL,
    api_key=PROXY_API_KEY
)

message = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "hello"}
    ]
)

print(message.content[0].text)
