FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y procps && rm -rf /var/lib/apt/lists/*
RUN pip install -r requirements.txt

COPY . .

CMD ["uvicorn", "claude-proxy-server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
