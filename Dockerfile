FROM python:3.11-slim-bookworm

LABEL description="Honeypot"

# Установка системных зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Копирование файлов проекта
WORKDIR /opt/honeypot
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypot.py .
COPY entrypoint.sh .

# Выдача прав на выполнение
RUN chmod +x entrypoint.sh

# Проброс портов
EXPOSE 2222 2223 8080

# Запуск
ENTRYPOINT ["./entrypoint.sh"]
