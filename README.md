# Honeypot

Honeypot для обнаружения сетевого сканирования.

## Возможности

- детектирование SYN, NULL, XMAS, FIN, ACK сканирования;
- противодействие OS fingerprinting
- структурированное логирование в JSON

## Сборка и запуск

```bash
git clone https://github.com/DanilShurigin/Honeypot.git
cd Honeypot
docker compose up --build -d
docker-compose logs -f
```
## Сканирование

Адрес контейнера: `172.30.0.10`.
