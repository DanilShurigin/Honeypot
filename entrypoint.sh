#!/bin/bash
# Точка входа в контейнер

echo "[ENTRYPOINT] Starting Honeypot Container..."
echo "[ENTRYPOINT] Date: $(date)"
echo "[ENTRYPOINT] Hostname: $(hostname)"

echo "[ENTRYPOINT] Starting honeypot service..."
# Запуск honeypot
exec /bin/bash -c "cd /opt/honeypot && python3 honeypot.py"
