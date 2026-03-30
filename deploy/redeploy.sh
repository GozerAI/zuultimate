#!/usr/bin/env bash
# Quick redeploy — pull latest, rebuild, restart
set -euo pipefail

APP_DIR="/opt/zuultimate/repo"
cd "$APP_DIR"

echo "=== Zuultimate Redeploy ==="

echo "[1/3] Pulling latest..."
git pull

echo "[2/3] Rebuilding containers..."
cd deploy
docker compose -f docker-compose.vps.yml build

echo "[3/3] Restarting services..."
docker compose -f docker-compose.vps.yml up -d

echo "Waiting for health check..."
for i in 1 2 3 4 5; do
    sleep 2
    if curl -sf http://localhost:8000/health/live > /dev/null 2>&1; then
        echo "Health check: OK"
        echo ""
        echo "=== Redeploy Complete ==="
        exit 0
    fi
done

echo "Health check: FAILED — check logs with: docker compose -f docker-compose.vps.yml logs -f"
exit 1
