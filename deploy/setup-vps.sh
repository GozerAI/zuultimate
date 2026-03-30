#!/usr/bin/env bash
# Zuultimate VPS Setup Script
# Run as root or with sudo
set -euo pipefail

APP_DIR="/opt/zuultimate"
REPO_URL="https://github.com/chrisarseno/zuultimate.git"

echo "=== Zuultimate VPS Setup ==="

# 1. Create directory
echo "[1/5] Setting up directory..."
mkdir -p "$APP_DIR"

# 2. Clone repo
echo "[2/5] Cloning Zuultimate..."
if [ ! -d "$APP_DIR/repo" ]; then
    git clone "$REPO_URL" "$APP_DIR/repo"
else
    cd "$APP_DIR/repo" && git pull
fi

# 3. Environment file
echo "[3/5] Setting up environment..."
if [ ! -f "$APP_DIR/repo/.env" ]; then
    cp "$APP_DIR/repo/.env.example" "$APP_DIR/repo/.env"
    # Generate random secrets
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    SERVICE_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    VAULT_SALT=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    MFA_SALT=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    PW_SALT=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

    sed -i "s|ZUUL_SECRET_KEY=change-me-to-a-random-secret-key|ZUUL_SECRET_KEY=$SECRET_KEY|" "$APP_DIR/repo/.env"
    sed -i "s|ZUUL_SERVICE_TOKEN=change-me-to-a-random-service-token|ZUUL_SERVICE_TOKEN=$SERVICE_TOKEN|" "$APP_DIR/repo/.env"
    sed -i "s|# ZUUL_VAULT_SALT=.*|ZUUL_VAULT_SALT=$VAULT_SALT|" "$APP_DIR/repo/.env"
    sed -i "s|# ZUUL_MFA_SALT=.*|ZUUL_MFA_SALT=$MFA_SALT|" "$APP_DIR/repo/.env"
    sed -i "s|# ZUUL_PASSWORD_VAULT_SALT=.*|ZUUL_PASSWORD_VAULT_SALT=$PW_SALT|" "$APP_DIR/repo/.env"
    sed -i "s|ZUUL_ENVIRONMENT=development|ZUUL_ENVIRONMENT=production|" "$APP_DIR/repo/.env"

    echo ""
    echo "  >> Generated secrets written to $APP_DIR/repo/.env"
    echo "  >> IMPORTANT: Copy ZUUL_SERVICE_TOKEN to Vinzy and Arclane .env files:"
    echo "     ZUUL_SERVICE_TOKEN=$SERVICE_TOKEN"
    echo ""
fi

# 4. Ensure shared Docker networks exist
echo "[4/5] Setting up Docker networks..."
docker network create webproxy 2>/dev/null || true
docker network create backend 2>/dev/null || true

# 5. Build and start
echo "[5/5] Building and starting services..."
cd "$APP_DIR/repo/deploy"
docker compose -f docker-compose.vps.yml up -d --build

echo ""
echo "=== Zuultimate Setup Complete ==="
echo "Health: http://localhost:8000/health/live"
echo ""
echo "Next steps:"
echo "  1. Copy ZUUL_SERVICE_TOKEN to Vinzy and Arclane .env files"
echo "  2. Add Caddy route if external access needed"
echo "  3. docker compose -f docker-compose.vps.yml logs -f"
