#!/bin/sh
set -eu

# Parse BACKEND_URL (e.g. http://backend:5000) into host and port
_backend="${BACKEND_URL:-http://backend:5000}"
_backend="${_backend#http://}"
_backend="${_backend#https://}"
BACKEND_HOST="${_backend%:*}"
BACKEND_PORT="${_backend##*:}"
export BACKEND_HOST BACKEND_PORT
export REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-120}"

# ── TLS Setup ────────────────────────────────────────────────────────
CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

# If user mounted a cert+key, use them; otherwise generate self-signed
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "[entrypoint] Generating self-signed TLS certificate..."
    apk add --no-cache openssl >/dev/null 2>&1 || true
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=US/ST=Local/L=Local/O=SecureProxyManager/CN=proxy-manager" \
        -addext "subjectAltName=DNS:localhost,DNS:proxy-manager,IP:127.0.0.1" \
        2>/dev/null
    echo "[entrypoint] Self-signed certificate generated (valid 10 years)"
else
    echo "[entrypoint] Using mounted TLS certificate"
fi

# Substitute env vars into the nginx template
envsubst '${BACKEND_HOST} ${BACKEND_PORT} ${REQUEST_TIMEOUT}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
