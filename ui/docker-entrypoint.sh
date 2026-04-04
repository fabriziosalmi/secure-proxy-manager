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
LE_DOMAIN="${LETSENCRYPT_DOMAIN:-}"
LE_EMAIL="${LETSENCRYPT_EMAIL:-}"

mkdir -p "$CERT_DIR"

# Priority: 1) Let's Encrypt  2) Mounted cert  3) Self-signed
if [ -n "$LE_DOMAIN" ] && [ -n "$LE_EMAIL" ]; then
    echo "[entrypoint] Let's Encrypt mode: domain=$LE_DOMAIN email=$LE_EMAIL"

    # Install certbot if not present
    if ! command -v certbot >/dev/null 2>&1; then
        echo "[entrypoint] Installing certbot..."
        apk add --no-cache certbot >/dev/null 2>&1 || true
    fi

    # Create webroot for ACME challenges
    mkdir -p /var/www/certbot

    # Check if we already have a valid cert
    LE_CERT="/etc/letsencrypt/live/$LE_DOMAIN/fullchain.pem"
    LE_KEY="/etc/letsencrypt/live/$LE_DOMAIN/privkey.pem"

    if [ -f "$LE_CERT" ] && [ -f "$LE_KEY" ]; then
        echo "[entrypoint] Existing Let's Encrypt certificate found — checking renewal"
        certbot renew --quiet --webroot -w /var/www/certbot 2>/dev/null || true
    else
        echo "[entrypoint] Requesting new certificate from Let's Encrypt..."
        # Start nginx temporarily on port 80 for ACME challenge
        cat > /tmp/acme-nginx.conf <<NGINX
server {
    listen 80;
    server_name $LE_DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 444; }
}
NGINX
        nginx -c /tmp/acme-nginx.conf &
        ACME_PID=$!
        sleep 2

        certbot certonly --webroot -w /var/www/certbot \
            -d "$LE_DOMAIN" --email "$LE_EMAIL" \
            --agree-tos --non-interactive --quiet 2>&1 || {
            echo "[entrypoint] Let's Encrypt failed — falling back to self-signed"
            kill $ACME_PID 2>/dev/null || true
            LE_DOMAIN=""
        }
        kill $ACME_PID 2>/dev/null || true
    fi

    # If LE succeeded, symlink certs
    if [ -n "$LE_DOMAIN" ] && [ -f "$LE_CERT" ]; then
        ln -sf "$LE_CERT" "$CERT_FILE"
        ln -sf "$LE_KEY" "$KEY_FILE"
        echo "[entrypoint] Let's Encrypt certificate active for $LE_DOMAIN"

        # Schedule daily renewal check
        (while true; do sleep 86400; certbot renew --quiet --webroot -w /var/www/certbot && nginx -s reload; done) &
    fi

elif [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[entrypoint] Using mounted TLS certificate"

else
    echo "[entrypoint] Generating self-signed TLS certificate..."
    apk add --no-cache openssl >/dev/null 2>&1 || true
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=US/ST=Local/L=Local/O=SecureProxyManager/CN=proxy-manager" \
        -addext "subjectAltName=DNS:localhost,DNS:proxy-manager,IP:127.0.0.1" \
        2>/dev/null
    echo "[entrypoint] Self-signed certificate generated (valid 1 year)"
fi

# Substitute env vars into the nginx template
envsubst '${BACKEND_HOST} ${BACKEND_PORT} ${REQUEST_TIMEOUT}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
