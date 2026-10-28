#!/bin/sh
set -eu

# Parse BACKEND_URL (e.g. http://backend:5000) into host and port
_backend="${BACKEND_URL:-http://backend:5000}"
_backend="${_backend#http://}"
_backend="${_backend#https://}"
BACKEND_HOST="${_backend%:*}"
BACKEND_PORT="${_backend##*:}"
export BACKEND_HOST BACKEND_PORT

# A backend name is resolved again at runtime through the container's DNS
# resolver (nginx.conf.template, upstream spm_backend). An address, or a name
# /etc/hosts holds (extra_hosts), is used as it is, resolved once at start:
# nginx's resolver asks DNS only, so it would not find that name.
BACKEND_RESOLVE=" resolve"
case "$BACKEND_HOST" in
    *[!0-9.]*) ;;
    *) BACKEND_RESOLVE="" ;;
esac
case "$BACKEND_HOST" in
    \[*\]) BACKEND_RESOLVE="" ;;
esac
if [ -n "$BACKEND_RESOLVE" ] && awk -v h="$BACKEND_HOST" '$1 !~ /^#/ { for (i = 2; i <= NF; i++) if ($i == h) f = 1 } END { exit !f }' /etc/hosts 2>/dev/null; then
    BACKEND_RESOLVE=""
fi
NGINX_RESOLVER=$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf 2>/dev/null || true)
case "$NGINX_RESOLVER" in
    "") NGINX_RESOLVER=127.0.0.11 ;;
    *:*) NGINX_RESOLVER="[$NGINX_RESOLVER]" ;;
esac
export BACKEND_RESOLVE NGINX_RESOLVER
export REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-120}"

# ── TLS Setup ────────────────────────────────────────────────────────
CERT_DIR="/etc/nginx/ssl"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
LE_DOMAIN="${LETSENCRYPT_DOMAIN:-}"
LE_EMAIL="${LETSENCRYPT_EMAIL:-}"

mkdir -p "$CERT_DIR"

# Priority: 1) Let's Encrypt  2) Mounted cert  3) Self-signed.
#
# The container must come up with SOME certificate. The self-signed branch used
# to be an `else` of the same chain as Let's Encrypt, so when LE was configured
# and failed (always, in the shipped image: certbot is not installed and the
# read-only root filesystem cannot install it at runtime) nginx started with no
# certificate and the container exited, over and over. LE is now an attempt;
# the fallbacks run whenever it did not produce a certificate.
LE_ACTIVE=0
if [ -n "$LE_DOMAIN" ] && [ -n "$LE_EMAIL" ]; then
    echo "[entrypoint] Let's Encrypt mode: domain=$LE_DOMAIN email=$LE_EMAIL"
    LE_CERT="/etc/letsencrypt/live/$LE_DOMAIN/fullchain.pem"
    LE_KEY="/etc/letsencrypt/live/$LE_DOMAIN/privkey.pem"

    if ! command -v certbot >/dev/null 2>&1; then
        echo "[entrypoint] ERROR: LETSENCRYPT_DOMAIN is set but certbot is not in this image. Falling back; to use a CA certificate, mount it at $CERT_FILE and $KEY_FILE." >&2
    else
        mkdir -p /var/www/certbot
        if [ -f "$LE_CERT" ] && [ -f "$LE_KEY" ]; then
            echo "[entrypoint] Existing Let's Encrypt certificate found — checking renewal"
            certbot renew --quiet --webroot -w /var/www/certbot || echo "[entrypoint] WARNING: certbot renew failed" >&2
        else
            echo "[entrypoint] Requesting new certificate from Let's Encrypt..."
            # A complete, standalone nginx for the HTTP-01 challenge, on the
            # container port that host port 80 maps to (8011). The old one was a
            # bare server{} block (nginx rejects it) listening on 80.
            cat > /tmp/acme-nginx.conf <<NGINX
pid /tmp/acme-nginx.pid;
events {}
http {
    access_log off;
    client_body_temp_path /tmp/acme-body;
    server {
        listen 8011;
        server_name $LE_DOMAIN;
        location /.well-known/acme-challenge/ { root /var/www/certbot; }
        location / { return 444; }
    }
}
NGINX
            nginx -c /tmp/acme-nginx.conf -g 'daemon off;' &
            ACME_PID=$!
            sleep 2
            certbot certonly --webroot -w /var/www/certbot \
                -d "$LE_DOMAIN" --email "$LE_EMAIL" \
                --agree-tos --non-interactive --quiet \
                || echo "[entrypoint] WARNING: Let's Encrypt issuance failed" >&2
            kill "$ACME_PID" 2>/dev/null || true
        fi
        if [ -f "$LE_CERT" ] && [ -f "$LE_KEY" ]; then
            ln -sf "$LE_CERT" "$CERT_FILE"
            ln -sf "$LE_KEY" "$KEY_FILE"
            LE_ACTIVE=1
            echo "[entrypoint] Let's Encrypt certificate active for $LE_DOMAIN"
            # Daily renewal check
            (while true; do sleep 86400; certbot renew --quiet --webroot -w /var/www/certbot && nginx -s reload; done) &
        fi
    fi
fi

if [ "$LE_ACTIVE" = 1 ]; then
    :
elif [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "[entrypoint] Using mounted TLS certificate"
else
    echo "[entrypoint] Generating self-signed TLS certificate..."
    # openssl is installed at build time (ui/Dockerfile); the root filesystem
    # is read-only, so nothing can be installed here.
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/C=US/ST=Local/L=Local/O=SecureProxyManager/CN=proxy-manager" \
        -addext "subjectAltName=DNS:localhost,DNS:proxy-manager,IP:127.0.0.1" \
        2>/dev/null
    echo "[entrypoint] Self-signed certificate generated (valid 1 year)"
fi

# Substitute env vars into the nginx template
envsubst '${BACKEND_HOST} ${BACKEND_PORT} ${BACKEND_RESOLVE} ${NGINX_RESOLVER} ${REQUEST_TIMEOUT}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
