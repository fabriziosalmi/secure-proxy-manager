#!/usr/bin/env bash
# The web container must start with a certificate in every TLS mode, under the
# runtime constraints of the shipped compose (read-only root, the web-tls
# volume for the cert dir). With LETSENCRYPT_DOMAIN set it used to exit 1 on every start:
# certbot is not in the image, and the self-signed fallback was an `else` of
# the same chain, so nginx started without a certificate.
#
# Usage: tests/shell/ui_tls_entrypoint_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-web-tls-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
NAME="spm-tls-$$"; VOL="spm-tls-$$"; SSLVOL="spm-tls-ssl-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1; docker volume rm "$VOL" "$SSLVOL" >/dev/null 2>&1' EXIT

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -f ui/Dockerfile -t "$IMAGE" . >/dev/null || { echo "build failed"; exit 1; }
fi

start() { # mode, extra docker args...
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run -d --name "$NAME" --read-only \
    --tmpfs /tmp --tmpfs /var/run --tmpfs /var/cache/nginx -v "$SSLVOL:/etc/nginx/ssl" \
    --tmpfs /etc/nginx/conf.d --tmpfs /var/www/certbot -v "$VOL:/etc/letsencrypt" \
    --add-host backend:127.0.0.1 "$@" "$IMAGE" >/dev/null
  for _ in $(seq 1 20); do
    docker exec "$NAME" sh -c 'wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/health' 2>/dev/null && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || return 1
    sleep 0.5
  done
  return 1
}

# logs_contain TEXT: true once the container's log holds TEXT. docker logs can
# lag the process by a moment, so a single read right after start returned an
# empty log once in CI (PR #424, passed on rerun); retry for up to 10 s.
logs_contain() {
  local _
  for _ in $(seq 1 20); do
    docker logs "$NAME" 2>&1 | grep -qF -- "$1" && return 0
    sleep 0.5
  done
  return 1
}

echo "── self-signed (no TLS settings) ──"
start && ok "serves HTTPS with a generated certificate" || bad "serves HTTPS with a generated certificate" "$(docker logs "$NAME" 2>&1 | tail -3)"

echo "── LETSENCRYPT_DOMAIN set, certbot absent ──"
if start -e LETSENCRYPT_DOMAIN=spm.example.org -e LETSENCRYPT_EMAIL=ops@example.org; then
  ok "still starts and serves HTTPS"
else
  bad "still starts and serves HTTPS" "$(docker logs "$NAME" 2>&1 | tail -3)"
fi
logs_contain 'certbot is not in this image' \
  && ok "says why Let's Encrypt is not active" || bad "says why Let's Encrypt is not active" "$(docker logs "$NAME" 2>&1 | tail -5)"

echo "── the service-to-service API is not published ──"
# /api/internal/alert is for the WAF on the internal network, which posts to
# backend:5000 directly. Through the public port it must be refused by nginx
# itself (404), while the rest of /api/ is still proxied (here 502: nothing
# listens on the backend address the test gives it).
start || bad "restart for the API checks" "$(docker logs "$NAME" 2>&1 | tail -3)"
code() { docker exec "$NAME" curl -sk -o /dev/null -w '%{http_code}' -X "$1" "https://127.0.0.1:8443$2"; }
c=$(code POST /api/internal/alert)
[ "$c" = 404 ] && ok "POST /api/internal/alert is refused by nginx (404)" || bad "POST /api/internal/alert is refused by nginx (404)" "got $c"
c=$(code GET /api/internal/anything)
[ "$c" = 404 ] && ok "anything under /api/internal/ is refused (404)" || bad "anything under /api/internal/ is refused (404)" "got $c"
c=$(code GET /api/health)
[ "$c" = 502 ] && ok "the rest of /api/ is still proxied to the backend" || bad "the rest of /api/ is still proxied to the backend" "got $c, want 502 from the proxy pass"

echo "── the CA certificate for devices ──"
# Proxied to the backend on both ports (502 here: no backend), not redirected
# from plain HTTP to HTTPS: a device fetches it before it trusts anything.
c=$(docker exec "$NAME" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8011/ca.crt)
[ "$c" = 502 ] && ok "/ca.crt on plain HTTP is proxied to the backend" || bad "/ca.crt on plain HTTP is proxied to the backend" "got $c, want 502 (301 is the redirect to HTTPS)"
c=$(code GET /ca.crt)
[ "$c" = 502 ] && ok "/ca.crt on HTTPS is proxied to the backend" || bad "/ca.crt on HTTPS is proxied to the backend" "got $c"

echo "── the PAC file when the proxy does not answer ──"
# pac_return SCHEME PORT: the PAC file's last return, the one for everything
# that is not local.
pac_return() { docker exec "$NAME" curl -sk "$1://127.0.0.1:$2/wpad.dat" | grep 'return "PROXY'; }
want='  return "PROXY 127.0.0.1:3128";'
[ "$(pac_return http 8011)" = "$want" ] && [ "$(pac_return https 8443)" = "$want" ] \
  && ok "by default it never sends the browser around the proxy (no DIRECT)" \
  || bad "by default no DIRECT" "http: $(pac_return http 8011) https: $(pac_return https 8443)"

if start -e PAC_FALLBACK_DIRECT=true; then
  want='  return "PROXY 127.0.0.1:3128; DIRECT";'
  [ "$(pac_return http 8011)" = "$want" ] && [ "$(pac_return https 8443)" = "$want" ] \
    && ok "PAC_FALLBACK_DIRECT=true puts DIRECT back" \
    || bad "PAC_FALLBACK_DIRECT=true puts DIRECT back" "http: $(pac_return http 8011) https: $(pac_return https 8443)"
else
  bad "starts with PAC_FALLBACK_DIRECT=true" "$(docker logs "$NAME" 2>&1 | tail -3)"
fi

if start -e PAC_FALLBACK_DIRECT=maybe; then
  bad "PAC_FALLBACK_DIRECT=maybe is refused" "the container started"
else
  logs_contain "PAC_FALLBACK_DIRECT must be true or false, not 'maybe'" \
    && ok "PAC_FALLBACK_DIRECT=maybe: refuses to start and says why" \
    || bad "PAC_FALLBACK_DIRECT=maybe says why" "$(docker logs "$NAME" 2>&1 | tail -3)"
fi

echo "── both compose files keep the certificate directory ──"
for f in docker-compose.yml deploy/docker-compose.prod.yml; do
  web=$(awk '/^  web:$/{f=1;next} f&&/^  [a-z][a-z0-9_-]*:$/{exit} f' "$f")
  if printf '%s\n' "$web" | grep -q -- '- web-tls:/etc/nginx/ssl' && ! printf '%s\n' "$web" | grep -qE -- '^\s+- /etc/nginx/ssl$'; then
    ok "$f mounts the web-tls volume at /etc/nginx/ssl, not a tmpfs"
  else
    bad "$f mounts the web-tls volume at /etc/nginx/ssl, not a tmpfs" "$(printf '%s\n' "$web" | grep -n 'nginx/ssl')"
  fi
done

echo "── the self-signed certificate is kept ──"
# /etc/nginx/ssl used to be a tmpfs: every start made a new certificate, so
# every browser warned again after a restart or an upgrade.
fingerprint() { docker exec "$NAME" openssl x509 -in /etc/nginx/ssl/server.crt -noout -fingerprint -sha256 2>/dev/null; }
docker volume rm "$SSLVOL" >/dev/null 2>&1
start || bad "starts on an empty certificate volume" "$(docker logs "$NAME" 2>&1 | tail -3)"
first=$(fingerprint)
[ -n "$first" ] && ok "makes a certificate on the first start" || bad "makes a certificate on the first start" "no certificate"
docker restart "$NAME" >/dev/null && sleep 2
[ "$(fingerprint)" = "$first" ] && ok "the same certificate after a restart" || bad "the same certificate after a restart" "$(fingerprint)"
start || bad "starts again with the same volume" "$(docker logs "$NAME" 2>&1 | tail -3)"
[ "$(fingerprint)" = "$first" ] && ok "the same certificate in a new container (an upgrade)" || bad "the same certificate in a new container" "$(fingerprint)"
logs_contain "Using this install's self-signed certificate, valid until" \
  && ok "says it reuses its certificate and until when" || bad "says it reuses its certificate" "$(docker logs "$NAME" 2>&1 | grep entrypoint | tail -3)"

echo "── a self-signed certificate near its end is made again ──"
docker exec "$NAME" sh -c 'openssl req -x509 -nodes -days 10 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj "/C=US/ST=Local/L=Local/O=SecureProxyManager/CN=proxy-manager" 2>/dev/null'
near=$(fingerprint)
start || bad "starts with a certificate 10 days from its end" "$(docker logs "$NAME" 2>&1 | tail -3)"
now=$(fingerprint)
[ -n "$now" ] && [ "$now" != "$near" ] && ok "replaces it with a new one" || bad "replaces it with a new one" "still $now"
docker exec "$NAME" openssl x509 -in /etc/nginx/ssl/server.crt -noout -checkend 25920000 >/dev/null 2>&1 \
  && ok "the new one is valid for about a year (more than 300 days)" || bad "the new one is valid for about a year" "$(docker exec "$NAME" openssl x509 -in /etc/nginx/ssl/server.crt -noout -enddate)"
logs_contain "expires within 30 days: making a new one" && ok "says why it made a new one" || bad "says why it made a new one" "$(docker logs "$NAME" 2>&1 | grep entrypoint | tail -3)"

echo "── a certificate the operator put there is never replaced ──"
docker exec "$NAME" sh -c 'openssl req -x509 -nodes -days 10 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt -subj "/O=Example Corp/CN=spm.example.org" 2>/dev/null'
mine=$(fingerprint)
start || bad "starts with the operator's certificate" "$(docker logs "$NAME" 2>&1 | tail -3)"
[ "$(fingerprint)" = "$mine" ] && ok "keeps it, even 10 days from its end" || bad "keeps the operator's certificate" "$(fingerprint)"
logs_contain "Using the mounted TLS certificate" && ok "says it uses the mounted certificate" || bad "says it uses the mounted certificate" "$(docker logs "$NAME" 2>&1 | grep entrypoint | tail -3)"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
