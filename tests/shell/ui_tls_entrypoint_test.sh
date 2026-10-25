#!/usr/bin/env bash
# The web container must start with a certificate in every TLS mode, under the
# runtime constraints of the shipped compose (read-only root, tmpfs for the
# cert dir). With LETSENCRYPT_DOMAIN set it used to exit 1 on every start:
# certbot is not in the image, and the self-signed fallback was an `else` of
# the same chain, so nginx started without a certificate.
#
# Usage: tests/shell/ui_tls_entrypoint_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-web-tls-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
NAME="spm-tls-$$"; VOL="spm-tls-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1; docker volume rm "$VOL" >/dev/null 2>&1' EXIT

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -f ui/Dockerfile -t "$IMAGE" . >/dev/null || { echo "build failed"; exit 1; }
fi

start() { # mode, extra docker args...
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run -d --name "$NAME" --read-only \
    --tmpfs /tmp --tmpfs /var/run --tmpfs /var/cache/nginx --tmpfs /etc/nginx/ssl \
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

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
