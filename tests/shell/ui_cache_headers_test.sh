#!/usr/bin/env bash
# What the browser may keep, and for how long. index.html was served with no
# Cache-Control, so a browser could keep it by heuristic after an upgrade and
# load scripts that no longer exist (a blank page until a hard reload). The
# one-year immutable rule matched every .js, .css and .svg, also the files in
# ui/public whose names never change (icons.svg, logo.svg, favicon.svg), so a
# change to one of them would never reach a returning browser.
#
#   1. index.html, and a client route that falls back to it: no-cache;
#   2. a hashed Vite asset under /assets/: public, immutable, one year;
#   3. an unhashed file from ui/public: not immutable, revalidated;
#   4. the server-level security headers are still on every one of them.
#
# Usage: tests/shell/ui_cache_headers_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-web-cache-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
NAME="spm-cache-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT

docker build -q -f ui/Dockerfile -t "$IMAGE" . >/dev/null || { echo "build failed"; exit 1; }
docker run -d --name "$NAME" --read-only \
  --tmpfs /tmp --tmpfs /var/run --tmpfs /var/cache/nginx --tmpfs /etc/nginx/ssl \
  --tmpfs /etc/nginx/conf.d --tmpfs /var/www/certbot --tmpfs /etc/letsencrypt \
  --add-host backend:127.0.0.1 "$IMAGE" >/dev/null
up=0
for _ in $(seq 1 40); do
  docker exec "$NAME" sh -c 'wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/health' 2>/dev/null && { up=1; break; }
  sleep 0.5
done
[ "$up" = 1 ] || { bad "the web container did not start" "$(docker logs "$NAME" 2>&1 | tail -5)"; exit 1; }

# headers PATH: the response headers, lower case, one per line.
headers() {
  docker exec "$NAME" sh -c "wget -S --no-check-certificate -O /dev/null 'https://127.0.0.1:8443$1' 2>&1" \
    | sed -n 's/^ *//p' | tr 'A-Z' 'a-z'
}
asset=$(docker exec "$NAME" sh -c 'ls /usr/share/nginx/html/assets/ | grep -E "\.js$" | head -n 1')
[ -n "$asset" ] || { bad "no hashed .js asset in the image" ""; exit 1; }

for p in / /index.html /clients; do
  h=$(headers "$p")
  printf '%s\n' "$h" | grep -q '^cache-control: no-cache' && ! printf '%s\n' "$h" | grep -q 'immutable' \
    && ok "$p: no-cache" || bad "$p: want Cache-Control no-cache" "$(printf '%s\n' "$h" | grep -E '^(http|cache-control|expires)' | tr '\n' ' ')"
done
h=$(headers "/assets/$asset")
printf '%s\n' "$h" | grep -q '^cache-control: public, immutable' && printf '%s\n' "$h" | grep -q '^cache-control: max-age=31536000' \
  && ok "/assets/$asset: public, immutable, one year" || bad "/assets/$asset: want immutable for a year" "$(printf '%s\n' "$h" | grep -E '^cache-control' | tr '\n' ' ')"
for p in /icons.svg /logo.svg /favicon.svg; do
  h=$(headers "$p")
  printf '%s\n' "$h" | grep -q '^http/1.1 200' && ! printf '%s\n' "$h" | grep -q 'immutable' && printf '%s\n' "$h" | grep -q '^cache-control: no-cache' \
    && ok "$p: revalidated, not immutable" || bad "$p: want no-cache and no immutable" "$(printf '%s\n' "$h" | grep -E '^(http|cache-control)' | tr '\n' ' ')"
done
for p in / "/assets/$asset" /icons.svg; do
  h=$(headers "$p")
  printf '%s\n' "$h" | grep -q '^strict-transport-security:' && printf '%s\n' "$h" | grep -q '^x-content-type-options: nosniff' \
    && printf '%s\n' "$h" | grep -q '^content-security-policy:' \
    && ok "$p: security headers kept" || bad "$p: security headers missing" "$(printf '%s\n' "$h" | tr '\n' ' ' | cut -c1-300)"
done

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
