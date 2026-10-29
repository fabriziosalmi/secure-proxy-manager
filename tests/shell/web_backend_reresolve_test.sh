#!/usr/bin/env bash
# The web container must follow the backend to a new address. proxy_pass
# named the backend, and nginx resolved the name once at start: when the
# backend container was recreated alone it came back on a new address and
# every /api request answered 502 until web was restarted (v3.18.2).
#
# A stand-in backend (nginx in the web image, answering with a marker) runs
# under the network alias "backend":
#   1. web reaches backend A;
#   2. backend B joins under the same alias while A still runs, so it has
#      another address, and A is removed: web reaches B within 30 s;
#   3. BACKEND_URL with an address works as before;
#   4. a backend name that only /etc/hosts knows works as before.
#
# Usage: tests/shell/web_backend_reresolve_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-web-reresolve-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
P="spm-rr-$$"; NET="$P-net"
trap 'docker rm -f "$P-web" "$P-a" "$P-b" "$P-ip" "$P-hosts" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1' EXIT

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -q -f ui/Dockerfile -t "$IMAGE" . >/dev/null || { echo "build failed"; exit 1; }
fi
docker network create "$NET" >/dev/null || { echo "network create failed"; exit 1; }

# stub NAME MARKER [docker args...]: a backend on port 5000 answering MARKER.
stub() {
  local name=$1 marker=$2; shift 2
  docker run -d --name "$name" --network "$NET" "$@" --entrypoint sh "$IMAGE" -c "
    printf '%s' 'pid /tmp/s.pid; events {} http { access_log off; client_body_temp_path /tmp/b; proxy_temp_path /tmp/p; fastcgi_temp_path /tmp/f; uwsgi_temp_path /tmp/u; scgi_temp_path /tmp/c; server { listen 5000; location / { default_type application/json; return 200 \"{\\\"stub\\\":\\\"$marker\\\"}\"; } } }' > /tmp/s.conf
    exec nginx -c /tmp/s.conf -g 'daemon off;'" >/dev/null
}
# web NAME [docker args...]: the web container, serving HTTPS.
web() {
  local name=$1; shift
  docker run -d --name "$name" --read-only \
    --tmpfs /tmp --tmpfs /var/run --tmpfs /var/cache/nginx --tmpfs /etc/nginx/ssl \
    --tmpfs /etc/nginx/conf.d --tmpfs /var/www/certbot "$@" "$IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    docker exec "$name" sh -c 'wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/health' 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
api() { docker exec "$1" sh -c 'wget -q --no-check-certificate -O - https://127.0.0.1:8443/api/health 2>&1' 2>/dev/null; }
# expect_within SECONDS NAME MARKER: /api answers from MARKER within SECONDS.
expect_within() {
  for _ in $(seq 1 "$1"); do
    case "$(api "$2")" in *"\"stub\":\"$3\""*) return 0 ;; esac
    sleep 1
  done
  return 1
}
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }

echo "── the backend moves to a new address ──"
stub "$P-a" A --network-alias backend
web "$P-web" --network "$NET" || { bad "web starts" "$(docker logs "$P-web" 2>&1 | tail -5)"; exit 1; }
expect_within 10 "$P-web" A && ok "web reaches backend A ($(ip_of "$P-a"))" || bad "web reaches backend A" "got: $(api "$P-web")"
stub "$P-b" B --network-alias backend
docker rm -f "$P-a" >/dev/null
expect_within 30 "$P-web" B && ok "web follows the backend to B ($(ip_of "$P-b")) without a restart" || bad "web follows the backend to B" "got: $(api "$P-web")"

echo "── BACKEND_URL with an address ──"
web "$P-ip" --network "$NET" -e BACKEND_URL="http://$(ip_of "$P-b"):5000" || bad "web starts with an address" "$(docker logs "$P-ip" 2>&1 | tail -5)"
expect_within 10 "$P-ip" B && ok "web reaches the backend at its address" || bad "web reaches the backend at its address" "got: $(api "$P-ip")"

echo "── a backend name only /etc/hosts knows ──"
web "$P-hosts" --network "$NET" -e BACKEND_URL=http://spm-hosts-only:5000 --add-host "spm-hosts-only:$(ip_of "$P-b")" \
  || bad "web starts with a hosts-file name" "$(docker logs "$P-hosts" 2>&1 | tail -5)"
expect_within 10 "$P-hosts" B && ok "web reaches a backend named in /etc/hosts" || bad "web reaches a backend named in /etc/hosts" "got: $(api "$P-hosts")"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
