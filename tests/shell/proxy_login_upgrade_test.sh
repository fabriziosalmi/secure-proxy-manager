#!/usr/bin/env bash
# Proxy login across an upgrade, end to end: the real backend and the real
# proxy entrypoint (startup.sh, supervisord, the watchdog that applies a
# reload), sharing /config as the compose files share ./config.
#
# The starting point is the state an install upgraded with proxy login on and
# no proxy credentials has: enable_proxy_auth "true" in the database, the
# /config/proxy_auth_enabled marker, and no password file. The test asserts
# that such an install is closed (every LAN client refused, the reason logged,
# the dashboard told), that setting the credentials through the API opens it
# to signed-in clients only, and that turning login off opens it again.
#
# Usage: tests/shell/proxy_login_upgrade_test.sh [proxy-image] [backend-image]
#   Images are built from proxy/ and backend-go/ when absent.
set -uo pipefail

PROXY_IMAGE="${1:-spm-proxy-test}"
BACKEND_IMAGE="${2:-spm-backend-test}"
PFX="spmlogin$$"
PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()   { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }
expect() { # name got want
  if [ "$2" = "$3" ]; then ok "$1 → $2"; else bad "$1" "got $2, want $3"; fi
}

LAN_NET=192.168.78.0/24; PUB_NET=203.0.113.0/24
PROXY_LAN=192.168.78.10; BACKEND_LAN=192.168.78.5; CLIENT=192.168.78.50
PROXY_PUB=203.0.113.2; PUB_SVC=203.0.113.10
ADMIN_PW="upgrade-admin-$$-pass"
API_CLIENT=192.168.78.6

cleanup() {
  docker rm -f "$PFX-proxy" "$PFX-backend" "$PFX-pub" >/dev/null 2>&1
  docker network rm "$PFX-lan" "$PFX-pub" >/dev/null 2>&1
  docker volume rm "$PFX-config" "$PFX-data" >/dev/null 2>&1
  rm -f "${SEEN:-}"
}
trap cleanup EXIT

build_if_missing() { # image dir
  if ! docker image inspect "$1" >/dev/null 2>&1; then
    echo "building $1 from $2 ..."
    docker build -q -t "$1" "$2" >/dev/null || { echo "build of $1 failed"; exit 1; }
  fi
}
build_if_missing "$PROXY_IMAGE" proxy/
build_if_missing "$BACKEND_IMAGE" backend-go/

docker network create --subnet "$LAN_NET" "$PFX-lan" >/dev/null || exit 1
docker network create --subnet "$PUB_NET" "$PFX-pub" >/dev/null || exit 1
docker volume create "$PFX-config" >/dev/null && docker volume create "$PFX-data" >/dev/null || exit 1

# An upstream standing in for a public site.
docker run -d --name "$PFX-pub" --network "$PFX-pub" --ip "$PUB_SVC" --memory 64m --entrypoint /bin/bash "$PROXY_IMAGE" -c '
  mkdir -p /srv && cd /srv && echo ok > index.html && exec python3 -m http.server 80 >/dev/null 2>&1' >/dev/null

# The backend as the compose files run it: no capabilities, read-only root.
start_backend() {
  docker rm -f "$PFX-backend" >/dev/null 2>&1
  docker run -d --name "$PFX-backend" --network "$PFX-lan" --ip "$BACKEND_LAN" --memory 128m \
    --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp --tmpfs /logs \
    -v "$PFX-config:/config" -v "$PFX-data:/data" \
    -e BASIC_AUTH_USERNAME=admin -e BASIC_AUTH_PASSWORD="$ADMIN_PW" \
    -e SECRET_KEY="upgrade-secret-key-$$-0123456789abcdef" -e PROXY_URL="http://$PROXY_LAN:3128" \
    "$BACKEND_IMAGE" >/dev/null || return 1
  local _
  for _ in $(seq 1 40); do docker exec "$PFX-backend" /server -healthcheck >/dev/null 2>&1 && return 0; sleep 0.5; done
  echo "backend did not come up:"; docker logs "$PFX-backend" 2>&1 | tail -20
  return 1
}

# The proxy's real entrypoint, as the compose files run it (read-only root,
# tmpfs where they put one). There is no WAF here: REQMOD is set to bypass.
start_proxy() {
  docker rm -f "$PFX-proxy" >/dev/null 2>&1
  docker create --name "$PFX-proxy" --network "$PFX-lan" --ip "$PROXY_LAN" --memory 384m \
    --cap-add NET_ADMIN --security-opt no-new-privileges:true --read-only \
    --tmpfs /tmp --tmpfs /var/run --tmpfs /var/log/supervisor --tmpfs /etc/squid \
    --tmpfs /var/log/squid --tmpfs /var/spool/squid \
    -v "$PFX-config:/config" --add-host "pub.test:$PUB_SVC" \
    -e WAF_FAIL_OPEN=1 -e PROXY_CACHE_SIZE_MB=50 "$PROXY_IMAGE" >/dev/null || return 1
  docker network connect --ip "$PROXY_PUB" "$PFX-pub" "$PFX-proxy"
  docker start "$PFX-proxy" >/dev/null
  local _
  for _ in $(seq 1 60); do
    docker exec "$PFX-proxy" test -f /var/log/squid/watchdog.heartbeat 2>/dev/null \
      && docker exec "$PFX-proxy" sh -c 'ss -ltn | grep -q ":3128"' 2>/dev/null && return 0
    sleep 1
  done
  echo "proxy did not come up:"; docker logs "$PFX-proxy" 2>&1 | tail -30
  return 1
}

# api METHOD PATH [JSON]: the HTTP status and body of a call to the backend.
api() {
  local method="$1" path="$2" body="${3:-}"
  docker run --rm --network "$PFX-lan" --ip "$API_CLIENT" --memory 64m --entrypoint curl "$PROXY_IMAGE" \
    -s -w '\n%{http_code}' --max-time 20 -u "admin:$ADMIN_PW" -X "$method" \
    -H 'Content-Type: application/json' ${body:+--data "$body"} "http://$BACKEND_LAN:5000$path" 2>/dev/null
}
status_of() { tail -1 <<<"$1"; }
json_field() { # body python-expression-on-d
  sed '$d' <<<"$1" | python3 -I -c "import json,sys; d=json.load(sys.stdin); print($2)" 2>/dev/null
}

# Client lines in the access log so far. Squid writes the log through its log
# daemon, so a line can land a moment after the response.
client_lines() {
  local n
  n="$(docker exec "$PFX-proxy" sh -c "grep -c ' $CLIENT ' /var/log/squid/access.log 2>/dev/null || true")"
  echo "${n:-0}"
}
# browse [curl args]: what a LAN client gets for a page through the proxy.
# The count of client lines before it is kept for last_reason, in a file
# because browse runs in a command substitution.
SEEN="$(mktemp)"
browse() {
  client_lines > "$SEEN"
  docker run --rm --network "$PFX-lan" --ip "$CLIENT" --memory 64m --entrypoint curl "$PROXY_IMAGE" \
    -s -o /dev/null -w '%{http_code}' --max-time 10 -x "http://$PROXY_LAN:3128" "$@" http://pub.test/ 2>/dev/null
}
# last_reason: the spm_reason field of the line the last browse wrote, once it is there.
last_reason() {
  local _ seen
  seen="$(cat "$SEEN" 2>/dev/null)"
  for _ in $(seq 1 25); do [ "$(client_lines)" -gt "${seen:-0}" ] && break; sleep 0.2; done
  docker exec "$PFX-proxy" sh -c "grep ' $CLIENT ' /var/log/squid/access.log | tail -1" | awk '{print $12}'
}
proxy_state() {
  docker exec "$PFX-proxy" sed -n 's/.*"state":"\([a-z_]*\)".*/\1/p' /config/proxy_auth_status.json 2>/dev/null
}

echo "── the state an install upgraded with login on and no credentials has ──"
start_backend || exit 1
# A restore writes the stored setting and the marker file as a save of the
# older version did, and no password file: there are no credentials to write.
res="$(api POST /api/maintenance/restore-config '{"config":{"enable_proxy_auth":"true"}}')"
expect "seed: login on in the database"                  "$(status_of "$res")" 200
expect "seed: the login marker is in /config"            "$(docker exec "$PFX-backend" sh -c 'test -f /config/proxy_auth_enabled && echo yes')" yes
expect "seed: no password file"                          "$(docker exec "$PFX-backend" sh -c 'test -e /config/proxy_users.htpasswd && echo present || echo absent')" absent

echo "── after the upgrade: every client is refused until credentials are set ──"
start_proxy || exit 1
expect "LAN client without credentials"                  "$(browse)" 403
expect "  reason logged"                                 "$(last_reason)" proxy_auth_unset
expect "LAN client sending credentials"                  "$(browse -U someone:some-password-1)" 403
expect "  reason logged"                                 "$(last_reason)" proxy_auth_unset
expect "the proxy records no_credentials"                "$(proxy_state)" no_credentials
expect "the proxy log says why"                          "$(docker logs "$PFX-proxy" 2>&1 | grep -c 'proxy login is on but no proxy credentials are set')" 1
res="$(api GET /api/status)"
expect "GET /api/status reports it"                      "$(json_field "$res" 'd["data"]["proxy_auth"]["state"]')" no_credentials
res="$(api GET /api/analytics/coverage)"
expect "GET /api/analytics/coverage reports it"          "$(json_field "$res" 'd["data"]["proxy_login_status"]["state"]')" no_credentials
res="$(api GET /api/settings)"
expect "settings: login on"                              "$(json_field "$res" '[r["setting_value"] for r in d["data"] if r["setting_name"]=="enable_proxy_auth"][0]')" true
expect "settings: no proxy password stored"              "$(json_field "$res" 'any(r.get("is_set") for r in d["data"] if r["setting_name"]=="proxy_auth_password")')" False
res="$(api POST /api/settings '{"enable_proxy_auth":"true","bandwidth_limit_mbps":"100"}')"
expect "saving with login on and no credentials"         "$(status_of "$res")" 400
expect "  the refusal names both credentials"            "$(json_field "$res" '",".join(sorted(d["errors"]))')" proxy_auth_password,proxy_auth_username

echo "── credentials set through the API ──"
res="$(api POST /api/settings '{"enable_proxy_auth":"true","proxy_auth_username":"office","proxy_auth_password":"upgrade-proxy-pass-1"}')"
expect "save the credentials"                            "$(status_of "$res")" 200
res="$(api POST /api/maintenance/reload-config '{}')"
expect "the proxy applies the reload"                    "$(json_field "$res" 'd["status"]')" success
expect "the file belongs to the proxy group"             "$(docker exec "$PFX-proxy" stat -c '%U:%G %a' /config/proxy_users.htpasswd)" "root:proxy 640"
expect "the proxy records enforced"                      "$(proxy_state)" enforced
expect "LAN client without credentials"                  "$(browse)" 407
expect "  reason logged"                                 "$(last_reason)" proxy_auth
expect "LAN client with wrong credentials"               "$(browse -U office:wrong-password-1)" 407
expect "LAN client with the credentials"                 "$(browse -U office:upgrade-proxy-pass-1)" 200
expect "  reason logged"                                 "$(last_reason)" none
res="$(api GET /api/settings)"
case "$res" in *upgrade-proxy-pass-1*) bad "GET /api/settings never returns the proxy password" "it is in the body";; *) ok "GET /api/settings never returns the proxy password";; esac
expect "  and says one is stored"                        "$(json_field "$res" '[r.get("is_set") for r in d["data"] if r["setting_name"]=="proxy_auth_password"][0]')" True

echo "── a backend restart keeps the file in line with the settings ──"
before="$(docker exec "$PFX-proxy" stat -c '%i %Y' /config/proxy_users.htpasswd)"
start_backend || exit 1
expect "a file already in line is not rewritten"         "$(docker exec "$PFX-proxy" stat -c '%i %Y' /config/proxy_users.htpasswd)" "$before"
docker exec "$PFX-proxy" rm -f /config/proxy_users.htpasswd
start_backend || exit 1
expect "a missing file is written again at startup"      "$(docker exec "$PFX-proxy" grep -c '^office:' /config/proxy_users.htpasswd 2>/dev/null)" 1

echo "── login turned off ──"
res="$(api POST /api/settings '{"enable_proxy_auth":"false","proxy_auth_username":"office"}')"
expect "turn login off"                                  "$(status_of "$res")" 200
res="$(api POST /api/maintenance/reload-config '{}')"
expect "the proxy applies the reload"                    "$(json_field "$res" 'd["status"]')" success
expect "the backend removed the password file"           "$(docker exec "$PFX-proxy" sh -c 'test -e /config/proxy_users.htpasswd && echo present || echo absent')" absent
expect "the proxy records off"                           "$(proxy_state)" off
expect "LAN client without credentials"                  "$(browse)" 200

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
