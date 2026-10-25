#!/usr/bin/env bash
# Behavioural test of the Squid access policy that generate_squid_conf.sh
# produces. generate_squid_conf_test.sh asserts on the TEXT of squid.conf; that
# cannot see an ordering bug, and the access policy had three of them at once:
#
#   - allow rules scoped by destination only (local_dst, local_dst_url, CONNECT
#     local_dst), evaluated before any source check, so a client from ANY
#     address could tunnel into the LAN or relay to a public host whose name
#     starts with "10.";
#   - proxy auth, content filtering and time restrictions appended AFTER
#     "http_access deny all", where Squid never reaches them;
#   - the IP blacklist written as a SOURCE ACL that also exempted LAN clients,
#     so it could not block a destination at all.
#
# Every case here runs real Squid from the real image against real clients on
# three docker networks, and asserts the HTTP status Squid returns:
#
#   ext 198.18.0.0/24   a source outside every localnet range ("the internet")
#   lan 192.168.77.0/24 an RFC1918 client network with one LAN service on it
#   pub 203.0.113.0/24  an upstream standing in for a public site
#
# Usage: tests/shell/squid_acl_matrix_test.sh [image]
set -uo pipefail

IMAGE="${1:-spm-proxy-test}"
PFX="spmacl$$"
PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()   { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

PROXY_EXT=198.18.0.10; PROXY_LAN=192.168.77.10; PROXY_PUB=203.0.113.2
EXT_CLIENT=198.18.0.50; EXT_OTHER=198.18.0.51; LAN_CLIENT=192.168.77.50
LAN_SVC=192.168.77.20; PUB_SVC=203.0.113.10

cleanup() {
  docker rm -f "$PFX-proxy" "$PFX-pub" "$PFX-lan" >/dev/null 2>&1
  docker network rm "$PFX-ext" "$PFX-lan" "$PFX-pub" >/dev/null 2>&1
}
trap cleanup EXIT

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE from proxy/ ..."
  docker build -q -t "$IMAGE" proxy/ >/dev/null || { echo "build failed"; exit 1; }
fi

docker network create --subnet 198.18.0.0/24   "$PFX-ext" >/dev/null || exit 1
docker network create --subnet 192.168.77.0/24 "$PFX-lan" >/dev/null || exit 1
docker network create --subnet 203.0.113.0/24  "$PFX-pub" >/dev/null || exit 1

# Upstreams: a plain HTTP server on :80 and :8443 (the CONNECT target) serving
# an index and an .exe, from the proxy image itself (python3 is in it).
upstream() {
  local name="$1" net="$2" ip="$3"
  docker run -d --name "$name" --network "$net" --ip "$ip" --entrypoint /bin/bash "$IMAGE" -c '
    mkdir -p /srv && cd /srv && echo ok > index.html && echo MZ > x.exe
    python3 -m http.server 8443 >/dev/null 2>&1 &
    exec python3 -m http.server 80 >/dev/null 2>&1' >/dev/null
}
upstream "$PFX-pub" "$PFX-pub" "$PUB_SVC"
upstream "$PFX-lan" "$PFX-lan" "$LAN_SVC"

# start_proxy SEED [ENV...]: run the generator against a fixture /config built
# by SEED, then run Squid in the foreground. The WAF is absent, so REQMOD is
# set to bypass: this test is about http_access, not ICAP.
start_proxy() {
  local seed="$1"; shift
  docker rm -f "$PFX-proxy" >/dev/null 2>&1
  docker create --name "$PFX-proxy" --network "$PFX-ext" --ip "$PROXY_EXT" \
    --add-host "pub.test:$PUB_SVC" --add-host "10.relay.test:$PUB_SVC" \
    -e WAF_FAIL_OPEN=1 -e PROXY_CACHE_SIZE_MB=50 "$@" \
    --entrypoint /bin/bash "$IMAGE" -c "
      set -e
      mkdir -p /config /etc/squid /var/spool/squid /var/log/squid /run/squid
      $seed
      /usr/local/bin/generate_squid_conf.sh >/tmp/gen.log 2>&1
      chown -R proxy:proxy /var/spool/squid /var/log/squid /run/squid
      squid -z -N >/dev/null 2>&1
      exec squid -N -d1" >/dev/null
  docker network connect --ip "$PROXY_LAN" "$PFX-lan" "$PFX-proxy"
  docker network connect --ip "$PROXY_PUB" "$PFX-pub" "$PFX-proxy"
  docker start "$PFX-proxy" >/dev/null
  local _
  for _ in $(seq 1 40); do
    [ "$(code "$PFX-lan" "$LAN_CLIENT" "http://pub.test/" 2>/dev/null)" != "000" ] && return 0
    sleep 0.5
  done
  echo "proxy did not come up:"; docker logs "$PFX-proxy" 2>&1 | tail -20
  return 1
}

# code NET IP URL [curl args]: HTTP status of a GET through the proxy.
code() {
  local net="$1" ip="$2" url="$3"; shift 3
  docker run --rm --network "$net" --ip "$ip" --entrypoint curl "$IMAGE" \
    -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://$( [ "$net" = "$PFX-ext" ] && echo "$PROXY_EXT" || echo "$PROXY_LAN" ):3128" \
    "$@" "$url" 2>/dev/null
}
# tunnel NET IP HOST:PORT: status of the CONNECT response itself.
tunnel() {
  local net="$1" ip="$2" target="$3"
  docker run --rm --network "$net" --ip "$ip" --entrypoint curl "$IMAGE" \
    -s -o /dev/null -w '%{http_connect}' --max-time 10 -p \
    -x "http://$( [ "$net" = "$PFX-ext" ] && echo "$PROXY_EXT" || echo "$PROXY_LAN" ):3128" \
    "http://$target/" 2>/dev/null
}
expect() { # name got want
  if [ "$2" = "$3" ]; then ok "$1 → $2"; else bad "$1" "got $2, want $3"; fi
}

echo "── baseline: who may use the proxy ──"
start_proxy 'true' || exit 1
expect "LAN client → public site"                        "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      200
expect "LAN client → LAN service"                        "$(code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/")"   200
expect "external client → public site"                   "$(code   "$PFX-ext" "$EXT_CLIENT" http://pub.test/)"      403
expect "external client → LAN service (GET)"             "$(code   "$PFX-ext" "$EXT_CLIENT" "http://$LAN_SVC/")"   403
expect "external client → LAN service (CONNECT :8443)"   "$(tunnel "$PFX-ext" "$EXT_CLIENT" "$LAN_SVC:8443")"      403
expect "external client → public host named 10.*"        "$(code   "$PFX-ext" "$EXT_CLIENT" http://10.relay.test/)" 403
expect "LAN client → cache manager"                      "$(docker run --rm --network "$PFX-lan" --ip "$LAN_CLIENT" --entrypoint curl "$IMAGE" -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$PROXY_LAN:3128/squid-internal-mgr/active_requests")" 403
expect "localhost → cache manager (stats stay possible)" "$(docker exec "$PFX-proxy" curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:3128/squid-internal-mgr/menu)" 200

echo "── IP blacklist blocks the destination ──"
start_proxy "echo $PUB_SVC > /config/ip_blacklist.txt" || exit 1
expect "LAN client → blacklisted destination"            "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      403
expect "LAN client → other destination still allowed"    "$(code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/")"   200

echo "── blacklisted domains are denied by Squid itself ──"
# The DNS sinkhole cannot stop a domain Squid already resolved or cached. Squid
# denies a listed domain before any cache lookup, up to SPM_SQUID_DOMAIN_ACL_MAX.
start_proxy "echo pub.test > /config/domain_blacklist.txt" || exit 1
expect "LAN client → blacklisted domain"                 "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      403
expect "LAN client → other destination still allowed"    "$(code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/")"   200
start_proxy "echo pub.test > /config/domain_blacklist.txt" -e SPM_SQUID_DOMAIN_ACL_MAX=0 || exit 1
expect "over the limit: Squid leaves it to the sinkhole" "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      200

echo "── proxy authentication is enforced ──"
start_proxy 'touch /config/proxy_auth_enabled' -e BASIC_AUTH_USERNAME=acluser -e BASIC_AUTH_PASSWORD=acl-test-pass || exit 1
expect "LAN client without credentials"                  "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      407
expect "LAN client with credentials"                     "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/ -U acluser:acl-test-pass)" 200

echo "── content filtering is enforced ──"
start_proxy "touch /config/content_filtering_enabled; printf '%s\n' '\\.exe\$' > /config/blocked_file_types.txt" || exit 1
expect "LAN client → blocked extension"                  "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/x.exe)" 403
expect "LAN client → allowed file"                       "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/index.html)" 200

echo "── time restrictions are enforced ──"
# A one-minute window twelve hours from now: the current time is outside it.
win_h=$(( ( $(date -u +%-H) + 12 ) % 24 ))
start_proxy "touch /config/time_restrictions_enabled; printf 'TIME_START=%02d:00\nTIME_END=%02d:01\n' $win_h $win_h > /config/time_restrictions.conf" || exit 1
expect "LAN client outside allowed hours"                "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      403

echo "── GUI_IP_WHITELIST admits an extra SOURCE ──"
start_proxy 'true' -e GUI_IP_WHITELIST="$EXT_CLIENT" || exit 1
expect "whitelisted external client → public site"       "$(code   "$PFX-ext" "$EXT_CLIENT" http://pub.test/)"      200
expect "other external client → public site"             "$(code   "$PFX-ext" "$EXT_OTHER"  http://pub.test/)"      403
expect "other external client → whitelisted IP (CONNECT :8443)" "$(tunnel "$PFX-ext" "$EXT_OTHER" "$EXT_CLIENT:8443")" 403

echo "── egress default-deny still applies ──"
start_proxy 'touch /config/egress_default_deny; echo pub.test > /config/dst_allow_domain.txt' || exit 1
expect "LAN client → allowlisted domain"                 "$(code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"      200
expect "LAN client → non-allowlisted name"               "$(code   "$PFX-lan" "$LAN_CLIENT" http://10.relay.test/)" 403

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
