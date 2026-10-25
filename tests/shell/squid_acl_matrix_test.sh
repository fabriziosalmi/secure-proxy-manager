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
# Each case also asserts the block reason Squid wrote for that request: the
# spm_reason note (12th field of the spm logformat) set by the rule that
# decided it, "none" for an allowed request. The statistics are built from that
# field, so a deny rule that loses its annotation, or a rule order change that
# lets another rule decide, fails here. The last two sections add a real
# dnsmasq (the dns image) answering the sinkhole address for a blacklisted
# name, and the real WAF (the waf-go image), whose block is the X-SPM-Reason
# ICAP header (13th field).
#
# Usage: tests/shell/squid_acl_matrix_test.sh [image]
#   WAF_IMAGE / DNS_IMAGE name the WAF and dnsmasq images (built from waf-go/
#   and dns/ when absent).
set -uo pipefail

IMAGE="${1:-spm-proxy-test}"
WAF_IMAGE="${WAF_IMAGE:-spm-waf-test}"
DNS_IMAGE="${DNS_IMAGE:-spm-dns-test}"
PFX="spmacl$$"
PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()   { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

PROXY_EXT=198.18.0.10; PROXY_LAN=192.168.77.10; PROXY_PUB=203.0.113.2
EXT_CLIENT=198.18.0.50; EXT_OTHER=198.18.0.51; LAN_CLIENT=192.168.77.50
LAN_SVC=192.168.77.20; PUB_SVC=203.0.113.10
DNS_SVC=192.168.77.53; WAF_SVC=192.168.77.44

cleanup() {
  docker rm -f "$PFX-proxy" "$PFX-pub" "$PFX-lan" "$PFX-dns" "$PFX-waf" >/dev/null 2>&1
  docker network rm "$PFX-ext" "$PFX-lan" "$PFX-pub" >/dev/null 2>&1
}
trap cleanup EXIT

build_if_missing() { # image dir
  if ! docker image inspect "$1" >/dev/null 2>&1; then
    echo "building $1 from $2 ..."
    docker build -q -t "$1" "$2" >/dev/null || { echo "build of $1 failed"; exit 1; }
  fi
}
build_if_missing "$IMAGE" proxy/

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
# set to bypass: this test is about http_access, not ICAP (except in the WAF
# section, which runs the WAF and names it with --add-host waf:...).
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
    if [ "$(code "$PFX-lan" "$LAN_CLIENT" "http://pub.test/" 2>/dev/null)" != "000" ]; then
      settle; return 0
    fi
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
# watchdog_py CODE: run CODE in the proxy container with the image's watchdog
# imported as w (its poll loop runs only as __main__).
watchdog_py() {
  docker exec "$PFX-proxy" python3 -I -c "
import importlib.util, json, types
spec = importlib.util.spec_from_file_location('w', '/usr/local/bin/blacklist_watchdog.py')
w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
$1" 2>&1 | tail -3
}

# Access-log lines so far. Squid writes the log through its log daemon, so a
# line can land a moment after the response; logged waits for it.
nlines() { docker exec "$PFX-proxy" sh -c 'wc -l < /var/log/squid/access.log' 2>/dev/null || echo 0; }
# settle: wait until the readiness probe's line is in the log, so the first
# case of a section does not read it as its own.
settle() {
  local a b _
  for _ in $(seq 1 10); do
    a="$(nlines)"; sleep 0.3; b="$(nlines)"
    [ "$a" = "$b" ] && [ "$b" -gt 0 ] && return 0
  done
}
# logged BEFORE FIELD: field FIELD of the first access-log line written after
# the log had BEFORE lines (12 = spm_reason note, 13 = X-SPM-Reason from ICAP).
logged() {
  local before="$1" field="$2" _
  for _ in $(seq 1 25); do
    [ "$(nlines)" -gt "$before" ] && break
    sleep 0.2
  done
  docker exec "$PFX-proxy" sed -n "$((before + 1))p" /var/log/squid/access.log | awk -v f="$field" '{print $f}'
}
# check NAME WANT_STATUS WANT_REASON code|tunnel NET IP TARGET [curl args]:
# the status the client saw and the reason Squid logged for that request.
check() {
  local name="$1" want="$2" reason="$3" kind="$4"; shift 4
  local before got
  before="$(nlines)"
  got="$("$kind" "$@")"
  expect "$name" "$got" "$want"
  expect "$name: reason logged" "$(logged "$before" 12)" "$reason"
}

echo "── baseline: who may use the proxy ──"
start_proxy 'true' || exit 1
check  "LAN client → public site"                        200 none          code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client → LAN service"                        200 none          code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/"
check  "external client → public site"                   403 source_gate   code   "$PFX-ext" "$EXT_CLIENT" http://pub.test/
check  "external client → LAN service (GET)"             403 source_gate   code   "$PFX-ext" "$EXT_CLIENT" "http://$LAN_SVC/"
check  "external client → LAN service (CONNECT :8443)"   403 source_gate   tunnel "$PFX-ext" "$EXT_CLIENT" "$LAN_SVC:8443"
check  "external client → public host named 10.*"        403 source_gate   code   "$PFX-ext" "$EXT_CLIENT" http://10.relay.test/
before="$(nlines)"
expect "LAN client → cache manager"                      "$(docker run --rm --network "$PFX-lan" --ip "$LAN_CLIENT" --entrypoint curl "$IMAGE" -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$PROXY_LAN:3128/squid-internal-mgr/active_requests")" 403
expect "LAN client → cache manager: reason logged"       "$(logged "$before" 12)" other
expect "localhost → cache manager (stats stay possible)" "$(docker exec "$PFX-proxy" curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:3128/squid-internal-mgr/menu)" 200
check_cache_stats() { # section label
  local before
  before="$(nlines)"
  # The watchdog's own fetch and parser, run in the proxy container against
  # this Squid: every field it reads is there, and the capacity is the
  # PROXY_CACHE_SIZE_MB=50 cache_dir (51200 KB).
  expect "$1: the watchdog reads the info page" "$(watchdog_py '
port = w.squid_http_port()
info = w.parse_squid_info(w.fetch_cache_manager("info", port))
cap = w.parse_squid_storedir(w.fetch_cache_manager("storedir", port))
gone = sorted(k for k, v in info.items() if v is None and "hit_ratio" not in k)
print("port=%d capacity=%s missing=%s" % (port, cap, ",".join(gone) or "none"))')" "port=3128 capacity=51200 missing=none"
  # collect_cache_stats end to end: the file it writes, with its fields.
  expect "$1: a collection writes cache_stats.json" "$(watchdog_py '
w.CACHE_STATS = "/tmp/cache_stats.json"
st = types.SimpleNamespace(cache_stats_due=0.0, cache_stats_problem=None, disk_capacity_kb=None, disk_capacity_conf=None)
ok = w.collect_cache_stats(st)
doc = json.load(open(w.CACHE_STATS))
print(ok, doc["version"], doc["disk_capacity_kb"], doc["uptime_s"] is not None, doc["store_entries"] is not None)')" "True 1 51200 True True"
  sleep 1
  expect "$1: the watchdog's fetches are not in the access log" "$(nlines)" "$before"
}
check_cache_stats "cache statistics"

echo "── direct IP, port and method rules ──"
check  "LAN client → public IP literal (GET)"            403 direct_ip       code   "$PFX-lan" "$LAN_CLIENT" "http://$PUB_SVC/"
check  "LAN client → public IP literal (CONNECT :8443)"  403 direct_ip       tunnel "$PFX-lan" "$LAN_CLIENT" "$PUB_SVC:8443"
check  "LAN client → port outside Safe_ports"            403 port_policy     code   "$PFX-lan" "$LAN_CLIENT" http://pub.test:22/
check  "LAN client → CONNECT to a non-SSL port"          403 port_policy     tunnel "$PFX-lan" "$LAN_CLIENT" pub.test:8080
check  "LAN client → PUT"                                403 protocol_policy code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/ -X PUT

echo "── IP blacklist blocks the destination ──"
start_proxy "echo $PUB_SVC > /config/ip_blacklist.txt" || exit 1
check  "LAN client → blacklisted destination"            403 ip_blacklist  code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client → other destination still allowed"    200 none          code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/"

echo "── an IP list with 2,000 entries another entry covers ──"
# Squid warns once per covered entry and aborts at startup past 1000 queued
# messages (earlyMessages->size() < 1000): a real 50,772-entry import kept the
# proxy in a restart loop. The list must reach Squid collapsed.
start_proxy "{ echo 10.200.0.0/16; for i in \$(seq 0 7); do for j in \$(seq 1 250); do echo 10.200.\$i.\$j; done; done; echo $PUB_SVC; } > /config/ip_blacklist.txt" || exit 1
check  "proxy starts, blacklisted destination denied"    403 ip_blacklist  code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client → other destination still allowed"    200 none          code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/"
expect "Squid's copy holds the 2 covering networks"      "$(docker exec "$PFX-proxy" grep -c . /etc/squid/blacklists/ip/local.txt)" 2

echo "── blacklisted domains are denied by Squid itself ──"
# The DNS sinkhole cannot stop a domain Squid already resolved or cached. Squid
# denies a listed domain before any cache lookup, up to SPM_SQUID_DOMAIN_ACL_MAX.
start_proxy "echo pub.test > /config/domain_blacklist.txt" || exit 1
check  "LAN client → blacklisted domain"                 403 domain_blacklist code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client → blacklisted domain (CONNECT)"       403 domain_blacklist tunnel "$PFX-lan" "$LAN_CLIENT" pub.test:8443
check  "LAN client → other destination still allowed"    200 none             code   "$PFX-lan" "$LAN_CLIENT" "http://$LAN_SVC/"
# The backend writes wildcard entries as "*.name"; to dstdomain that is a
# literal host that never matches. dnsmasq blocks the exact name, so must Squid.
start_proxy "echo '*.pub.test' > /config/domain_blacklist.txt" || exit 1
check  "LAN client → domain listed as *.name"            403 domain_blacklist code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
start_proxy "echo pub.test > /config/domain_blacklist.txt" -e SPM_SQUID_DOMAIN_ACL_MAX=0 || exit 1
check  "over the limit: Squid leaves it to the sinkhole" 200 none             code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/

echo "── proxy authentication is enforced ──"
start_proxy 'touch /config/proxy_auth_enabled' -e BASIC_AUTH_USERNAME=acluser -e BASIC_AUTH_PASSWORD=acl-test-pass || exit 1
check  "LAN client without credentials"                  407 proxy_auth    code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client with wrong credentials"               407 proxy_auth    code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/ -U acluser:wrong
# The auth rule sets its reason before the auth ACL decides (that ACL must
# stay last for the 407); the allow rule that admits the request resets it.
check  "LAN client with credentials"                     200 none          code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/ -U acluser:acl-test-pass

echo "── content filtering is enforced ──"
start_proxy "touch /config/content_filtering_enabled; printf '%s\n' '\\.exe\$' > /config/blocked_file_types.txt" || exit 1
check  "LAN client → blocked extension"                  403 content_filter code  "$PFX-lan" "$LAN_CLIENT" http://pub.test/x.exe
check  "LAN client → allowed file"                       200 none           code  "$PFX-lan" "$LAN_CLIENT" http://pub.test/index.html

echo "── time restrictions are enforced ──"
# A one-minute window twelve hours from now: the current time is outside it.
win_h=$(( ( $(date -u +%-H) + 12 ) % 24 ))
start_proxy "touch /config/time_restrictions_enabled; printf 'TIME_START=%02d:00\nTIME_END=%02d:01\n' $win_h $win_h > /config/time_restrictions.conf" || exit 1
check  "LAN client outside allowed hours"                403 time_restriction code "$PFX-lan" "$LAN_CLIENT" http://pub.test/

echo "── GUI_IP_WHITELIST admits an extra SOURCE ──"
start_proxy 'true' -e GUI_IP_WHITELIST="$EXT_CLIENT" || exit 1
check  "whitelisted external client → public site"       200 none          code   "$PFX-ext" "$EXT_CLIENT" http://pub.test/
check  "other external client → public site"             403 source_gate   code   "$PFX-ext" "$EXT_OTHER"  http://pub.test/
check  "other external client → whitelisted IP (CONNECT :8443)" 403 source_gate tunnel "$PFX-ext" "$EXT_OTHER" "$EXT_CLIENT:8443"

echo "── egress default-deny still applies ──"
start_proxy 'touch /config/egress_default_deny; echo pub.test > /config/dst_allow_domain.txt' || exit 1
check  "LAN client → allowlisted domain"                 200 none          code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
check  "LAN client → non-allowlisted name"               403 egress_policy code   "$PFX-lan" "$LAN_CLIENT" http://10.relay.test/

echo "── a name the DNS sinkhole answers is denied, with the block page ──"
# Above SPM_SQUID_DOMAIN_ACL_MAX only dnsmasq knows the list. It answers 0.0.0.0
# and :: for a blacklisted name; Squid used to connect to that address and log
# TCP_TUNNEL/503 or TCP_MISS/503 (a connection error for the client, nothing
# in the statistics). The dns_sinkhole rule denies the answer itself.
build_if_missing "$DNS_IMAGE" dns/
docker run -d --name "$PFX-dns" --network "$PFX-lan" --ip "$DNS_SVC" --entrypoint /bin/sh "$DNS_IMAGE" -c '
  mkdir -p /config/dnsmasq.d
  printf "0.0.0.0 sink.test\n:: sink.test\n" > /config/dnsmasq.d/blocklist.hosts
  exec dnsmasq --conf-file=/dev/null --no-daemon --user=root --listen-address=0.0.0.0 --bind-interfaces --no-resolv --addn-hosts=/config/dnsmasq.d/blocklist.hosts' >/dev/null
start_proxy 'true' --add-host "dns:$DNS_SVC" || exit 1
expect "the generator points Squid at dnsmasq"           "$(docker exec "$PFX-proxy" grep -c "^dns_nameservers $DNS_SVC$" /etc/squid/squid.conf)" 1
check  "LAN client → sinkholed name (GET)"               403 domain_blacklist_dns code   "$PFX-lan" "$LAN_CLIENT" http://sink.test/
check  "LAN client → sinkholed name (CONNECT)"           403 domain_blacklist_dns tunnel "$PFX-lan" "$LAN_CLIENT" sink.test:443
check  "LAN client → name dnsmasq does not sinkhole"     200 none                 code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/
docker rm -f "$PFX-dns" >/dev/null 2>&1

echo "── a WAF block is told apart from a Squid deny ──"
# Both are a 403 to the client. The WAF names itself in its ICAP response
# (X-SPM-Reason: waf), which Squid logs as the 13th field; the note stays none
# because an allow rule let the request through to the WAF.
build_if_missing "$WAF_IMAGE" waf-go/
docker run -d --name "$PFX-waf" --network "$PFX-lan" --ip "$WAF_SVC" --memory 128m \
  -e WAF_TRAFFIC_LOG_PATH=/tmp/waf_traffic.jsonl "$WAF_IMAGE" >/dev/null
for _ in $(seq 1 20); do docker exec "$PFX-waf" wget -q --spider http://localhost:8080/health 2>/dev/null && break; sleep 0.5; done
start_proxy "echo bl.test > /config/domain_blacklist.txt" --add-host "waf:$WAF_SVC" --add-host "bl.test:$PUB_SVC" || exit 1
attack='http://pub.test/?q=%3Cscript%3Ealert(1)%3C/script%3E'
before="$(nlines)"
expect "LAN client → request the WAF blocks"             "$(code "$PFX-lan" "$LAN_CLIENT" "$attack")" 403
expect "WAF block: the ICAP header is logged"            "$(logged "$before" 13)" waf
expect "WAF block: no Squid rule claims it"              "$(logged "$before" 12)" none
before="$(nlines)"
expect "LAN client → blacklisted domain, same proxy"     "$(code "$PFX-lan" "$LAN_CLIENT" http://bl.test/)" 403
expect "Squid deny: reason logged"                       "$(logged "$before" 12)" domain_blacklist
expect "Squid deny: no WAF header"                       "$(logged "$before" 13)" -
check  "LAN client → clean request through the WAF"      200 none          code   "$PFX-lan" "$LAN_CLIENT" http://pub.test/

echo "── cache statistics do not go through the WAF ──"
# REQMOD fail-closed and the WAF stopped: client traffic is refused, the
# watchdog's localhost fetch of the cache manager still answers.
start_proxy 'true' --add-host "waf:$WAF_SVC" -e WAF_FAIL_OPEN=0 || exit 1
expect "REQMOD is fail-closed"                           "$(docker exec "$PFX-proxy" grep -c 'reqmod_precache bypass=0 ' /etc/squid/squid.conf)" 1
docker stop "$PFX-waf" >/dev/null
got="$(code "$PFX-lan" "$LAN_CLIENT" http://pub.test/)"
if [ "$got" != 200 ]; then ok "WAF down: LAN client → public site not served → $got"; else bad "WAF down: LAN client → public site" "got 200, want a refusal"; fi
settle  # the refused request's own log line, before counting lines again
check_cache_stats "WAF down"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
