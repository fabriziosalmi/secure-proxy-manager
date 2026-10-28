#!/usr/bin/env bash
# SafeSearch and YouTube Restricted Mode must leave the forced names
# resolvable. They were cname= overrides to targets dnsmasq does not know
# locally, so dnsmasq answered the CNAME with no address: with SafeSearch on,
# www.google.com, www.bing.com and duckduckgo.com could not be reached
# through the proxy at all (Squid: TCP_TUNNEL/503 in 1 ms).
#
# Runs of the dns image with both features on:
#   1. normal upstream resolvers: every forced name has an IPv4 address, and
#      the Google and YouTube ones are Google's enforcement address;
#   2. a stand-in upstream on a private network, refreshed every few seconds:
#      - down at start: Google and YouTube resolve to the documented address,
#        Bing and DuckDuckGo are pinned to 0.0.0.0 (blocked, not unfiltered);
#      - up: the refresh picks up its addresses;
#      - up with a new Bing address: the refresh follows it;
#      - down again: the refresh keeps the addresses in use.
#
# Usage: tests/shell/dns_safesearch_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-dns-safesearch-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
NAME="spm-dns-ss-$$"; UP="spm-dns-ss-up-$$"; NET="spm-dns-ss-net-$$"; CFG=$(mktemp -d)
trap 'docker rm -f "$NAME" "$UP" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$CFG"' EXIT

docker build -q -t "$IMAGE" dns >/dev/null || { echo "build failed"; exit 1; }
mkdir -p "$CFG/dnsmasq.d"
echo 1 > "$CFG/safesearch_enabled"
echo 1 > "$CFG/youtube_restricted_enabled"

start() { # extra docker args...
  docker rm -f "$NAME" >/dev/null 2>&1
  docker run -d --name "$NAME" -v "$CFG:/config" "$@" "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    docker exec "$NAME" dig +short +time=1 +tries=1 localhost @127.0.0.1 >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}
a_records() { docker exec "$NAME" dig +short +time=3 "$1" A @127.0.0.1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | tr '\n' ' '; }
# expect_within SECONDS NAME WANT: NAME answers exactly WANT within SECONDS.
expect_within() {
  for _ in $(seq 1 "$1"); do
    [ "$(a_records "$2")" = "$3 " ] && return 0
    sleep 1
  done
  return 1
}
# upstream BING_IP: the stand-in resolver, answering for the four targets.
upstream() {
  docker rm -f "$UP" >/dev/null 2>&1
  docker run -d --name "$UP" --network "$NET" --ip "$UP_IP" --entrypoint dnsmasq "$IMAGE" \
    --no-daemon --conf-file=/dev/null --no-resolv --no-hosts \
    --address=/forcesafesearch.google.com/216.239.38.120 \
    --address=/restrict.youtube.com/216.239.38.120 \
    --address=/strict.bing.com/"$1" \
    --address=/safe.duckduckgo.com/203.0.113.8 >/dev/null
}
# upstream_down: the same address with nothing on port 53, so every lookup
# fails at once (port unreachable) instead of waiting for a timeout.
upstream_down() {
  docker rm -f "$UP" >/dev/null 2>&1
  docker run -d --name "$UP" --network "$NET" --ip "$UP_IP" --entrypoint sleep "$IMAGE" 600 >/dev/null
}

echo "── upstream reachable ──"
start || { bad "dns container starts" "$(docker logs "$NAME" 2>&1 | tail -5)"; exit 1; }
for n in www.google.com www.google.it www.bing.com duckduckgo.com www.youtube.com m.youtube.com; do
  ips=$(a_records "$n")
  [ -n "$ips" ] && ok "$n has an IPv4 address ($ips)" || bad "$n has an IPv4 address" "A answer: $(docker exec "$NAME" dig +short "$n" A @127.0.0.1 | tr '\n' ' ')"
done
for n in www.google.com www.youtube.com; do
  case " $(a_records "$n")" in
    *" 216.239.38.120 "*) ok "$n resolves to Google's enforcement address" ;;
    *) bad "$n resolves to Google's enforcement address" "got: $(a_records "$n")" ;;
  esac
done

echo "── upstream down at start, then back, then moved, then down ──"
SUBNET="10.$((RANDOM % 200 + 20)).$((RANDOM % 250)).0/24"
docker network create --subnet "$SUBNET" "$NET" >/dev/null || { bad "test network" "$SUBNET"; exit 1; }
UP_IP="${SUBNET%.0/24}.53"
upstream_down
start --network "$NET" -e SAFESEARCH_REFRESH_SECONDS=4 \
  -e DNS_UPSTREAM_1="$UP_IP" -e DNS_UPSTREAM_2="$UP_IP" -e DNS_UPSTREAM_3="$UP_IP" \
  || { bad "dns container starts" "$(docker logs "$NAME" 2>&1 | tail -5)"; exit 1; }
for n in www.google.com www.youtube.com; do
  [ "$(a_records "$n")" = "216.239.38.120 " ] && ok "down: $n falls back to the documented address" || bad "down: $n falls back to the documented address" "got: $(a_records "$n")"
done
for n in www.bing.com duckduckgo.com; do
  [ "$(a_records "$n")" = "0.0.0.0 " ] && ok "down: $n is blocked (0.0.0.0)" || bad "down: $n is blocked (0.0.0.0)" "got: $(a_records "$n")"
done
# The log is read whole first: with pipefail, grep -q closing the pipe early
# would fail the pipeline on docker's SIGPIPE.
log=$(docker logs "$NAME" 2>&1)
case "$log" in
  *"did not resolve; blocked"*) ok "down: the start log says why" ;;
  *) bad "down: the start log says why" "$(printf '%s\n' "$log" | grep -i safesearch | head -3)" ;;
esac

upstream 203.0.113.7
expect_within 30 www.bing.com 203.0.113.7 && ok "back: the refresh resolves www.bing.com" || bad "back: the refresh resolves www.bing.com" "got: $(a_records www.bing.com)"
expect_within 5 duckduckgo.com 203.0.113.8 && ok "back: the refresh resolves duckduckgo.com" || bad "back: the refresh resolves duckduckgo.com" "got: $(a_records duckduckgo.com)"

upstream 203.0.113.9
expect_within 30 www.bing.com 203.0.113.9 && ok "moved: the refresh follows the new www.bing.com address" || bad "moved: the refresh follows the new www.bing.com address" "got: $(a_records www.bing.com)"

upstream_down
restarts_before=$(docker logs "$NAME" 2>&1 | grep -c "target address changed")
sleep 15
[ "$(a_records www.bing.com)" = "203.0.113.9 " ] && ok "down again: www.bing.com keeps its address" || bad "down again: www.bing.com keeps its address" "got: $(a_records www.bing.com)"
restarts_after=$(docker logs "$NAME" 2>&1 | grep -c "target address changed")
[ "$restarts_after" = "$restarts_before" ] && ok "down again: dnsmasq is not restarted" || bad "down again: dnsmasq is not restarted" "$restarts_before -> $restarts_after restarts"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
