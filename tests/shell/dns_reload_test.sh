#!/usr/bin/env bash
# The dns watchdog reloads dnsmasq on every change to the sinkhole file and on
# every reload trigger, also when two writes fall in the same second. It used
# to compare whole-second mtimes only: a domain taken out of the sinkhole in the
# same second as the write before (a list pasted, then set to groups only)
# stayed at 0.0.0.0 until some later change.
#
# A run of the dns image on a volume, with the container paused while the
# files change, so the watchdog only ever sees the final state:
#   1. the sinkhole file is replaced (a new file, as the backend writes it)
#      with the same size and the same mtime: the new entry is sinkholed and
#      the old one is not;
#   2. the sinkhole file is rewritten in place with the same size and mtime,
#      and the reload trigger is rewritten with new content and the same
#      mtime: the trigger reloads dnsmasq.
#
# Usage: tests/shell/dns_reload_test.sh [image]
set -uo pipefail
IMAGE="${1:-spm-dns-reload-test}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
NAME="spm-dns-rl-$$"; VOL="spm-dns-rl-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1; docker volume rm "$VOL" >/dev/null 2>&1' EXIT

docker build -q -t "$IMAGE" dns >/dev/null || { echo "build failed"; exit 1; }
docker volume create "$VOL" >/dev/null
# on_volume SCRIPT: runs SCRIPT in a throwaway container with the volume at /config.
on_volume() { docker run --rm -v "$VOL:/config" --entrypoint sh "$IMAGE" -c "$1"; }
T=1767225600 # a fixed mtime, the same for every write below
H=/config/dnsmasq.d/blocklist.hosts
on_volume "mkdir -p /config/dnsmasq.d
  printf '0.0.0.0 gone.example\n:: gone.example\n' > $H.tmp && mv $H.tmp $H && touch -d @$T $H
  printf 1 > /config/.reload-dns && touch -d @$T /config/.reload-dns"

docker run -d --name "$NAME" -v "$VOL:/config" "$IMAGE" >/dev/null
a() { docker exec "$NAME" dig +short +time=2 +tries=1 "$1" A @127.0.0.1 2>/dev/null | head -n 1; }
# within SECONDS NAME WANT: NAME answers WANT within SECONDS.
within() { for _ in $(seq 1 "$1"); do [ "$(a "$2")" = "$3" ] && return 0; sleep 1; done; return 1; }
within 30 gone.example 0.0.0.0 || { bad "dnsmasq did not start with the sinkhole file" "$(docker logs "$NAME" 2>&1 | tail -5)"; exit 1; }
# The entrypoint touches the sinkhole file at start: put its mtime back to T
# and let the watchdog see that, so T is the mtime it last saw.
on_volume "touch -d @$T $H"
sleep 6

docker pause "$NAME" >/dev/null
on_volume "printf '0.0.0.0 kept.example\n:: kept.example\n' > $H.tmp && mv $H.tmp $H && touch -d @$T $H"
docker unpause "$NAME" >/dev/null
within 10 kept.example 0.0.0.0 && [ "$(a gone.example)" != 0.0.0.0 ] \
  && ok "a sinkhole file replaced in the same second reloads dnsmasq (kept in, gone out)" \
  || bad "a sinkhole file replaced in the same second was not reloaded" "kept=$(a kept.example) gone=$(a gone.example)"

docker pause "$NAME" >/dev/null
on_volume "printf '0.0.0.0 next.example\n:: next.example\n' > $H && touch -d @$T $H
  printf 2 > /config/.reload-dns && touch -d @$T /config/.reload-dns"
docker unpause "$NAME" >/dev/null
within 10 next.example 0.0.0.0 \
  && ok "a reload trigger written in the same second reloads dnsmasq" \
  || bad "a reload trigger written in the same second was not seen" "next=$(a next.example)"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
