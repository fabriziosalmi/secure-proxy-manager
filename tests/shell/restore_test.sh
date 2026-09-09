#!/usr/bin/env bash
# SECURE-DATA-02. scripts/restore.sh is the tool an operator reaches for during
# an incident, and nothing ran it — not a test, not a Makefile target, not CI.
# Its whole design point is that it verifies the archive BEFORE replacing the
# live database, and that property was unestablished at the moment it would be
# relied on.
#
# These tests exercise the decision the script exists to make, in a sandbox: it
# must refuse a corrupt or incomplete backup, and it must leave data/ untouched
# when it refuses. The parts that need Docker (compose down/up) are not driven
# here; what is verified is everything up to and including the refusal.
set -uo pipefail

PASS=0; FAIL=0
G="\033[0;32m"; R="\033[0;31m"; N="\033[0m"
ok()  { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ${R}✗${N} %s\n     %s\n" "$1" "${2:-}"; }

command -v sqlite3 >/dev/null 2>&1 || { echo "sqlite3 not installed — skipping"; exit 0; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

# A sandbox that looks like the repository root the script cd's into.
mkdir -p "$SANDBOX/scripts" "$SANDBOX/data"
cp "$REPO/scripts/restore.sh" "$SANDBOX/scripts/"
echo "LIVE" > "$SANDBOX/data/marker"
sqlite3 "$SANDBOX/data/proxy_manager.db" "CREATE TABLE live(x); INSERT INTO live VALUES('current');"

# Enough rows to span several pages: PRAGMA integrity_check validates pages that
# hold data, and returns "ok" for damage in a header or in free space — verified
# directly, corrupting at offsets 2000 and 4200 in a small database is not
# detected while 8300 is. A test that corrupted the first kilobyte would pass
# for the wrong reason.
mkgood() {
  mkdir -p "$1"
  sqlite3 "$1/proxy_manager.db" "CREATE TABLE t(x);" 
  for i in $(seq 1 400); do
    echo "INSERT INTO t VALUES('row-$i-padding-padding-padding');"
  done | sqlite3 "$1/proxy_manager.db"
}

run() { ( cd "$SANDBOX" && printf 'restore\n' | bash scripts/restore.sh "$1" 2>&1 ); }

echo "── refuses what is not a backup ──"
out="$(run "$SANDBOX/data.bak.missing")"
grep -q 'no such backup' <<<"$out" && ok "a nonexistent directory is refused" \
                                   || bad "a nonexistent directory is refused" "$out"

mkdir -p "$SANDBOX/data.bak.empty"
out="$(run "$SANDBOX/data.bak.empty")"
grep -q 'does not contain proxy_manager.db' <<<"$out" && ok "a directory with no database is refused" \
                                                      || bad "a directory with no database is refused" "$out"

echo "── refuses a CORRUPT backup, which is the point ──"
mkgood "$SANDBOX/data.bak.corrupt"
# Corrupt a page that holds data, which is what integrity_check inspects.
dd if=/dev/urandom of="$SANDBOX/data.bak.corrupt/proxy_manager.db" bs=1 seek=8300 count=600 conv=notrunc status=none
out="$(run "$SANDBOX/data.bak.corrupt")"
if grep -qi 'integrity check on the backup failed' <<<"$out"; then
  ok "a corrupt backup is refused BEFORE the swap"
else
  bad "a corrupt backup is refused BEFORE the swap" "$out"
fi

echo "── and the live data survives the refusal ──"
if [ "$(cat "$SANDBOX/data/marker" 2>/dev/null)" = "LIVE" ]; then
  ok "data/ untouched after a refused restore"
else
  bad "data/ untouched after a refused restore" "the live directory was modified or removed"
fi
live="$(sqlite3 "$SANDBOX/data/proxy_manager.db" 'SELECT x FROM live' 2>&1)"
[ "$live" = "current" ] && ok "the live database is still the live one" \
                        || bad "the live database is still the live one" "$live"

echo "── accepts a good backup (verification stage only) ──"
mkgood "$SANDBOX/data.bak.good"
out="$(run "$SANDBOX/data.bak.good")"
grep -q 'passes PRAGMA integrity_check' <<<"$out" && ok "a sound backup passes verification" \
                                                  || bad "a sound backup passes verification" "$out"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
