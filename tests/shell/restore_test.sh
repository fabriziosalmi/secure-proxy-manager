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
# +e on purpose, and it must be explicit. GitHub invokes a run step as
# `bash -e {0}`, so errexit is already ON before the script's first line, and
# `set -uo pipefail` does not clear it. This harness is built to run every
# assertion and print a summary, so the first command that returns non-zero —
# a grep that does not match, a restore.sh that correctly refuses with a
# non-zero status — would end the run silently instead of failing a check.
#
# That is what actually broke this drill in CI. It reported
# "a corrupt backup is refused BEFORE the swap" with an EMPTY detail, which
# reads as restore.sh accepting a corrupt backup; the truth was that the script
# had been killed by errexit and never captured the output. Verified by running
# it on Linux both ways: 6 passed without -e, dead at the first section with it.
set +e
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
# Corrupt a page that holds data, which is what integrity_check inspects, and
# then CHECK that SQLite agrees the file is corrupt before asserting anything
# about restore.sh.
#
# A fixed offset alone was not enough. This used to write 600 random bytes at
# 8300 and trust that to be inside a data page, which held on the machine it
# was written on and failed once in CI: page layout depends on the SQLite build
# and version, so the damage can land in free space, where integrity_check
# returns "ok" by design. The test then reported that restore.sh had failed to
# refuse a corrupt backup, when the backup SQLite was handed was not corrupt in
# any way it recognises. A security gate that is sometimes wrong gets ignored,
# which is worse than not having it.
#
# So: damage progressively deeper until SQLite itself says the file is broken.
# The assertion below then tests the real property — given a backup SQLite
# considers corrupt, restore.sh must refuse it before touching data/.
corrupt_until_sqlite_notices() {
  local db="$1" off
  for off in 8300 12400 16500 20600 24700; do
    dd if=/dev/urandom of="$db" bs=1 seek="$off" count=600 conv=notrunc status=none 2>/dev/null
    if [ "$(sqlite3 "$db" 'PRAGMA integrity_check;' 2>&1 | head -1)" != "ok" ]; then
      return 0
    fi
  done
  return 1
}
if ! corrupt_until_sqlite_notices "$SANDBOX/data.bak.corrupt/proxy_manager.db"; then
  bad "the test could not produce a backup SQLite considers corrupt" \
      "integrity_check still reports ok after damaging five data pages"
fi
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

echo "── a host without sqlite3 must not skip verification silently ──"
# A PATH holding only what the script needs before the verification stage, so
# sqlite3 (and docker) cannot be found. The script is run by absolute bash.
NOBIN="$(mktemp -d)"
for tool in dirname cat; do ln -s "$(command -v "$tool")" "$NOBIN/$tool"; done
run_nosqlite() { ( cd "$SANDBOX" && printf 'restore\n' | env PATH="$NOBIN" "$(command -v bash)" scripts/restore.sh "$@" 2>&1 ); }

out="$(run_nosqlite "$SANDBOX/data.bak.good")"
if grep -q 'sqlite3 is not installed' <<<"$out" && grep -q -- '--skip-check' <<<"$out" \
   && [ "$(cat "$SANDBOX/data/marker" 2>/dev/null)" = "LIVE" ]; then
  ok "no sqlite3 -> refuses, names the escape hatch, and data/ is untouched"
else
  bad "no sqlite3 -> refuses before touching data/" "$out"
fi

out="$(run_nosqlite --skip-check "$SANDBOX/data.bak.good")"
grep -q 'WITHOUT verifying' <<<"$out" && ok "--skip-check proceeds, and says it is unverified" \
                                     || bad "--skip-check proceeds, and says it is unverified" "$out"
rm -rf "$NOBIN"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
