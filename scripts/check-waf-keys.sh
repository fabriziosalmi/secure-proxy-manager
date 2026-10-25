#!/usr/bin/env bash
# SECURE-QUAL-05. The six WAF heuristic keys are enumerated in six places across
# four file formats — one of which calls itself "the single source of truth" and
# another carries a "Keep in sync with" comment. That copy set had already
# drifted: .env.example showed three of them defaulting to false while the code
# and both compose files default them to true, so an operator uncommenting those
# lines silently DISABLED three heuristics.
#
# Same shape as scripts/check-version-sync.sh: turn a lockstep list into an
# enforced invariant. Portable to bash 3.2 (no associative arrays).
set -euo pipefail
cd "$(dirname "$0")/.."

keys_in() {
    grep -ohE 'waf_h_[a-z]+|WAF_H_[A-Z]+' "$1" 2>/dev/null \
        | grep -viE '_max$' \
        | tr 'A-Z' 'a-z' | sort -u
}

REF_FILE="waf-go/internal/engine/heuristics.go"
REF="$(keys_in "$REF_FILE")"
[ -n "$REF" ] || { echo "FAIL: no heuristic keys found in $REF_FILE"; exit 1; }

FILES="backend-go/internal/handlers/settings_checks.go
backend-go/internal/database/db.go
backend-go/internal/workers/waf_reconciler.go
ui/src/lib/settingsMeta.ts
docker-compose.yml
deploy/docker-compose.prod.yml
.env.example"

rc=0
count=1
for f in $FILES; do
    # A file that moved used to end the script silently: under set -e the
    # failing grep inside the command substitution exited with no message.
    if [ ! -f "$f" ]; then
        echo "FAIL: $f does not exist; update FILES in $0 to where the keys live now"
        rc=1
        continue
    fi
    got="$(keys_in "$f" || true)"
    if [ "$got" != "$REF" ]; then
        echo "FAIL: $f disagrees with $REF_FILE"
        diff <(echo "$REF") <(echo "$got") | sed 's/^/    /' || true
        rc=1
    fi
    count=$((count + 1))
done

if [ $rc -eq 0 ]; then
    echo "OK: the WAF heuristic key set is identical across $count files"
fi
exit $rc
