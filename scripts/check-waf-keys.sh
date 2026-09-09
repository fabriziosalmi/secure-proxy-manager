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

FILES="backend-go/internal/handlers/settings.go
backend-go/internal/workers/waf_reconciler.go
ui/src/pages/Settings.tsx
docker-compose.yml
deploy/docker-compose.prod.yml
.env.example"

rc=0
count=1
for f in $FILES; do
    got="$(keys_in "$f")"
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
