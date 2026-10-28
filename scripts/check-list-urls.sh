#!/usr/bin/env bash
# Every URL the UI offers in Popular Lists and every auto-refresh default must
# answer 200. The URLs are read from the source rather than listed here: four
# hand-picked URLs passed while HaGeZi answered 404 and Talos 403, and the UI
# kept offering them.
#
# A list host that does not answer is not a broken URL. The step used to run
# under set -e, so one curl timeout (exit 28) ended it on the first slow host
# without checking the rest, and a red job stopped unrelated merges. Now each
# URL gets ATTEMPTS tries; one that never answers is a warning, a status other
# than 200 is a failure, and so is a run where no URL answered at all.
#
# Usage: scripts/check-list-urls.sh [url...]   (no arguments: read the sources)
# Environment: MAX_TIME (seconds per try, 25), ATTEMPTS (3), RETRY_DELAY (5).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

MAX_TIME="${MAX_TIME:-25}"
ATTEMPTS="${ATTEMPTS:-3}"
RETRY_DELAY="${RETRY_DELAY:-5}"

if [ "$#" -gt 0 ]; then
    urls=$(printf '%s\n' "$@")
else
    urls=$( { grep -oE "url: 'https://[^']+'" ui/src/components/blacklists/popularLists.ts | sed -E "s/^url: '//; s/'$//"
              grep -oE '"https://[^"]+"' backend-go/internal/workers/blacklist_refresh.go | tr -d '"'; } | sort -u)
fi
[ -n "$urls" ] || { echo "no list URLs found in the sources"; exit 1; }

# warn: a GitHub annotation in Actions, plain text elsewhere.
warn() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning::$1"; else echo "WARN $1"; fi; }

ok=0 failed=0 unreachable=0
for url in $urls; do
    code=000
    for try in $(seq 1 "$ATTEMPTS"); do
        # curl prints 000 when it gets no response; its exit status is not
        # needed and must not end the script.
        code=$(curl -sL -o /dev/null -w '%{http_code}' --max-time "$MAX_TIME" \
            -H 'User-Agent: SecureProxyManager/CI' "$url" 2>/dev/null) || true
        # Retry only what can pass on a second try: no response, 429, 5xx.
        case "$code" in 000|429|5??) ;; *) break ;; esac
        [ "$try" -lt "$ATTEMPTS" ] && sleep "$RETRY_DELAY"
    done
    case "$code" in
        200) echo "OK   [200] $url"; ok=$((ok+1)) ;;
        000) warn "no response from $url after $ATTEMPTS tries of ${MAX_TIME}s"; unreachable=$((unreachable+1)) ;;
        *)   echo "FAIL [$code] $url"; failed=$((failed+1)) ;;
    esac
done

echo "$ok ok, $failed failed, $unreachable unreachable"
[ $((ok + failed)) -gt 0 ] || { echo "no URL answered: the runner has no network, nothing was checked"; exit 1; }
[ "$failed" -eq 0 ]
