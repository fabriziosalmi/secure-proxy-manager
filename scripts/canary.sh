#!/usr/bin/env bash
# Nightly canary for the standing test environment (the ci-<repo> LXC).
#
# It answers three questions that nothing else asked, and that went unanswered
# for eighteen commits:
#
#   1. Is the environment still on main? It had drifted three weeks behind
#      without anyone noticing, so the one place to test before a release did
#      not contain the fix that was about to be released.
#   2. Does main still come up? A green pull request proves the images build,
#      not that the stack reaches a healthy state on a machine with state on it.
#   3. Does the data plane still refuse an attack and pass benign traffic?
#      That is the property the product exists for, and it is not implied by a
#      container reporting healthy.
#
# NOT tests/ci-e2e.sh: that script tears the stack down with `docker compose
# down -v`, which destroys the volumes of a standing environment. This one is
# non-destructive by construction — it rebuilds and restarts, and never removes
# a volume.
#
# Run it from the deployment directory inside the container:
#   bash scripts/canary.sh
#
# Exit status is 0 when every check passed. The verdict is also written to
# CANARY_STATE (default /var/lib/spm-canary.json) so a reader that is not
# watching the output can still see the last result and its age — a log nobody
# reads is how the backup job failed ninety-seven times unnoticed.
set -uo pipefail

CANARY_STATE="${CANARY_STATE:-/var/lib/spm-canary.json}"
HEALTH_URL="${HEALTH_URL:-https://localhost:8443/api/health}"
PROXY="${PROXY:-http://localhost:3128}"
PROBE_HOST="${PROBE_HOST:-http://example.com}"
COMPOSE="${COMPOSE:-docker compose}"

PASS=0; FAIL=0; NOTES=""
ok()  { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; NOTES="${NOTES}${NOTES:+; }$1"; }

finish() {
  local verdict="pass"
  [ "$FAIL" -eq 0 ] || verdict="fail"
  printf '{"verdict":"%s","passed":%d,"failed":%d,"commit":"%s","version":"%s","at":"%s","notes":"%s"}\n' \
    "$verdict" "$PASS" "$FAIL" "${HEAD_SHA:-unknown}" "${VERSION:-unknown}" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NOTES" > "$CANARY_STATE" 2>/dev/null ||
    printf 'canary: cannot write %s\n' "$CANARY_STATE" >&2
  printf '── canary %s: %d passed, %d failed\n' "$verdict" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ]
}

echo "── aligning to origin/main ──"
git fetch -q origin main || { bad "git fetch failed"; finish; exit 1; }
BEFORE=$(git rev-parse --short HEAD)
TARGET=$(git rev-parse --short origin/main)
if [ "$BEFORE" != "$TARGET" ]; then
  echo "  $BEFORE -> $TARGET"
  # reset --hard leaves untracked files alone, so .env and the runtime ACLs
  # exported under config/ survive.
  git reset --hard -q origin/main || { bad "git reset failed"; finish; exit 1; }
else
  echo "  already at $TARGET"
fi
HEAD_SHA=$(git rev-parse --short HEAD)

echo "── rebuild and restart ──"
if ! $COMPOSE build >/tmp/canary-build.log 2>&1; then
  bad "compose build failed (see /tmp/canary-build.log)"; finish; exit 1
fi
if ! $COMPOSE up -d --remove-orphans >>/tmp/canary-build.log 2>&1; then
  bad "compose up failed (see /tmp/canary-build.log)"; finish; exit 1
fi

echo "── health ──"
VERSION=""
for _ in $(seq 1 40); do
  body=$(curl -sk --max-time 5 "$HEALTH_URL" 2>/dev/null) || body=""
  case "$body" in *'"status"'*) VERSION=$(printf '%s' "$body" | sed -nE 's/.*"version":"([^"]*)".*/\1/p'); break ;; esac
  sleep 3
done
if [ -n "$VERSION" ]; then ok "backend healthy (v$VERSION)"; else bad "backend never reported healthy"; fi

down=$($COMPOSE ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk '$2!="running"{print $1}' | tr '\n' ' ')
if [ -z "$down" ]; then ok "all services running"; else bad "services not running: $down"; fi

echo "── data plane ──"
# A payload the WAF must refuse, in a BODY: the shape that passed until 3.13.1.
code=$(curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" --max-time 20 \
  -X POST "$PROBE_HOST/login" -d "user=admin'--&pass=x" 2>/dev/null) || code=000
if [ "$code" = "403" ]; then ok "WAF blocks a comment terminator in a body (403)"
else bad "WAF did NOT block the body payload (got $code)"; fi

# The control: a quote opening a literal that starts with dashes must pass.
# Anything but 403 means it traversed; the origin's own status does not matter.
code=$(curl -s -o /dev/null -w '%{http_code}' -x "$PROXY" --max-time 20 \
  -X POST "$PROBE_HOST/api" -H 'Content-Type: application/json' \
  -d '{"args":["--json","--verbose"]}' 2>/dev/null) || code=000
if [ "$code" = "403" ]; then bad "false positive: benign CLI-flag JSON was blocked"
elif [ "$code" = "000" ]; then bad "benign probe did not complete (no response)"
else ok "benign CLI-flag JSON traverses ($code from the origin)"; fi

finish
