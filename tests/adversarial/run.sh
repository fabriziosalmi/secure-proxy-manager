#!/usr/bin/env bash
#
# Adversarial e2e sandbox orchestrator (issue #200, Phase 1).
#
# Brings up the isolated proxy + WAF + dns + mock-upstream + attacker stack,
# drives the block-matrix corpus through the proxy, prints the FP/FN report, and
# tears everything down. Exit code is the CI gate (non-zero on hard FN/FP).
#
#   tests/adversarial/run.sh            # build, run, report, teardown
#   KEEP_UP=1 tests/adversarial/run.sh  # leave the stack running for debugging
#   NO_BUILD=1 tests/adversarial/run.sh # skip image rebuild (faster re-runs)
set -uo pipefail

cd "$(dirname "$0")"

# Resolve a docker binary (Docker Desktop on macOS is not always on PATH).
DOCKER="docker"
if ! command -v docker >/dev/null 2>&1; then
  for p in /usr/local/bin/docker /opt/homebrew/bin/docker \
           /Applications/Docker.app/Contents/Resources/bin/docker; do
    [ -x "$p" ] && DOCKER="$p" && break
  done
fi
# Put the resolved docker's directory on PATH so its credential helpers
# (docker-credential-desktop, …) resolve during build/pull, even when this shell
# was started without Docker Desktop on PATH.
case "$DOCKER" in
  */*) PATH="$(cd "$(dirname "$DOCKER")" && pwd):$PATH"; export PATH ;;
esac
if ! "$DOCKER" info >/dev/null 2>&1; then
  echo "error: docker daemon not reachable (is Docker running?)" >&2
  exit 2
fi

DC=("$DOCKER" compose -f docker-compose.adversarial.yml)

mkdir -p report
rm -f report/report.md report/report.json report/results.json

cleanup() {
  if [ "${KEEP_UP:-0}" = "1" ]; then
    echo "── KEEP_UP=1: leaving stack running. Tear down with:"
    echo "     ${DC[*]} down -v --remove-orphans"
    return
  fi
  echo "── teardown ──"
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

BUILD_FLAG="--build"
[ "${NO_BUILD:-0}" = "1" ] && BUILD_FLAG=""

echo "── bringing up adversarial sandbox (proxy + waf + dns + mock-upstream + backend) ──"
# Start the data-plane detached and wait for health, THEN run the attacker planes
# as one-shots. (Not `up --abort-on-container-exit`: that stops the whole stack the
# moment the attacker exits, which fights KEEP_UP and any post-run inspection.)
"${DC[@]}" up -d $BUILD_FLAG --wait waf dns proxy mock-upstream backend
up_rc=$?
rc=0
if [ "$up_rc" -ne 0 ]; then
  echo "error: sandbox failed to become healthy" >&2
  "${DC[@]}" ps
  exit "$up_rc"
fi

# Plane 1 — data-plane block-matrix (traffic through proxy + WAF/ICAP).
echo "── plane 1: block-matrix (proxy + WAF/ICAP) ──"
"${DC[@]}" run --rm attacker;               p1=$?

# Plane 2 — API attacker (direct to the backend auth boundary).
echo "── plane 2: API attacker (backend auth boundary) ──"
"${DC[@]}" run --rm --entrypoint /adversarial/api-attack.sh attacker; p2=$?

[ "$p1" -ne 0 ] && rc=1
[ "$p2" -ne 0 ] && rc=1

echo
for f in report/report.md report/api-report.md; do
  if [ -f "$f" ]; then
    echo "════════════════════════════════════════════════════════════════════════"
    cat "$f"
    echo "════════════════════════════════════════════════════════════════════════"
  fi
done

echo
printf '  plane 1 (block-matrix): %s\n' "$([ "$p1" -eq 0 ] && echo PASS || echo FAIL)"
printf '  plane 2 (API attacker): %s\n' "$([ "$p2" -eq 0 ] && echo PASS || echo FAIL)"
if [ "$rc" -eq 0 ]; then
  echo "✅ adversarial gate: PASS"
else
  echo "❌ adversarial gate: FAIL"
fi
exit "$rc"
