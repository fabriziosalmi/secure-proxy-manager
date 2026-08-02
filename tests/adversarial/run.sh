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
rm -f report/report.md report/report.json report/results.json \
      report/api-report.md report/api-report.json report/api-results.json \
      report/bench-report.md report/bench-baseline.json report/bench-proxied.json

# Build the plane-3 bench report from k6's summary exports (baseline vs proxied),
# reporting p50/p95/throughput and the proxy + ICAP overhead.
bench_report() {
  local bl=report/bench-baseline.json pr=report/bench-proxied.json
  command -v jq >/dev/null 2>&1 || { echo "warning: jq not found; skipping bench report"; return; }
  [ -f "$pr" ] || { echo "warning: no proxied bench summary produced"; return; }
  # k6 --summary-export is FLAT: .metrics.<name>.<stat> (no ".values").
  local dur='.metrics.http_req_duration'
  local p_p50 p_p95 p_p99 p_rps p_err b_p50 b_p95 b_rps
  p_p50=$(jq -r "${dur}.med // 0"       "$pr"); p_p95=$(jq -r "${dur}[\"p(95)\"] // 0" "$pr")
  p_p99=$(jq -r "${dur}[\"p(99)\"] // 0" "$pr"); p_rps=$(jq -r '.metrics.http_reqs.rate // 0' "$pr")
  p_err=$(jq -r '.metrics.http_req_failed.value // 0' "$pr")
  if [ -f "$bl" ]; then
    b_p50=$(jq -r "${dur}.med // 0" "$bl"); b_p95=$(jq -r "${dur}[\"p(95)\"] // 0" "$bl")
    b_rps=$(jq -r '.metrics.http_reqs.rate // 0' "$bl")
  else b_p50=0; b_p95=0; b_rps=0; fi
  local ov50 ov95
  ov50=$(awk -v a="$p_p50" -v b="$b_p50" 'BEGIN{printf "%.2f", a-b}')
  ov95=$(awk -v a="$p_p95" -v b="$b_p95" 'BEGIN{printf "%.2f", a-b}')
  {
    echo "# Bench / latency report"
    echo
    echo "> Load through the real proxy + WAF/ICAP vs a direct baseline (#200 Phase 3)."
    echo "> Unique per-request URL (cache-buster) → measures real inspection, not cache hits."
    echo
    echo "| Metric (ms unless noted) | Baseline (direct) | Proxied (proxy+WAF) | Overhead |"
    echo "|---|--:|--:|--:|"
    printf '| p50 latency | %.2f | %.2f | %s |\n' "$b_p50" "$p_p50" "$ov50"
    printf '| p95 latency | %.2f | %.2f | %s |\n' "$b_p95" "$p_p95" "$ov95"
    printf '| p99 latency | – | %.2f | – |\n' "$p_p99"
    printf '| throughput (req/s) | %.1f | %.1f | – |\n' "$b_rps" "$p_rps"
    printf '| error rate | – | %.4f | – |\n' "$p_err"
    echo
    echo "_Gate (proxied run): p95 < ${P95_MS:-800} ms and error rate < ${MAX_FAIL:-0.05} (k6 thresholds)._"
  } >report/bench-report.md
}

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

# Plane 3 — bench/latency (k6). Baseline (direct) is informational; the proxied
# run through proxy + WAF carries the thresholds and is the gate.
echo "── plane 3: bench/latency (k6 through proxy + WAF) ──"
"${DC[@]}" run --rm -e TARGET=http://mock-upstream/bench \
  k6 run --quiet --summary-export=/report/bench-baseline.json /bench/bench.js >/dev/null 2>&1 || true
"${DC[@]}" run --rm -e TARGET=http://upstream.test/bench -e HTTP_PROXY=http://proxy:3128 \
  k6 run --quiet --summary-export=/report/bench-proxied.json /bench/bench.js; p3=$?
bench_report

[ "$p1" -ne 0 ] && rc=1
[ "$p2" -ne 0 ] && rc=1
[ "$p3" -ne 0 ] && rc=1

echo
for f in report/report.md report/api-report.md report/bench-report.md; do
  if [ -f "$f" ]; then
    echo "════════════════════════════════════════════════════════════════════════"
    cat "$f"
    echo "════════════════════════════════════════════════════════════════════════"
  fi
done

echo
printf '  plane 1 (block-matrix): %s\n' "$([ "$p1" -eq 0 ] && echo PASS || echo FAIL)"
printf '  plane 2 (API attacker): %s\n' "$([ "$p2" -eq 0 ] && echo PASS || echo FAIL)"
printf '  plane 3 (bench/latency): %s\n' "$([ "${p3:-1}" -eq 0 ] && echo PASS || echo FAIL)"
if [ "$rc" -eq 0 ]; then
  echo "✅ adversarial gate: PASS"
else
  echo "❌ adversarial gate: FAIL"
fi
exit "$rc"
