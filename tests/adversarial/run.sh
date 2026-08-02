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
      report/bench-report.md report/bench-baseline.json report/bench-proxied.json \
      report/resilience-report.md report/config-matrix-report.md

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

# Plane 4 — resilience. Kills/restarts waf and dns and asserts the two properties
# that matter under failure: (1) losing the WAF FAILS CLOSED (a benign request
# is denied, not served uninspected — no fail-open hole), and (2) the stack
# self-heals (blocking resumes after the WAF returns; traffic flows after dns is
# recycled). Sets the global P4_RC. Runs LAST (it disrupts the data plane).
P4_RC=0
resilience() {
  local RESREC=() name detail v s sb sm
  add() { RESREC+=("$1|$2|$3"); }

  # Probe through the proxy from a throwaway attacker container on adv-edge.
  # --no-deps: don't wait on service health (the proxy goes unhealthy while the
  # WAF is down, but squid still answers — with an ICAP error, which is the point).
  probe() {
    # curl -w always prints a code (000 on no response); </dev/null so the
    # container never consumes the caller's stdin. Compose progress is on stderr.
    "${DC[@]}" run --rm --no-deps -T --entrypoint curl attacker \
      -s -o /dev/null -w '%{http_code}' --max-time 12 --path-as-is \
      -x http://proxy:3128 "http://upstream.test$1" </dev/null 2>/dev/null
  }
  wait_healthy() {
    local svc=$1 tries=${2:-30} h
    for _ in $(seq 1 "$tries"); do
      h=$("$DOCKER" inspect -f '{{.State.Health.Status}}' "spm-adversarial-${svc}-1" 2>/dev/null || echo none)
      [ "$h" = "healthy" ] && return 0
      sleep 2
    done
    return 1
  }

  # R1 — baseline: benign is served while everything is healthy.
  s=$(probe /index.html)
  if [ "$s" = "200" ]; then v=PASS; else v=FAIL; P4_RC=1; fi
  add "baseline" "benign→$s (want 200)" "$v"

  # R2 — WAF fail-closed: with the WAF down, REQMOD (bypass=0) must NOT let a
  # request through uninspected. A 200 here would be a fail-OPEN security hole.
  "${DC[@]}" stop waf >/dev/null 2>&1
  sleep 3
  s=$(probe /index.html)
  if [ "$s" != "200" ]; then v=PASS; else v=FAIL; P4_RC=1; fi
  add "waf-fail-closed" "waf down: benign→$s (want NOT 200)" "$v"

  # R3 — WAF self-heal: after the WAF returns, benign flows again AND malicious
  # is still blocked (ruleset/ISTag intact). Retry: squid reconnects ICAP lazily.
  "${DC[@]}" start waf >/dev/null 2>&1
  if wait_healthy waf; then
    sb=000; for _ in 1 2 3 4 5 6; do sb=$(probe /index.html); [ "$sb" = "200" ] && break; sleep 2; done
    sm=$(probe "/p?id=1%20UNION%20SELECT%20a%20FROM%20b")
    if [ "$sb" = "200" ] && [ "$sm" = "403" ]; then v=PASS; else v=FAIL; P4_RC=1; fi
    add "waf-self-heal" "recovered: benign→$sb (want 200), malicious→$sm (want 403)" "$v"
  else
    add "waf-self-heal" "waf did not become healthy after restart" "FAIL"; P4_RC=1
  fi

  # R4 — DNS self-heal: recycle dns and confirm resolution/traffic recovers.
  "${DC[@]}" restart dns >/dev/null 2>&1
  if wait_healthy dns; then
    sleep 2
    sb=000; for _ in 1 2 3 4 5; do sb=$(probe /index.html); [ "$sb" = "200" ] && break; sleep 2; done
    if [ "$sb" = "200" ]; then v=PASS; else v=FAIL; P4_RC=1; fi
    add "dns-self-heal" "dns recycled: benign→$sb (want 200)" "$v"
  else
    add "dns-self-heal" "dns did not become healthy after restart" "FAIL"; P4_RC=1
  fi

  {
    echo "# Resilience report"
    echo
    echo "> Fail-closed on WAF loss + self-heal under failure (#200 Phase 4)."
    echo
    echo "| Check | Detail | Verdict |"
    echo "|---|---|---|"
    for r in "${RESREC[@]}"; do
      name=${r%%|*}; detail=${r#*|}; v=${detail##*|}; detail=${detail%|*}
      printf '| %s | %s | %s |\n' "$name" "$detail" "$v"
    done
    echo
    if [ "$P4_RC" -eq 0 ]; then echo "_Gate: **PASS** — fail-closed held and the stack self-healed._"
    else echo "_Gate: **FAIL** — see the checks above._"; fi
  } >report/resilience-report.md
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
# --user 0: k6's image drops root, but the ./report bind mount is owned by the
# host/CI user, so a non-root k6 can't write the --summary-export file there
# (works on Docker Desktop only because it remaps ownership). Run as uid 0.
"${DC[@]}" run --rm --user 0 -e TARGET=http://mock-upstream/bench \
  k6 run --quiet --summary-export=/report/bench-baseline.json /bench/bench.js >/dev/null 2>&1 || true
"${DC[@]}" run --rm --user 0 -e TARGET=http://upstream.test/bench -e HTTP_PROXY=http://proxy:3128 \
  k6 run --quiet --summary-export=/report/bench-proxied.json /bench/bench.js; p3=$?
bench_report

# Plane 5 — config-matrix: settings actually change live proxy/WAF behaviour
# (WAF category toggles through the real backend→WAF push path). Runs before the
# disruptive resilience plane, at the healthy default config.
echo "── plane 5: config-matrix (settings flip the data plane) ──"
"${DC[@]}" run --rm --entrypoint /adversarial/config-matrix.sh attacker; p5=$?

# Plane 4 — resilience (fail-closed + self-heal). Runs last: it disrupts the
# data plane by stopping/starting waf and dns.
echo "── plane 4: resilience (fail-closed + self-heal) ──"
resilience; p4=$P4_RC

[ "$p1" -ne 0 ] && rc=1
[ "$p2" -ne 0 ] && rc=1
[ "$p3" -ne 0 ] && rc=1
[ "$p4" -ne 0 ] && rc=1
[ "$p5" -ne 0 ] && rc=1

echo
for f in report/report.md report/api-report.md report/bench-report.md report/config-matrix-report.md report/resilience-report.md; do
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
printf '  plane 5 (config-matrix): %s\n' "$([ "${p5:-1}" -eq 0 ] && echo PASS || echo FAIL)"
printf '  plane 4 (resilience): %s\n' "$([ "${p4:-1}" -eq 0 ] && echo PASS || echo FAIL)"
if [ "$rc" -eq 0 ]; then
  echo "✅ adversarial gate: PASS"
else
  echo "❌ adversarial gate: FAIL"
fi
exit "$rc"
