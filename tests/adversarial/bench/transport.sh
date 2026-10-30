#!/usr/bin/env bash
# Transport baseline. Runs bench/transport.js through the
# adversarial stack in seven scenarios and writes report/transport.md:
#
#   S1 GET straight to the upstream (no proxy)
#   S2 GET through the proxy, ICAP off        S3 the same, ICAP on
#   S4 POST 64 KiB, ICAP off                  S5 the same, ICAP on
#   S6 POST 1,000,000 B, ICAP off             S7 the same, ICAP on
#
# ICAP is switched off with "icap_enable off" in custom_squid_extra.conf,
# which generate_squid_conf.sh appends last, and every scenario checks the
# WAF's REQMOD counter: it must not move with ICAP off and must move with
# ICAP on, or the run stops. WAF CPU is sampled with docker stats.
#
# Usage: tests/adversarial/bench/transport.sh   (VUS, DURATION from env)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
DC=(docker compose -f docker-compose.adversarial.yml)
VUS="${VUS:-10}" DURATION="${DURATION:-30s}"
TOKEN=adv-alert-token-not-a-real-secret   # the adversarial stack's test value
mkdir -p report

reqmods() {
  "${DC[@]}" exec -T waf wget -qO- --header "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/metrics 2>/dev/null |
    awk '$1=="waf_reqmod_duration_seconds_count"{print $2}'
}

set_icap() { # on|off
  if [ "$1" = off ]; then
    "${DC[@]}" exec -T proxy sh -c 'echo "icap_enable off" > /config/custom_squid_extra.conf'
  else
    "${DC[@]}" exec -T proxy sh -c 'rm -f /config/custom_squid_extra.conf'
  fi
  "${DC[@]}" restart proxy >/dev/null
  for _ in $(seq 1 30); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$("${DC[@]}" ps -q proxy)")" = healthy ] && return 0
    sleep 2
  done
  echo "proxy did not come back healthy after icap $1" >&2
  exit 1
}

run() { # id, icap(on|off|direct), method, body_bytes
  local id=$1 icap=$2 method=$3 bytes=$4 path=/bench proxy=(-e HTTP_PROXY=http://proxy:3128)
  # Uploads go to /bench-post, which reads the body before it answers (see
  # mock-upstream/nginx.conf).
  [ "$method" = POST ] && path=/bench-post
  local target=http://upstream.test$path
  if [ "$icap" = direct ]; then target=http://mock-upstream$path; proxy=(); fi
  local before after waf_ctr
  before=$(reqmods)
  waf_ctr=$("${DC[@]}" ps -q waf)
  : > "report/transport-$id.cpu"
  ( while :; do docker stats --no-stream --format '{{.CPUPerc}}' "$waf_ctr" >> "report/transport-$id.cpu" 2>/dev/null; sleep 1; done ) &
  local sampler=$!
  "${DC[@]}" run --rm -T --user 0 -e TARGET="$target" "${proxy[@]}" -e METHOD="$method" -e BODY_BYTES="$bytes" \
    -e VUS="$VUS" -e DURATION="$DURATION" -e SUMMARY_PATH="/report/transport-$id.json" \
    k6 run --quiet /bench/transport.js > "report/transport-$id.k6.log" 2>&1
  kill "$sampler" 2>/dev/null; wait "$sampler" 2>/dev/null
  after=$(reqmods)
  local moved=$(( after - before ))
  case "$icap" in
    off|direct) [ "$moved" -eq 0 ] || { echo "$id: ICAP is meant to be out of the path, but the WAF saw $moved REQMODs" >&2; exit 1; } ;;
    on) [ "$moved" -gt 0 ] || { echo "$id: ICAP is meant to be on, but the WAF saw no REQMOD" >&2; exit 1; } ;;
  esac
  echo "$id icap=$icap method=$method body=$bytes reqmods=$moved"
}

"${DC[@]}" up -d --build --wait waf dns proxy mock-upstream backend >/dev/null || { echo "stack did not start" >&2; exit 1; }

set_icap off
run S1 direct GET 0
run S2 off GET 0
run S4 off POST 65536
run S6 off POST 1000000
set_icap on
run S3 on GET 0
run S5 on POST 65536
run S7 on POST 1000000

{
  echo "# Transport baseline ($VUS VUs, $DURATION per scenario)"
  echo
  echo "| Scenario | Requests | Failed | req/s | p50 ms | p90 ms | p99 ms | max ms | WAF CPU mean % | Statuses |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
  for id in S1 S2 S3 S4 S5 S6 S7; do
    f="report/transport-$id.json"
    cpu=$(awk '{gsub("%","");s+=$1;n++} END{if(n) printf "%.1f", s/n; else print "-"}' "report/transport-$id.cpu")
    jq -r --arg id "$id" --arg cpu "$cpu" '.metrics as $m |
      "| \($id) | \($m.http_reqs.count) | \(($m.http_req_failed.rate*100)|tostring|.[0:5])% | \($m.http_reqs.rate|floor) | \($m.http_req_duration.med*100|round/100) | \($m.http_req_duration["p(90)"]*100|round/100) | \($m.http_req_duration["p(99)"]*100|round/100) | \($m.http_req_duration.max*100|round/100) | \($cpu) | \([$m|to_entries[]|select(.key|startswith("status_"))|"\(.key|ltrimstr("status_")):\(.value.count)"]|join(" ")) |"' "$f"
  done
} > report/transport.md
cat report/transport.md
