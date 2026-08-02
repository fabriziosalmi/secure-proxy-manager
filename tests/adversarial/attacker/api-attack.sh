#!/usr/bin/env bash
#
# Adversarial API attacker (issue #200, Phase 2).
#
# Probes the backend's OWN auth/authorization boundary by hitting it DIRECTLY
# (not through the proxy): auth-bypass on protected endpoints, forged/tampered
# JWTs (alg=none confusion, mutated signature), SQL-injection in login, and
# rate-limit enforcement. Control cases prove legitimate access still works.
#
# Verdict per case:
#   expect=unauthorized  → PASS iff 401/403; a 2xx is a BYPASS (FAIL)
#   expect=ok            → PASS iff 2xx     (control; a non-2xx = broken)
#   expect=ratelimited   → PASS iff a rapid burst yields >=1 HTTP 429
#
# Exit code = CI gate: non-zero if any hard-gate case fails.
set -uo pipefail

API="${API:-http://backend:5000}"
API_CORPUS="${API_CORPUS:-/adversarial/api-corpus.json}"
API_USER="${API_USER:-testadmin}"
API_PASS="${API_PASS:-TestP@ss123!}"
REPORT_DIR="${REPORT_DIR:-/report}"

mkdir -p "$REPORT_DIR"
RESULTS="$(mktemp)"

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }

b64url() { base64 -w0 2>/dev/null | tr '+/' '-_' | tr -d '='; }

echo "── SPM adversarial API attacker ─────────────────────────────────────────"
echo "   api=$API  corpus=$API_CORPUS"
echo

# ── Obtain a real JWT for the bearer_valid / bearer_tampered cases ────────────
login_resp=$(curl -sS --max-time 15 -X POST -H 'Content-Type: application/json' \
  --data "{\"username\":\"$API_USER\",\"password\":\"$API_PASS\"}" \
  "$API/api/auth/login" 2>/dev/null || true)
TOKEN=$(printf '%s' "$login_resp" | jq -r '.access_token // empty' 2>/dev/null)
[ -n "$TOKEN" ] && echo "   (obtained a session token for control/tamper cases)" \
                || echo "   (WARNING: login did not return a token — control cases will surface it)"

# alg=none forgery claiming admin (unsigned).
ALG_NONE_H=$(printf '%s' '{"alg":"none","typ":"JWT"}' | b64url)
ALG_NONE_P=$(printf '%s' '{"sub":"admin","username":"admin","role":"admin","exp":9999999999}' | b64url)
ALG_NONE_TOKEN="${ALG_NONE_H}.${ALG_NONE_P}."

# Valid token with a mutated signature (guaranteed-invalid).
TAMPERED_TOKEN=""
if [ -n "$TOKEN" ]; then
  sig="${TOKEN##*.}"; rest="${TOKEN%.*}"; last="${sig: -1}"
  if [ "$last" = "A" ]; then repl="B"; else repl="A"; fi
  TAMPERED_TOKEN="${rest}.${sig%?}${repl}"
fi

n=$(jq 'length' "$API_CORPUS")
i=0
while [ "$i" -lt "$n" ]; do
  row=$(jq -c ".[$i]" "$API_CORPUS")
  i=$((i + 1))

  IFS=$'\t' read -r id method path auth expect gate ctype <<EOF
$(jq -r '[.id,.method,.path,.auth,.expect,.gate,(.content_type//"")] | @tsv' <<<"$row")
EOF
  body=$(jq -r '.body // empty' <<<"$row")

  if [ "$expect" = "ratelimited" ]; then
    burst=$(jq -r '.burst // 90' <<<"$row")
    # Fire the burst with real concurrency so the arrival rate exceeds the
    # limiter's sustained rate (20/s) + burst (60), reliably tripping 429.
    got429=$(seq 1 "$burst" | xargs -P 20 -I{} \
      curl -sS -o /dev/null -w '%{http_code}\n' --max-time 10 "$API$path" 2>/dev/null \
      | grep -c '^429$' || true)
    [ "${got429:-0}" -ge 1 ] && verdict="PASS" || verdict="FAIL"
    status="burst:${burst},429x${got429:-0}"
  else
    set -- -sS --max-time 15 -o /dev/null -w '%{http_code}' -X "$method"
    case "$auth" in
      basic)          set -- "$@" -u "$API_USER:$API_PASS" ;;
      bearer_valid)   set -- "$@" -H "Authorization: Bearer $TOKEN" ;;
      bearer_bad)     set -- "$@" -H "Authorization: Bearer garbage.garbage.garbage" ;;
      bearer_alg_none)set -- "$@" -H "Authorization: Bearer $ALG_NONE_TOKEN" ;;
      bearer_tampered)set -- "$@" -H "Authorization: Bearer $TAMPERED_TOKEN" ;;
      none)           : ;;
    esac
    if [ -n "$body" ]; then
      [ -n "$ctype" ] && set -- "$@" -H "Content-Type: $ctype"
      set -- "$@" --data "$body"
    fi
    set -- "$@" "$API$path"
    status=$(curl "$@" 2>/dev/null || echo "000")

    case "$expect" in
      ok)           { [ "$status" -ge 200 ] 2>/dev/null && [ "$status" -lt 300 ]; } && verdict="PASS" || verdict="FAIL" ;;
      unauthorized) { [ "$status" = "401" ] || [ "$status" = "403" ]; } && verdict="PASS" || verdict="FAIL" ;;
      *)            verdict="FAIL" ;;
    esac
  fi

  jq -nc --arg id "$id" --arg method "$method" --arg path "$path" --arg auth "$auth" \
        --arg expect "$expect" --arg gate "$gate" --arg status "$status" --arg verdict "$verdict" \
        '{id:$id,method:$method,path:$path,auth:$auth,expect:$expect,gate:$gate,status:$status,verdict:$verdict}' \
        >>"$RESULTS"

  [ "$verdict" = "PASS" ] && tag=$(green PASS) || tag=$(red FAIL)
  printf '  %-22s %-6s %-26s auth=%-15s expect=%-13s got=%-16s %b\n' \
    "$id" "$method" "$path" "$auth" "$expect" "$status" "$tag"
done

# ── Aggregate ────────────────────────────────────────────────────────────────
jq -s '.' "$RESULTS" >"$REPORT_DIR/api-results.json"

summary=$(jq '{
  total: length,
  pass:  [.[]|select(.verdict=="PASS")]|length,
  fail:  [.[]|select(.verdict=="FAIL")]|length,
  hard_fail: [.[]|select(.verdict=="FAIL" and .gate=="hard")]|length,
  bypasses: [.[]|select(.verdict=="FAIL" and .expect=="unauthorized")]|length
}' "$REPORT_DIR/api-results.json")

hard_fail=$(jq -r '.hard_fail' <<<"$summary")
pass=$(jq -r '.pass' <<<"$summary"); fail=$(jq -r '.fail' <<<"$summary")
total=$(jq -r '.total' <<<"$summary"); bypasses=$(jq -r '.bypasses' <<<"$summary")

gate_pass=true
[ "$hard_fail" -gt 0 ] && gate_pass=false

{
  echo "# Adversarial API-attacker report"
  echo
  echo "> SPM backend auth/authorization regression — attacker hits the API"
  echo "> directly (issue #200, Phase 2)."
  echo
  echo "## Summary"
  echo
  echo "| Metric | Value |"
  echo "|---|---|"
  echo "| Cases | $total |"
  echo "| Pass | $pass |"
  echo "| **Fail** | $fail (hard: $hard_fail) |"
  echo "| **Auth bypasses (unauthenticated 2xx)** | $bypasses |"
  if $gate_pass; then echo "| **Gate** | ✅ PASS |"; else echo "| **Gate** | ❌ FAIL |"; fi
  echo
  echo "## Cases"
  echo
  echo "| Case | Method | Path | Auth | Expect | Status | Verdict |"
  echo "|---|---|---|---|---|---|---|"
  jq -r '.[] | "| \(.id) | \(.method) | \(.path) | \(.auth) | \(.expect) | \(.status) | \(.verdict) |"' \
    "$REPORT_DIR/api-results.json"
  echo
  if [ "$fail" -gt 0 ]; then
    echo "## Failures"
    echo
    jq -r '.[] | select(.verdict=="FAIL") |
      "- **FAIL** `\(.id)` (\(.expect), gate=\(.gate)) — \(.method) \(.path) auth=\(.auth) → \(.status)"' \
      "$REPORT_DIR/api-results.json"
    echo
  fi
} >"$REPORT_DIR/api-report.md"

jq -n --argjson summary "$summary" --argjson gate_pass "$($gate_pass && echo true || echo false)" \
  --slurpfile results "$REPORT_DIR/api-results.json" \
  '{gate_pass:$gate_pass, summary:$summary, results:$results[0]}' \
  >"$REPORT_DIR/api-report.json"

echo
echo "── Summary ──────────────────────────────────────────────────────────────"
printf '  cases=%s  pass=%s  fail=%s(hard %s)  bypasses=%s\n' \
  "$total" "$pass" "$fail" "$hard_fail" "$bypasses"
if $gate_pass; then
  echo "  gate: $(green PASS)"; echo "  report: $REPORT_DIR/api-report.md"; exit 0
else
  echo "  gate: $(red FAIL) — auth/authorization regressions present"
  echo "  report: $REPORT_DIR/api-report.md"; exit 1
fi
