#!/usr/bin/env bash
#
# Adversarial config-matrix (issue #200, harness Phase 5).
#
# Proves that changing a SETTING actually changes live proxy/WAF behaviour — not
# just that the API accepts the change. It flips WAF rule-category toggles through
# the REAL backend→WAF push path (POST /api/waf/categories/toggle → waf:8080)
# and asserts the data plane flips:
#   - disable a category  → that category's attack now PASSES through the proxy
#   - a different category → still BLOCKS (the toggle is selective, not global)
#   - re-enable            → the attack BLOCKS again
#
# Every probe uses a unique cache-buster query so neither Squid's cache nor the
# WAF safe-cache can serve a stale verdict — the toggle's effect is observed
# immediately (a category toggle also bumps the WAF ISTag, dropping Squid's
# cached verdicts).
#
# Exit code = CI gate: non-zero if any expected flip did not happen.
set -uo pipefail

API="${API:-http://backend:5000}"
PROXY="${PROXY:-http://proxy:3128}"
BASE="${BASE:-http://upstream.test}"
API_USER="${API_USER:-testadmin}"
API_PASS="${API_PASS:-TestP@ss123!}"
REPORT_DIR="${REPORT_DIR:-/report}"
mkdir -p "$REPORT_DIR"

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }

SQLI="/p?id=1%20UNION%20SELECT%20a%20FROM%20b"
XSS="/p?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

cb=0
# probe sends an attack payload through the proxy with a fresh cache-buster and
# returns the HTTP status (403 = blocked). Retries briefly to absorb toggle
# propagation timing.
probe() {
  local path=$1 want=$2 s
  for _ in 1 2 3 4 5; do
    cb=$((cb + 1))
    s=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 --path-as-is \
      -x "$PROXY" "${BASE}${path}&cb=${cb}" </dev/null 2>/dev/null)
    [ "$s" = "$want" ] && break
    sleep 1
  done
  echo "$s"
}

# toggleCat flips a WAF category through the backend mgmt API. Returns the HTTP
# status of the backend call.
toggleCat() {
  local cat=$1 enabled=$2
  curl -sS -o /dev/null -w '%{http_code}' --max-time 12 -u "$API_USER:$API_PASS" \
    -X POST -H 'Content-Type: application/json' \
    --data "{\"category\":\"${cat}\",\"enabled\":${enabled}}" \
    "$API/api/waf/categories/toggle" </dev/null 2>/dev/null
}

REC=()
rc=0
add() { # name | detail | want-substring-of-verdict PASS/FAIL
  REC+=("$1|$2|$3")
  [ "$3" = "FAIL" ] && rc=1
}
check() { # name | got | wantExpr(0=pass) | detail
  local name=$1 verdict=$2 detail=$3
  add "$name" "$detail" "$verdict"
}

echo "── SPM adversarial config-matrix (WAF category toggles) ──────────────────"
echo "   api=$API  proxy=$PROXY"
echo

# Baseline: both attacks blocked with default (all categories on).
s=$(probe "$SQLI" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "baseline-sqli-blocked" "$v" "SQLi→$s (want 403)"
s=$(probe "$XSS" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "baseline-xss-blocked" "$v" "XSS→$s (want 403)"

# Disable SQL_INJECTION → SQLi passes, XSS still blocks (selective).
t=$(toggleCat "SQL_INJECTION" false)
[ "${t:0:1}" = 2 ] && v=PASS || v=FAIL
check "toggle-off-sqli-api" "$v" "POST categories/toggle SQL_INJECTION=false → $t (want 2xx)"
s=$(probe "$SQLI" 200); [ "$s" != 403 ] && v=PASS || v=FAIL
check "sqli-disabled-passes" "$v" "category off: SQLi→$s (want NOT 403)"
s=$(probe "$XSS" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "xss-still-blocks-while-sqli-off" "$v" "selective: XSS→$s (want 403)"

# Re-enable SQL_INJECTION → SQLi blocks again.
t=$(toggleCat "SQL_INJECTION" true)
s=$(probe "$SQLI" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "sqli-reenabled-blocks" "$v" "re-enabled: SQLi→$s (want 403)"

# Symmetric: disable XSS_ATTACKS → XSS passes, SQLi still blocks.
t=$(toggleCat "XSS_ATTACKS" false)
[ "${t:0:1}" = 2 ] && v=PASS || v=FAIL
check "toggle-off-xss-api" "$v" "POST categories/toggle XSS_ATTACKS=false → $t (want 2xx)"
s=$(probe "$XSS" 200); [ "$s" != 403 ] && v=PASS || v=FAIL
check "xss-disabled-passes" "$v" "category off: XSS→$s (want NOT 403)"
s=$(probe "$SQLI" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "sqli-still-blocks-while-xss-off" "$v" "selective: SQLi→$s (want 403)"

# Restore (also the flip-back assertion).
t=$(toggleCat "XSS_ATTACKS" true)
s=$(probe "$XSS" 403); [ "$s" = 403 ] && v=PASS || v=FAIL
check "xss-reenabled-blocks" "$v" "re-enabled: XSS→$s (want 403)"

# ── Report ───────────────────────────────────────────────────────────────────
{
  echo "# Config-matrix report"
  echo
  echo "> Settings actually change live proxy/WAF behaviour — WAF category toggles"
  echo "> flipped through the real backend→WAF push path (#200 Phase 5)."
  echo
  echo "| Check | Detail | Verdict |"
  echo "|---|---|---|"
  for r in "${REC[@]}"; do
    printf '| %s | %s | %s |\n' "${r%%|*}" "$(echo "$r" | cut -d'|' -f2)" "${r##*|}"
  done
  echo
  if [ "$rc" -eq 0 ]; then echo "_Gate: **PASS** — every toggle flipped the data plane as expected, selectively._"
  else echo "_Gate: **FAIL** — a setting did not change proxy behaviour as expected._"; fi
} >"$REPORT_DIR/config-matrix-report.md"

echo
for r in "${REC[@]}"; do
  n=${r%%|*}; d=$(echo "$r" | cut -d'|' -f2); vv=${r##*|}
  [ "$vv" = PASS ] && tag=$(green PASS) || tag=$(red FAIL)
  printf '  %-34s %-46s %b\n' "$n" "$d" "$tag"
done
echo
if [ "$rc" -eq 0 ]; then
  echo "  gate: $(green PASS)"; echo "  report: $REPORT_DIR/config-matrix-report.md"; exit 0
else
  echo "  gate: $(red FAIL)"; echo "  report: $REPORT_DIR/config-matrix-report.md"; exit 1
fi
