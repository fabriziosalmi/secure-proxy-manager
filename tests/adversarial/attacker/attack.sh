#!/usr/bin/env bash
#
# Adversarial block-matrix driver (issue #200, Phase 1).
#
# Sends every corpus case THROUGH the forward proxy (so the real WAF/ICAP path
# inspects it), classifies the verdict as TP/TN/FP/FN, and emits a block-matrix
# + FP/FN report (Markdown + JSON) to $REPORT_DIR.
#
# Verdict signal is the HTTP status the client sees: a WAF block surfaces as 403.
# The WAF's internal category is NOT observable client-side — Squid replaces the
# ICAP block body with its own error page (deny_info), which is the correct
# black-box attacker view. The INTENDED category/rule per case is documented in
# corpus.json (`category` + `desc`); attributing the actual firing category would
# require correlating the WAF's own logs (a later enhancement, cf. #107).
#
# Exit code = CI gate: non-zero if any HARD-gate case is a false negative
# (malicious not blocked) or false positive (benign blocked). SOFT-gate cases
# (normalization-dependent or sub-threshold-by-design) are reported, not gated.
set -uo pipefail

CORPUS="${CORPUS:-/adversarial/corpus.json}"
REPORT_DIR="${REPORT_DIR:-/report}"
PROXY="${PROXY:-http://proxy:3128}"
BASE="${BASE:-http://upstream.test}"

mkdir -p "$REPORT_DIR"
RESULTS="$(mktemp)"
BODY="/tmp/resp.out"

green() { printf '\033[32m%s\033[0m' "$1"; }
red()   { printf '\033[31m%s\033[0m' "$1"; }

echo "── SPM adversarial block-matrix ─────────────────────────────────────────"
echo "   proxy=$PROXY  target=$BASE  corpus=$CORPUS"
echo

n=$(jq 'length' "$CORPUS")
i=0
while [ "$i" -lt "$n" ]; do
  row=$(jq -c ".[$i]" "$CORPUS")
  i=$((i + 1))

  # Scalar fields (none contain tabs/newlines) in one jq call.
  IFS=$'\t' read -r id category kind vector method expect gate ctype <<EOF
$(jq -r '[.id,.category,.kind,.vector,.method,.expect,.gate,(.content_type//"")] | @tsv' <<<"$row")
EOF
  path=$(jq -r '.path' <<<"$row")
  body=$(jq -r '.body // empty' <<<"$row")

  # Build the curl invocation. --path-as-is preserves ../ and encoded payloads;
  # the WAF percent-decodes internally, so the encoded corpus reaches the rules.
  set -- -sS --max-time 20 -o "$BODY" -w '%{http_code}' -x "$PROXY" --path-as-is -X "$method"

  hlen=$(jq '(.headers // []) | length' <<<"$row")
  j=0
  while [ "$j" -lt "$hlen" ]; do
    set -- "$@" -H "$(jq -r ".headers[$j]" <<<"$row")"
    j=$((j + 1))
  done

  if [ -n "$body" ]; then
    [ -n "$ctype" ] && set -- "$@" -H "Content-Type: $ctype"
    set -- "$@" --data-binary "$body"
  fi
  set -- "$@" "${BASE}${path}"

  status=$(curl "$@" 2>/dev/null || echo "000")

  blocked=false
  [ "$status" = "403" ] && blocked=true

  if [ "$expect" = "block" ]; then
    $blocked && verdict="TP" || verdict="FN"
  else
    $blocked && verdict="FP" || verdict="TN"
  fi

  jq -nc \
    --arg id "$id" --arg category "$category" --arg kind "$kind" \
    --arg vector "$vector" --arg expect "$expect" --arg gate "$gate" \
    --arg verdict "$verdict" --argjson blocked "$blocked" --argjson status "${status:-0}" \
    '{id:$id,category:$category,kind:$kind,vector:$vector,expect:$expect,gate:$gate,status:$status,blocked:$blocked,verdict:$verdict}' \
    >>"$RESULTS"

  case "$verdict" in
    TP|TN) tag=$(green "$verdict") ;;
    FN|FP) tag=$(red   "$verdict") ;;
    *)     tag="$verdict" ;;
  esac
  printf '  %-26s %-22s %-8s expect=%-5s status=%-3s %b\n' \
    "$id" "$category" "$vector" "$expect" "$status" "$tag"
done

# ── Aggregate ────────────────────────────────────────────────────────────────
jq -s '.' "$RESULTS" >"$REPORT_DIR/results.json"

summary=$(jq '{
  total:   length,
  tp:      [.[]|select(.verdict=="TP")]|length,
  tn:      [.[]|select(.verdict=="TN")]|length,
  fp:      [.[]|select(.verdict=="FP")]|length,
  fn:      [.[]|select(.verdict=="FN")]|length,
  hard_fn: [.[]|select(.verdict=="FN" and .gate=="hard")]|length,
  hard_fp: [.[]|select(.verdict=="FP" and .gate=="hard")]|length,
  categories_covered: ([.[]|select(.expect=="block")|.category]|unique|length)
}' "$REPORT_DIR/results.json")

hard_fn=$(jq -r '.hard_fn' <<<"$summary")
hard_fp=$(jq -r '.hard_fp' <<<"$summary")
tp=$(jq -r '.tp' <<<"$summary"); tn=$(jq -r '.tn' <<<"$summary")
fp=$(jq -r '.fp' <<<"$summary"); fn=$(jq -r '.fn' <<<"$summary")
total=$(jq -r '.total' <<<"$summary"); covered=$(jq -r '.categories_covered' <<<"$summary")

gate_pass=true
{ [ "$hard_fn" -gt 0 ] || [ "$hard_fp" -gt 0 ]; } && gate_pass=false

# ── Markdown report ──────────────────────────────────────────────────────────
{
  echo "# Adversarial block-matrix report"
  echo
  echo "> SPM data-plane security regression — traffic driven through the real"
  echo "> forward proxy + WAF/ICAP (issue #200, Phase 1)."
  echo
  echo "## Summary"
  echo
  echo "| Metric | Value |"
  echo "|---|---|"
  echo "| Cases | $total |"
  echo "| WAF categories exercised | $covered |"
  echo "| True positives (malicious blocked) | $tp |"
  echo "| True negatives (benign allowed) | $tn |"
  echo "| **False negatives (malicious allowed)** | $fn (hard: $hard_fn) |"
  echo "| **False positives (benign blocked)** | $fp (hard: $hard_fp) |"
  if $gate_pass; then echo "| **Gate** | ✅ PASS |"; else echo "| **Gate** | ❌ FAIL |"; fi
  echo
  echo "## Block-matrix"
  echo
  echo "_Status is the client-observed HTTP code (403 = blocked). Category is the"
  echo "payload's intended target rule-group (see corpus \`desc\`), not necessarily"
  echo "the WAF's internal attribution, which is not visible client-side._"
  echo
  echo "| Case | Category | Kind | Vector | Expect | Status | Verdict |"
  echo "|---|---|---|---|---|---|---|"
  jq -r '.[] | "| \(.id) | \(.category) | \(.kind) | \(.vector) | \(.expect) | \(.status) | \(.verdict) |"' \
    "$REPORT_DIR/results.json"
  echo
  if [ "$fn" -gt 0 ] || [ "$fp" -gt 0 ]; then
    echo "## Misses"
    echo
    jq -r '.[] | select(.verdict=="FN" or .verdict=="FP") |
      "- **\(.verdict)** `\(.id)` (\(.category), gate=\(.gate)) — expected \(.expect), got HTTP \(.status)"' \
      "$REPORT_DIR/results.json"
    echo
  fi
} >"$REPORT_DIR/report.md"

jq -n --argjson summary "$summary" --argjson gate_pass "$($gate_pass && echo true || echo false)" \
  --slurpfile results "$REPORT_DIR/results.json" \
  '{gate_pass:$gate_pass, summary:$summary, results:$results[0]}' \
  >"$REPORT_DIR/report.json"

echo
echo "── Summary ──────────────────────────────────────────────────────────────"
printf '  cases=%s  categories=%s  TP=%s TN=%s  FN=%s(hard %s)  FP=%s(hard %s)\n' \
  "$total" "$covered" "$tp" "$tn" "$fn" "$hard_fn" "$fp" "$hard_fp"
if $gate_pass; then
  echo "  gate: $(green PASS)"
  echo "  report: $REPORT_DIR/report.md"
  exit 0
else
  echo "  gate: $(red FAIL) — hard false negatives/positives present"
  echo "  report: $REPORT_DIR/report.md"
  exit 1
fi
