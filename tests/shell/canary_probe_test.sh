#!/usr/bin/env bash
# scripts/canary.sh against stub git, compose and curl: a proxy that answers
# nothing for a few seconds (Squid reconfiguring after the backend's list
# export, v3.19.0) is waited for, and so is Squid answering ERR_ICAP_FAILURE
# while the WAF is recreated (v3.20.0); a proxy that never answers, or a WAF
# that stays unreachable, fails; and a real verdict, a missed block, a false
# positive or an origin's own 500, is never retried into a pass.
#
# Usage: tests/shell/canary_probe_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
REPO=$(pwd)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/deploy"

# git: the deployment is already at origin/main.
cat > "$T/bin/git" <<'EOF'
#!/usr/bin/env bash
case "$1" in rev-parse) echo abc1234 ;; esac
exit 0
EOF

# compose: build and up succeed, every service runs, the proxy is healthy.
cat > "$T/bin/compose" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  "ps proxy --format {{.Health}}") echo healthy ;;
  ps*) printf 'proxy running\nwaf running\n' ;;
esac
exit 0
EOF

# curl: /api/health answers; a request through the proxy gets no response
# for its first DOWN calls, then Squid's 500 with X-Squid-Error:
# ERR_ICAP_FAILURE for the next ICAP calls, then LOGIN for the attack and API
# for the benign probe. Each proxy call is logged with its path. The header
# is printed only when the -w format asks for it, as curl does.
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in *"/api/health"*) echo '{"status":"healthy","version":"9.9.9"}'; exit 0 ;; esac
path=other
case "$*" in *"/login"*) path=login ;; *"/api"*) path=api ;; esac
echo "$path" >> "$STUB_LOG"
n=$(wc -l < "$STUB_LOG")
if [ "$n" -le "${DOWN:-0}" ]; then printf 000; exit 7; fi
code= err=
if [ "$n" -le $(( ${DOWN:-0} + ${ICAP:-0} )) ]; then code=500 err="ERR_ICAP_FAILURE 0"
else case $path in login) code=${LOGIN:-403} ;; api) code=${API:-405} ;; esac; fi
case "$*" in *'%header{x-squid-error}'*) printf '%s %s' "$code" "$err" ;; *) printf '%s' "$code" ;; esac
exit 0
EOF
chmod +x "$T/bin/git" "$T/bin/compose" "$T/bin/curl"

run() { # down login api [icap] -> exit code of the canary; output in $T/out
  : > "$T/log"
  (cd "$T/deploy" && PATH="$T/bin:$PATH" STUB_LOG="$T/log" DOWN="$1" LOGIN="$2" API="$3" ICAP="${4:-0}" \
    COMPOSE="$T/bin/compose" CANARY_STATE="$T/state.json" PROBE_RETRY_DELAY=0 \
    bash "$REPO/scripts/canary.sh" > "$T/out" 2>&1)
}
calls() { grep -c "^$1$" "$T/log"; }

run 0 403 405; rc=$?
[ "$rc" -eq 0 ] && [ "$(calls login)" -eq 1 ] && [ "$(calls api)" -eq 1 ] && ok "a proxy that answers: one request per probe, pass" ||
  bad "a proxy that answers" "rc=$rc $(tr '\n' ' ' < "$T/log")"

run 2 403 405; rc=$?
[ "$rc" -eq 0 ] && [ "$(calls login)" -eq 3 ] && grep -q '"verdict":"pass"' "$T/state.json" &&
  ok "no response for two attempts (Squid reconfiguring) is waited for" ||
  bad "no response for two attempts is waited for" "rc=$rc $(tail -4 "$T/out" | tr '\n' ' ')"

run 99 403 405; rc=$?
[ "$rc" -ne 0 ] && [ "$(calls login)" -eq 10 ] && grep -q 'got 000' "$T/state.json" && grep -q 'did not complete' "$T/state.json" &&
  ok "a proxy that never answers fails after 10 attempts per probe" ||
  bad "a proxy that never answers fails" "rc=$rc login=$(calls login) $(cat "$T/state.json")"

run 0 200 405; rc=$?
[ "$rc" -ne 0 ] && [ "$(calls login)" -eq 1 ] && grep -q 'did NOT block' "$T/state.json" &&
  ok "a missed block fails at once and is not retried" ||
  bad "a missed block fails at once" "rc=$rc login=$(calls login) $(cat "$T/state.json")"

run 0 403 403; rc=$?
[ "$rc" -ne 0 ] && [ "$(calls api)" -eq 1 ] && grep -q 'false positive' "$T/state.json" &&
  ok "a false positive fails at once and is not retried" ||
  bad "a false positive fails at once" "rc=$rc api=$(calls api) $(cat "$T/state.json")"

run 0 403 405 2; rc=$?
[ "$rc" -eq 0 ] && [ "$(calls login)" -eq 3 ] && grep -q '"verdict":"pass"' "$T/state.json" &&
  ok "Squid's ERR_ICAP_FAILURE for two attempts (WAF recreated) is waited for" ||
  bad "ERR_ICAP_FAILURE for two attempts is waited for" "rc=$rc $(tail -4 "$T/out" | tr '\n' ' ')"

run 0 403 405 99; rc=$?
[ "$rc" -ne 0 ] && [ "$(calls login)" -eq 10 ] && grep -q 'WAF unreachable' "$T/state.json" &&
  ok "a WAF that stays unreachable fails after 10 attempts per probe" ||
  bad "a WAF that stays unreachable fails" "rc=$rc login=$(calls login) $(cat "$T/state.json")"

run 0 500 405; rc=$?
[ "$rc" -ne 0 ] && [ "$(calls login)" -eq 1 ] && grep -q 'did NOT block' "$T/state.json" &&
  ok "an origin's 500 on the attack is a missed block, not retried" ||
  bad "an origin's 500 on the attack is a missed block" "rc=$rc login=$(calls login) $(cat "$T/state.json")"

run 0 403 500; rc=$?
[ "$rc" -eq 0 ] && [ "$(calls api)" -eq 1 ] && grep -q '500 from the origin' "$T/out" &&
  ok "an origin's 500 on the benign probe traverses, not retried" ||
  bad "an origin's 500 on the benign probe traverses" "rc=$rc api=$(calls api) $(tail -3 "$T/out" | tr '\n' ' ')"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
