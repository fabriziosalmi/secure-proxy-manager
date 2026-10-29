#!/usr/bin/env bash
# scripts/canary.sh against stub git, compose and curl: a proxy that answers
# nothing for a few seconds (Squid reconfiguring after the backend's list
# export, v3.19.0) is waited for; a proxy that never answers fails; and a
# real verdict, a missed block or a false positive, is never retried into a
# pass.
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
# for its first DOWN calls, then LOGIN for the attack and API for the
# benign probe. Each proxy call is logged with its path.
cat > "$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in *"/api/health"*) echo '{"status":"healthy","version":"9.9.9"}'; exit 0 ;; esac
path=other
case "$*" in *"/login"*) path=login ;; *"/api"*) path=api ;; esac
echo "$path" >> "$STUB_LOG"
n=$(wc -l < "$STUB_LOG")
if [ "$n" -le "${DOWN:-0}" ]; then printf 000; exit 7; fi
case $path in login) printf '%s' "${LOGIN:-403}" ;; api) printf '%s' "${API:-405}" ;; esac
exit 0
EOF
chmod +x "$T/bin/git" "$T/bin/compose" "$T/bin/curl"

run() { # down login api -> exit code of the canary; output in $T/out
  : > "$T/log"
  (cd "$T/deploy" && PATH="$T/bin:$PATH" STUB_LOG="$T/log" DOWN="$1" LOGIN="$2" API="$3" \
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

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
