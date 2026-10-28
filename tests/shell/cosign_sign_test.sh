#!/usr/bin/env bash
# scripts/cosign-sign.sh against a stub cosign: a transient sign failure is
# retried, a persistent one fails, and a sign that "succeeds" without a
# verifiable signature fails too.
#
# Usage: tests/shell/cosign_sign_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); printf "  ✗ %s\n     %s\n" "$1" "${2:-}"; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

# The stub fails "sign" SIGN_FAILS times, then succeeds; "verify" exits
# VERIFY_RC. Calls are logged so the test can count them.
cat > "$T/cosign" <<'EOF'
#!/usr/bin/env bash
echo "$1" >> "$STUB_LOG"
case "$1" in
  sign)
    n=$(grep -c '^sign$' "$STUB_LOG")
    [ "$n" -le "${SIGN_FAILS:-0}" ] && { echo "409 createLogEntryConflict" >&2; exit 1; }
    exit 0 ;;
  verify) exit "${VERIFY_RC:-0}" ;;
esac
EOF
chmod +x "$T/cosign"

run() { # sign_fails verify_rc -> exit code of the script
  : > "$T/log"
  PATH="$T:$PATH" STUB_LOG="$T/log" SIGN_FAILS="$1" VERIFY_RC="$2" COSIGN_RETRY_DELAY=0 \
    bash scripts/cosign-sign.sh "ghcr.io/example/img@sha256:0000" >/dev/null 2>&1
}

run 0 0; rc=$?; signs=$(grep -c '^sign$' "$T/log")
[ "$rc" -eq 0 ] && [ "$signs" -eq 1 ] && ok "signs once and verifies" || bad "signs once and verifies" "rc=$rc signs=$signs"

run 1 0; rc=$?; signs=$(grep -c '^sign$' "$T/log")
[ "$rc" -eq 0 ] && [ "$signs" -eq 2 ] && ok "one transient failure (the 409 of v3.18.1) is retried" || bad "one transient failure is retried" "rc=$rc signs=$signs"

run 3 0; rc=$?; signs=$(grep -c '^sign$' "$T/log")
[ "$rc" -ne 0 ] && [ "$signs" -eq 3 ] && ok "three failures fail the step" || bad "three failures fail the step" "rc=$rc signs=$signs"

run 0 1; rc=$?
[ "$rc" -ne 0 ] && ok "a sign whose signature does not verify fails the step" || bad "a sign whose signature does not verify fails the step" "rc=$rc"

grep -q '^verify$' "$T/log" && ok "the verify ran" || bad "the verify ran" "$(cat "$T/log")"

printf "\n  %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
