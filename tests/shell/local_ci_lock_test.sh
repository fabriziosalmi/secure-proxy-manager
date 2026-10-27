#!/usr/bin/env bash
#
# Verifies scripts/local-ci.sh locking and its refusal of a checkout that is
# not a linked worktree, the non-interactive guards in ci-e2e.sh and
# adversarial/run.sh, and the subnet overlap hint in squid_acl_matrix_test.sh.
# Runs in the shellcheck job of ci.yml.
set -euo pipefail

# Under a git hook or git rebase -x, an inherited GIT_DIR would point the
# scratch repository's git init and commit below at the calling repository.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_PREFIX

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '  PASS  %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s: %s\n' "$1" "$2" >&2; }

echo "── local-ci.sh lock and non-interactive guard tests ──"

# 1. scripts/local-ci.sh exists and is executable
if [ -x "$ROOT/scripts/local-ci.sh" ]; then
  pass "scripts/local-ci.sh exists and is executable"
else
  fail "scripts/local-ci.sh exists and is executable" "missing or not executable"
fi

# 2. No scratchpad path or spmghsa project name in scripts/local-ci.sh
if [ -f "$ROOT/scripts/local-ci.sh" ] && ! grep -Eq 'scratchpad|claude-501|spmghsa' "$ROOT/scripts/local-ci.sh"; then
  pass "scripts/local-ci.sh has no scratchpad paths or spmghsa references"
else
  fail "scripts/local-ci.sh has no scratchpad paths or spmghsa references" "found forbidden reference or file missing"
fi

TMP_TEST=$(mktemp -d "${TMPDIR:-/tmp}/spm-local-ci-test.XXXXXX")
trap 'rm -rf "$TMP_TEST"' EXIT

# A scratch repository with a linked worktree, so no test touches this checkout.
G=(git -c user.name=t -c user.email=t@example.invalid -c init.defaultBranch=main)
"${G[@]}" init -q "$TMP_TEST/main"
"${G[@]}" -C "$TMP_TEST/main" commit -q --allow-empty -m init
"${G[@]}" -C "$TMP_TEST/main" worktree add -q --detach "$TMP_TEST/wt"
WT="$TMP_TEST/wt"

# 3. Two concurrent invocations: first holds lock and finishes, second fails immediately without breaking the first

LOCK_DIR="$TMP_TEST/ci.lock"
SPM_LOCAL_CI_LOCK_DIR="$LOCK_DIR" SPM_LOCAL_CI_DRY_RUN=1 SPM_LOCAL_CI_HOLD_SECONDS=2 \
  bash "$ROOT/scripts/local-ci.sh" "$WT" "$TMP_TEST/logs1" >"$TMP_TEST/out1.txt" 2>&1 &
PID1=$!

# Wait for the first process to create the lock directory
for _ in $(seq 1 20); do
  [ -d "$LOCK_DIR" ] && break
  sleep 0.1
done

set +e
OUT2=$(SPM_LOCAL_CI_LOCK_DIR="$LOCK_DIR" SPM_LOCAL_CI_DRY_RUN=1 \
  bash "$ROOT/scripts/local-ci.sh" "$WT" "$TMP_TEST/logs2" 2>&1)
RC2=$?
set -e

if [ "$RC2" -ne 0 ] && printf '%s' "$OUT2" | grep -qi "lock"; then
  pass "second local-ci.sh invocation exits non-zero with a lock message"
else
  fail "second local-ci.sh invocation exits non-zero with a lock message" "rc=$RC2 out=$OUT2"
fi

if [ -d "$LOCK_DIR" ]; then
  pass "second invocation leaves the active holder's lock directory intact while first is running"
else
  fail "second invocation leaves the active holder's lock directory intact while first is running" "lock directory was removed early"
fi

wait "$PID1"
RC1=$?
if [ "$RC1" -eq 0 ] && [ ! -d "$LOCK_DIR" ] && grep -q '^done$' "$TMP_TEST/logs1/results.txt"; then
  pass "first invocation completes cleanly and releases the lock on exit"
else
  fail "first invocation completes cleanly and releases the lock on exit" "rc1=$RC1 lock_exists=$([ -d "$LOCK_DIR" ] && echo yes || echo no)"
fi

# 4. A main checkout (where a deployment may run) is refused before any reset:
# its untracked data/ survives. Not a dry run: the guard alone must stop it.
mkdir -p "$TMP_TEST/main/data" && echo keep > "$TMP_TEST/main/data/spm.db"
set +e
OUT3=$(SPM_LOCAL_CI_LOCK_DIR="$TMP_TEST/lock3" bash "$ROOT/scripts/local-ci.sh" "$TMP_TEST/main" "$TMP_TEST/logs3" 2>&1)
RC3=$?
set -e
if [ "$RC3" -ne 0 ] && printf '%s' "$OUT3" | grep -q 'not a linked git worktree' && [ -f "$TMP_TEST/main/data/spm.db" ] && [ ! -d "$TMP_TEST/lock3" ]; then
  pass "a main checkout is refused, its data/ kept and the lock released"
else
  fail "a main checkout is refused, its data/ kept and the lock released" "rc=$RC3 out=$OUT3"
fi

set +e
OUT4=$(SPM_LOCAL_CI_LOCK_DIR="$TMP_TEST/lock4" SPM_LOCAL_CI_ALLOW_RESET=1 SPM_LOCAL_CI_DRY_RUN=1 \
  bash "$ROOT/scripts/local-ci.sh" "$TMP_TEST/main" "$TMP_TEST/logs4" 2>&1)
RC4=$?
set -e
if [ "$RC4" -eq 0 ] && printf '%s' "$OUT4" | grep -q '^done$'; then
  pass "SPM_LOCAL_CI_ALLOW_RESET=1 accepts a disposable checkout"
else
  fail "SPM_LOCAL_CI_ALLOW_RESET=1 accepts a disposable checkout" "rc=$RC4 out=$OUT4"
fi

# 5. A lock left by a process that no longer runs is taken over.
sh -c 'exit 0' &
DEAD=$!
wait "$DEAD" || true
mkdir -p "$TMP_TEST/lock5" && echo "$DEAD" > "$TMP_TEST/lock5/pid"
set +e
OUT5=$(SPM_LOCAL_CI_LOCK_DIR="$TMP_TEST/lock5" SPM_LOCAL_CI_DRY_RUN=1 bash "$ROOT/scripts/local-ci.sh" "$WT" "$TMP_TEST/logs5" 2>&1)
RC5=$?
set -e
if [ "$RC5" -eq 0 ] && printf '%s' "$OUT5" | grep -q 'stale lock' && [ ! -d "$TMP_TEST/lock5" ]; then
  pass "a stale lock from a dead pid is taken over and released"
else
  fail "a stale lock from a dead pid is taken over and released" "rc=$RC5 out=$OUT5"
fi

# 6. Root cause guards in ci-e2e.sh, adversarial/run.sh, and squid_acl_matrix_test.sh
if grep -q 'sudo -n chown' "$ROOT/tests/ci-e2e.sh"; then
  pass "tests/ci-e2e.sh uses sudo -n chown"
else
  fail "tests/ci-e2e.sh uses sudo -n chown" "missing -n flag on sudo chown"
fi

UNTAGGED_RUNS=$(grep -E '"\$\{DC\[@\]\}" run ' "$ROOT/tests/adversarial/run.sh" | grep -v -- ' -T ' || true)
if [ -z "$UNTAGGED_RUNS" ]; then
  pass "tests/adversarial/run.sh passes -T to every docker compose run"
else
  fail "tests/adversarial/run.sh passes -T to every docker compose run" "missing -T on: $UNTAGGED_RUNS"
fi

# The hint names the prefix the suite really gives its networks.
MTX_PFX=$(sed -n 's/^PFX="\([a-z]*\)\$\$"$/\1/p' "$ROOT/tests/shell/squid_acl_matrix_test.sh")
if [ -n "$MTX_PFX" ] && grep -q "Pool overlaps" "$ROOT/tests/shell/squid_acl_matrix_test.sh" &&
  grep -q "docker network rm .*grep '^$MTX_PFX'" "$ROOT/tests/shell/squid_acl_matrix_test.sh"; then
  pass "tests/shell/squid_acl_matrix_test.sh explains how to clean up overlapping networks"
else
  fail "tests/shell/squid_acl_matrix_test.sh explains how to clean up overlapping networks" "missing Pool overlaps hint, or its docker network rm does not match PFX=$MTX_PFX"
fi

echo
printf 'Summary: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
