#!/usr/bin/env bash
# pre-commit-validate.sh — fast local validation before committing
#
# Runs without Docker (uses local toolchains).
# Checks: TypeScript types, ESLint, Go format/vet/tests, UI build.
#
# Usage:
#   ./scripts/pre-commit-validate.sh
#   ./scripts/pre-commit-validate.sh --fix    # auto-fix ESLint issues where possible

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX_MODE=false

for arg in "$@"; do
  [ "$arg" = "--fix" ] && FIX_MODE=true
done

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
STEPS=()

step_start() { echo -e "\n${CYAN}▶ $*${NC}"; }
step_ok()    { echo -e "${GREEN}  ✓ $*${NC}"; PASS=$((PASS+1)); STEPS+=("PASS: $*"); }
step_fail()  { echo -e "${RED}  ✗ $*${NC}"; FAIL=$((FAIL+1)); STEPS+=("FAIL: $*"); }
step_warn()  { echo -e "${YELLOW}  ~ $*${NC}"; }

# ── 1. TypeScript type-check ──────────────────────────────────────────────────

step_start "TypeScript type-check (tsc --noEmit)"
if (cd "${REPO_ROOT}/ui" && npx tsc --noEmit 2>&1); then
  step_ok "TypeScript: no type errors"
else
  step_fail "TypeScript: type errors found (fix before committing)"
fi

# ── 2. ESLint ─────────────────────────────────────────────────────────────────

step_start "ESLint"
LINT_ARGS="."
[ "$FIX_MODE" = true ] && LINT_ARGS=". --fix"
if (cd "${REPO_ROOT}/ui" && npx eslint ${LINT_ARGS} 2>&1); then
  step_ok "ESLint: clean"
else
  if [ "$FIX_MODE" = true ]; then
    step_warn "ESLint: some issues could not be auto-fixed — review manually"
    FAIL=$((FAIL+1)); STEPS+=("FAIL: ESLint (unfixable issues remain)")
  else
    step_fail "ESLint: issues found (run with --fix to auto-fix, or review manually)"
  fi
fi

# ── 3. Go format & vet ────────────────────────────────────────────────────────

step_start "Go format & vet (backend-go, waf-go)"
# gofmt drift is reported as a warning (the tree has pre-existing drift that CI
# does not gate on); go vet is the hard gate. Run with --fix to auto-format.
GO_OK=true
for mod in backend-go waf-go; do
  dir="${REPO_ROOT}/${mod}"
  [ -d "$dir" ] || continue
  unformatted="$(cd "$dir" && gofmt -l . 2>/dev/null || true)"
  if [ -n "$unformatted" ]; then
    if [ "$FIX_MODE" = true ]; then
      (cd "$dir" && gofmt -w .)
      echo "    fixed formatting in ${mod}"
    else
      step_warn "${mod} not gofmt-clean (run with --fix): $(echo "$unformatted" | tr '\n' ' ')"
    fi
  fi
  if ! (cd "$dir" && go vet ./... 2>&1); then
    echo -e "  ${RED}FAIL: go vet in ${mod}${NC}"
    GO_OK=false
  fi
done

if $GO_OK; then
  step_ok "Go: go vet passed"
else
  step_fail "Go: go vet issues found"
fi

# ── 4. Go unit tests ──────────────────────────────────────────────────────────

step_start "Go unit tests (go test ./...)"
GOTEST_OK=true
for mod in backend-go waf-go; do
  dir="${REPO_ROOT}/${mod}"
  [ -d "$dir" ] || continue
  if ! (cd "$dir" && go test ./... 2>&1); then
    GOTEST_OK=false
  fi
done

if $GOTEST_OK; then
  step_ok "Go unit tests: all passed"
else
  step_fail "Go unit tests: failures detected"
fi

# ── 5. UI build smoke-test ────────────────────────────────────────────────────

step_start "UI build (vite build)"
if (cd "${REPO_ROOT}/ui" && npm run build 2>&1); then
  step_ok "UI build: success"
else
  step_fail "UI build: failed (TypeScript or Vite error)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}─── Validation summary ───────────────────────────────────${NC}"
for s in "${STEPS[@]}"; do
  if [[ "$s" == PASS* ]]; then
    echo -e "  ${GREEN}✓${NC} ${s#PASS: }"
  else
    echo -e "  ${RED}✗${NC} ${s#FAIL: }"
  fi
done
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}All $PASS checks passed — ready to commit.${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}$FAIL check(s) failed, $PASS passed — fix issues before committing.${NC}"
  exit 1
fi
