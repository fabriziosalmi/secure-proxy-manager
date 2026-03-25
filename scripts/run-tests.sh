#!/usr/bin/env bash
# run-tests.sh — spin up the full test stack, run all tests, tear it down
#
# Usage:
#   ./scripts/run-tests.sh               # run everything
#   ./scripts/run-tests.sh --no-build    # skip image rebuild
#   ./scripts/run-tests.sh --keep        # don't tear down after (for debugging)
#
# The exit code mirrors the test runner: 0 = all passed, 1 = failures.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/docker-compose.test.yml"
RESULTS_DIR="${REPO_ROOT}/.test-results"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

BUILD_FLAG="--build"
KEEP_UP=false

for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD_FLAG="" ;;
    --keep)     KEEP_UP=true ;;
  esac
done

info()    { echo -e "${CYAN}[test]${NC} $*"; }
success() { echo -e "${GREEN}[test]${NC} $*"; }
warn()    { echo -e "${YELLOW}[test]${NC} $*"; }
error()   { echo -e "${RED}[test]${NC} $*"; }

# ── Cleanup ───────────────────────────────────────────────────────────────────

teardown() {
  if [ "$KEEP_UP" = false ]; then
    info "Tearing down test stack..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
  else
    warn "--keep flag set: stack left running. Tear down with:"
    warn "  docker compose -f docker-compose.test.yml down -v"
  fi
}
trap teardown EXIT

# ── Copy test results from Docker volume to host ───────────────────────────────

copy_results() {
  mkdir -p "$RESULTS_DIR"
  local cid
  cid=$(docker compose -f "$COMPOSE_FILE" ps -q test-runner 2>/dev/null | head -1)
  if [ -n "$cid" ]; then
    docker cp "${cid}:/test-results/." "$RESULTS_DIR/" 2>/dev/null || true
    if [ -f "${RESULTS_DIR}/html/index.html" ]; then
      success "HTML report: file://${RESULTS_DIR}/html/index.html"
    fi
    if [ -f "${RESULTS_DIR}/results.json" ]; then
      info "JSON results: ${RESULTS_DIR}/results.json"
    fi
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

info "Secure Proxy Manager — E2E Test Suite"
info "Compose file: $COMPOSE_FILE"
echo ""

# Install Playwright deps if running locally (not in Docker)
if [ -z "${CI:-}" ] && [ -f "${REPO_ROOT}/tests/e2e/package.json" ]; then
  info "Installing Playwright deps locally..."
  (cd "${REPO_ROOT}/tests/e2e" && npm install --silent)
fi

info "Starting test stack (${BUILD_FLAG:-no rebuild})..."
docker compose -f "$COMPOSE_FILE" ${BUILD_FLAG} pull --quiet 2>/dev/null || true

EXIT_CODE=0
docker compose -f "$COMPOSE_FILE" up \
  ${BUILD_FLAG} \
  --abort-on-container-exit \
  --exit-code-from test-runner \
  2>&1 | tee /tmp/spm-test-run.log || EXIT_CODE=$?

copy_results

echo ""
if [ "$EXIT_CODE" -eq 0 ]; then
  success "All tests passed!"
else
  error "Tests failed (exit code: $EXIT_CODE). Check output above."
  if [ -f "${RESULTS_DIR}/html/index.html" ]; then
    warn "Open the HTML report for details: file://${RESULTS_DIR}/html/index.html"
  fi
fi

exit "$EXIT_CODE"
