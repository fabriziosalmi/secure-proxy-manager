#!/usr/bin/env bash
# Secure Proxy Manager — deployment validation suite.
#
# Smoke-checks a running SPM instance (any host) and runs the Playwright E2E
# suite against it. Works for a local stack or a remote deployment.
#
# Usage:
#   scripts/validate-homelab.sh [host] [port]
#   BASE_URL=https://proxy.example.com:8443 scripts/validate-homelab.sh
#
# Defaults: host=localhost, port=8443. The host/port form builds an https:// URL;
# set BASE_URL explicitly to use http:// or a non-standard path.
#
# Auth for the E2E suite (optional, defaults match the dev stack):
#   BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD
set -euo pipefail

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8443}"
BASE_URL="${BASE_URL:-https://${TARGET_HOST}:${TARGET_PORT}}"

[ -n "$BASE_URL" ] || { echo "❌ BASE_URL is empty" >&2; exit 2; }

echo "============================================="
echo "   Secure Proxy Manager Deployment Validator "
echo "   Targeting: ${BASE_URL}"
echo "============================================="

# 1. Reachability (-k: self-signed certs are expected on SPM's bumped TLS).
echo "Checking reachability..."
if curl -k -sf --max-time 15 "${BASE_URL}/" >/dev/null; then
  echo "✔ Reachability: OK"
else
  echo "❌ Reachability failed. Ensure the instance at ${BASE_URL} is running and accessible." >&2
  exit 1
fi

# 2. Playwright E2E suite against the target.
echo "Checking E2E test suite..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../ui"

if [ ! -x node_modules/.bin/playwright ]; then
  echo "Tip: run 'npm ci' in the ui/ directory first (Playwright is a devDependency)." >&2
fi
# Browser binaries are installed on demand; nudge if missing.
npx playwright install chromium >/dev/null 2>&1 || \
  echo "Tip: 'npx playwright install chromium' if browser binaries are missing." >&2

echo "Running E2E tests against ${BASE_URL}..."
BASE_URL="${BASE_URL}" npx playwright test

echo "============================================="
echo "   ✔ Deployment Validation Successful!        "
echo "============================================="
