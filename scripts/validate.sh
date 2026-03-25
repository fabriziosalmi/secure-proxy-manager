#!/bin/bash
# Pre-push validation: run this before every push to catch issues early.
# Usage: ./scripts/validate.sh
#
# Checks:
#   1. TypeScript build (UI)
#   2. Backend unit tests (pytest, no live network)
#   3. Popular list URL health (live check)
#
# Exit codes: 0 = all pass, 1 = one or more checks failed

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}  $1"; ((PASS++)) || true; }
fail() { echo -e "${RED}FAIL${NC}  $1"; ((FAIL++)) || true; }
info() { echo -e "${YELLOW}----${NC}  $1"; }

echo ""
echo "========================================"
echo " Secure Proxy Manager — Pre-push checks"
echo "========================================"
echo ""

# ── 1. TypeScript build ──────────────────────────────────────────────────
info "TypeScript build…"
if (cd "$ROOT/ui" && npm run build --silent 2>&1 | tail -5); then
  pass "UI TypeScript build"
else
  fail "UI TypeScript build"
fi
echo ""

# ── 2. Backend unit tests ────────────────────────────────────────────────
info "Backend unit tests…"
PYTEST_BIN=""
for candidate in pytest pytest3 python3 python; do
  if command -v "$candidate" &>/dev/null; then
    case "$candidate" in
      pytest*) PYTEST_BIN="$candidate"; break ;;
      python*) if "$candidate" -m pytest --version &>/dev/null 2>&1; then PYTEST_BIN="$candidate -m pytest"; break; fi ;;
    esac
  fi
done

if [ -n "$PYTEST_BIN" ]; then
  if BASIC_AUTH_USERNAME=testuser BASIC_AUTH_PASSWORD=testpass \
     $PYTEST_BIN "$ROOT/tests/test_imports.py" -v --tb=short -q 2>&1; then
    pass "Backend unit tests"
  else
    fail "Backend unit tests"
  fi
else
  echo "  pytest not found — skipping (install: pip install pytest pytest-mock httpx)"
fi
echo ""

# ── 3. Popular list URLs ─────────────────────────────────────────────────
info "Popular list URL health check…"

check_url() {
  local name="$1"
  local url="$2"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -H "User-Agent: SecureProxyManager/validate" "$url")
  if [ "$code" = "200" ]; then
    echo -e "  ${GREEN}OK${NC}  [$code] $name"
  else
    echo -e "  ${RED}FAIL${NC} [$code] $name"
    echo "       $url"
    ((FAIL++)) || true
    return 1
  fi
}

check_url "Firehol Level 1"    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
check_url "Spamhaus DROP"      "https://www.spamhaus.org/drop/drop.txt"
check_url "Emerging Threats"   "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
check_url "CINS Army"          "https://cinsarmy.com/list/ci-badguys.txt"
check_url "StevenBlack hosts"  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
check_url "URLhaus domains"    "https://urlhaus.abuse.ch/downloads/hostfile/"
check_url "Phishing Army"      "https://phishing.army/download/phishing_army_blocklist_extended.txt"

if [ "$FAIL" -eq 0 ]; then pass "All list URLs reachable"; fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────────
echo "========================================"
if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}All checks passed${NC} ($PASS passed, 0 failed)"
  echo "========================================"
  exit 0
else
  echo -e "${RED}${FAIL} check(s) failed${NC} ($PASS passed)"
  echo "========================================"
  exit 1
fi
