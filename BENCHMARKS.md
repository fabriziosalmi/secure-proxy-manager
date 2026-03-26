# Benchmarks

Reproducible security and performance benchmarks for Secure Proxy Manager.

## Environment

| Component | Version |
|-----------|---------|
| Secure Proxy Manager | 1.3.0 |
| WAF Engine | Go ICAP 2.0 (78 rules, 11 categories, anomaly scoring) |
| Proxy | Squid 5.x |
| Test host | macOS (M-series), curl 8.7 |
| Target | Debian VM (192.168.100.253), Docker Compose, LAN |
| Upstream | httpbin.org (internet RTT ~100ms) |

## WAF Security Detection

**Date**: 2026-03-26
**WAF Config**: 78 rules, threshold=10, tar-pit after 3 blocks in 60s

### Attack detection (23/23 = 100%)

| Category | Test | HTTP | Result |
|----------|------|------|--------|
| SQL_INJECTION | UNION SELECT | 403 | Blocked |
| SQL_INJECTION | DROP TABLE | 403 | Blocked |
| SQL_INJECTION | WAITFOR DELAY (blind) | 403 | Blocked |
| SQL_INJECTION | xp_cmdshell | 403 | Blocked |
| SQL_INJECTION | INFORMATION_SCHEMA | 403 | Blocked |
| SQL_INJECTION | POST body SQLi | 403 | Blocked |
| XSS_ATTACKS | script tag | 403 | Blocked |
| XSS_ATTACKS | javascript: URI | 403 | Blocked |
| XSS_ATTACKS | onerror handler | 403 | Blocked |
| XSS_ATTACKS | SVG onload | 403 | Blocked |
| XSS_ATTACKS | POST body XSS | 403 | Blocked |
| COMMAND_INJECTION | semicolon + cat | 403 | Blocked |
| COMMAND_INJECTION | pipe + grep | 403 | Blocked |
| COMMAND_INJECTION | subshell $() | 403 | Blocked |
| DIRECTORY_TRAVERSAL | ../../etc/passwd | 403 | Blocked |
| DIRECTORY_TRAVERSAL | double encoded | 403 | Blocked |
| SSRF | AWS metadata 169.254.169.254 | 403 | Blocked |
| SSRF | localhost:8080 | 403 | Blocked |
| SSRF | file:// protocol | 403 | Blocked |
| LOG4SHELL | JNDI in User-Agent | 403 | Blocked |
| XXE | ENTITY SYSTEM | 403 | Blocked |
| DATA_LEAK | AWS access key (AKIA...) | 403 | Blocked |
| DATA_LEAK | PEM private key | 403 | Blocked |

### False positives (0/5 = 0% FP rate)

| Test | HTTP | Result |
|------|------|--------|
| Normal search query | 200 | Allowed |
| JSON POST (user data) | 200 | Allowed |
| URL with special chars (c++ programming) | 200 | Allowed |
| E-commerce multi-param query | 200 | Allowed |
| REST API with dates | 200 | Allowed |

### Summary

```
Detection rate:      100% (23/23 attacks blocked)
False positive rate: 0%   (0/5 legitimate requests blocked)
```

## Performance

### Latency (single request, LAN → proxy → httpbin.org)

| Metric | Value |
|--------|-------|
| Clean request (proxy + WAF + upstream) | ~108ms |
| Malicious request (blocked by WAF, no upstream) | ~12ms |
| WAF inspection overhead | <1ms (Go benchmark: 96us/req all 78 rules) |
| Upstream RTT (httpbin.org) | ~100ms |
| Tar-pit delay (repeat offenders) | 10,000ms |

### Throughput

| Mode | Requests | Time | Rate |
|------|----------|------|------|
| Sequential (1 client) | 50 | 10,097ms | 4.9 req/s |
| Concurrent (10 clients) | 50 | 2,322ms | 21.5 req/s |

### Go WAF micro-benchmarks (`go test -bench`)

| Benchmark | Time/op | Allocs/op |
|-----------|---------|-----------|
| MatchLegitimateURL (all 78 rules) | 95,599 ns | 0 |
| MatchMaliciousURL (Tier 1 early-exit) | 9,237 ns | 1 |
| NormalizeInput (anti-evasion) | 2,543 ns | 21 |

## How to reproduce

### Security benchmark

```bash
# Requires: proxy running on 192.168.100.253:3128
PROXY="192.168.100.253:3128"

# Should return 403 (blocked)
curl -s -o /dev/null -w "%{http_code}" -x $PROXY \
  "http://httpbin.org/get?id=1'+UNION+SELECT+1--"

# Should return 200 (allowed)
curl -s -o /dev/null -w "%{http_code}" -x $PROXY \
  "http://httpbin.org/get?q=hello+world"
```

### Performance benchmark

```bash
# Single request latency
curl -s -o /dev/null -w "%{time_total}s" -x $PROXY \
  "http://httpbin.org/get?q=hello"

# Concurrent throughput (10 parallel)
for i in $(seq 1 10); do
  curl -s -o /dev/null -x $PROXY "http://httpbin.org/get?q=test" &
done
wait
```

### Go micro-benchmark

```bash
cd waf-go && go test -bench=. -benchmem ./...
```

## Known limitations

- WAF operates at the ICAP layer (Squid REQMOD): it inspects URLs, headers, and request bodies. Response body inspection (RESPMOD) only checks Content-Type, not content.
- Anomaly scoring threshold (default 10) may need tuning per deployment. Low-severity rules (score 2-4) alone won't trigger a block.
- Tar-pitting is IP-based and in-memory: it resets on WAF container restart.
- HTTPS inspection requires SSL Bump enabled in Squid (client must trust the proxy CA).
- regex-based detection has inherent limits vs. semantic analysis (e.g., libinjection for SQL).
