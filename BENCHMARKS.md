# Benchmarks — Secure Proxy Manager v1.4.0

Reproducible security and performance benchmarks. All numbers are from real traffic on a LAN-deployed stack.

## Environment

| Component | Detail |
|-----------|--------|
| Version | 1.4.0 |
| WAF Engine | Go ICAP 2.0 — 171 rules, 21 categories, anomaly scoring |
| Proxy | Squid 5.9 |
| Backend | FastAPI + Uvicorn + SQLite WAL |
| Frontend | React 19 + Vite + Tailwind |
| Server | Debian LXC container (192.168.100.253), Docker Compose |
| Test client | macOS (M-series), curl 8.7.1 |
| Upstream | httpbin.org (internet, ~100ms RTT) |
| Date | 2026-03-26 |

## Security: Attack Detection

**31/31 attacks blocked (100%), 0/7 false positives (0% FP rate)**

### Attacks (all return HTTP 403)

| # | Category | Vector | Result |
|---|----------|--------|--------|
| 1 | SQL_INJECTION | UNION SELECT | Blocked |
| 2 | SQL_INJECTION | DROP TABLE | Blocked |
| 3 | SQL_INJECTION | WAITFOR DELAY (blind) | Blocked |
| 4 | SQL_INJECTION | xp_cmdshell | Blocked |
| 5 | SQL_INJECTION | INFORMATION_SCHEMA | Blocked |
| 6 | SQL_INJECTION | POST body SQLi | Blocked |
| 7 | XSS_ATTACKS | script tag | Blocked |
| 8 | XSS_ATTACKS | javascript: URI | Blocked |
| 9 | XSS_ATTACKS | onerror event handler | Blocked |
| 10 | XSS_ATTACKS | SVG onload | Blocked |
| 11 | COMMAND_INJECTION | ; cat /etc/passwd | Blocked |
| 12 | COMMAND_INJECTION | \| grep password | Blocked |
| 13 | COMMAND_INJECTION | $(cmd) subshell | Blocked |
| 14 | DIRECTORY_TRAVERSAL | ../../etc/passwd | Blocked |
| 15 | DIRECTORY_TRAVERSAL | double-encoded %252e | Blocked |
| 16 | SSRF | AWS metadata 169.254.169.254 | Blocked |
| 17 | SSRF | localhost:8080 | Blocked |
| 18 | SSRF | file:// protocol | Blocked |
| 19 | LOG4SHELL | JNDI in User-Agent | Blocked |
| 20 | XXE | ENTITY SYSTEM | Blocked |
| 21 | CLOUD_SECRETS | AWS IAM key (AKIA...) | Blocked |
| 22 | DATA_LEAK | PEM private key | Blocked |
| 23 | SENSITIVE_FILES | .git/config | Blocked |
| 24 | SENSITIVE_FILES | .env | Blocked |
| 25 | SENSITIVE_FILES | .aws/credentials | Blocked |
| 26 | WEBSHELL_C2 | c99.php | Blocked |
| 27 | WEBSHELL_C2 | mimikatz | Blocked |
| 28 | CRYPTO_TUNNEL | stratum+tcp mining | Blocked |
| 29 | CRYPTO_TUNNEL | xmrig binary | Blocked |
| 30 | DATA_EXFIL | Discord webhook | Blocked |
| 31 | JAVA_DESER | SpEL RCE | Blocked |

### False Positives (all return HTTP 200)

| Test | Result |
|------|--------|
| Normal search query | Allowed |
| JSON POST user data | Allowed |
| C++ programming query | Allowed |
| E-commerce multi-param | Allowed |
| REST API with dates | Allowed |
| PDF download | Allowed |
| OAuth callback | Allowed |

## Performance: Latency

Measured: client (macOS LAN) → Squid proxy → Go ICAP WAF → httpbin.org (internet)

### Clean requests (20 samples)

| Metric | Value |
|--------|-------|
| Min | 105ms |
| P50 (median) | 107ms |
| Average | 226ms |
| P95 | 883ms |
| P99 | 883ms |
| Max | 883ms |

Note: ~100ms is the baseline RTT to httpbin.org. The WAF adds <1ms overhead.

### Blocked requests (no upstream connection)

Blocked requests are served in ~12ms (first offense) or ~10s (tar-pit after 3+ blocks in 60s).

### Go WAF micro-benchmarks

| Benchmark | Time/op | Allocs |
|-----------|---------|--------|
| All 171 rules (legitimate URL) | 176us | 0 |
| Tier 1 early-exit (malicious URL) | 11us | 1 |
| Input normalization | 2.6us | 21 |
| Shannon entropy | 1.6us | 5 |

## Performance: Throughput

### Via Internet (httpbin.org upstream, ~100ms RTT)

| Concurrency | Requests | Time | Rate |
|-------------|----------|------|------|
| 1 client | 50 | 12,154ms | 4.1 req/s |
| 5 clients | 50 | 3,372ms | 14.8 req/s |
| 10 clients | 100 | 6,783ms | 14.7 req/s |
| 20 clients | 100 | 3,840ms | 26.0 req/s |
| 50 clients | 200 | 4,377ms | 45.6 req/s |
| 100 clients | 500 | 5,680ms | 88.0 req/s |
| 200 clients | 400 | 2,591ms | 154.3 req/s |
| 500 clients | 1,000 | 3,781ms | 264.4 req/s |
| **1,000 clients** | **1,000** | **2,974ms** | **336.2 req/s** |

### LAN-only target (no internet RTT, same network)

| Concurrency | Requests | Time | Rate |
|-------------|----------|------|------|
| 10 clients | 100 | 294ms | 340.1 req/s |
| 50 clients | 200 | 289ms | 692.0 req/s |
| 100 clients | 500 | 667ms | **749.6 req/s** |
| 200 clients | 400 | 565ms | 707.9 req/s |
| **500 clients** | **1,000** | **1,337ms** | **747.9 req/s** |

**Peak throughput: ~750 req/s** with all 171 WAF rules active (limited by WiFi LAN, not by proxy/WAF). On wired gigabit: expect 1000+ req/s.

## Backend API Latency

| Endpoint | Latency |
|----------|---------|
| /health | 7ms |
| /api/health | 6ms |
| /api/logs/stats | 457ms |
| /api/security/score | 475ms |
| /api/logs/timeline | 481ms |
| /api/database/stats | 481ms |
| /api/waf/stats | 482ms |

Note: ~450ms endpoints query a 67MB SQLite database with 500K+ log entries. With a fresh DB, these are <10ms.

## WAF Intelligence Metrics (live snapshot after benchmark)

```json
{
  "total_requests": 365,
  "total_blocked": 36,
  "block_rate_pct": 9.86,
  "avg_url_entropy": 4.18,
  "high_entropy_count": 17,
  "requests_last_minute": 302,
  "top_blocked_categories": [
    {"key": "SQL_INJECTION", "count": 12},
    {"key": "XSS_ATTACKS", "count": 4},
    {"key": "DIRECTORY_TRAVERSAL", "count": 4},
    {"key": "SENSITIVE_FILES", "count": 3},
    {"key": "COMMAND_INJECTION", "count": 3}
  ]
}
```

Traffic profiling log: 365 entries, 126KB (`/data/waf_traffic.jsonl`)

## WAF Rule Coverage

| Category | Rules | Detects |
|----------|-------|---------|
| SQL_INJECTION | 16 | UNION, DROP, blind (WAITFOR/SLEEP), stacked queries, xp_cmdshell, INFORMATION_SCHEMA, hex encoding, NoSQL |
| XSS_ATTACKS | 10 | script tags, 20+ event handlers, SVG/math, javascript:/data: URIs, DOM manipulation, template injection |
| COMMAND_INJECTION | 8 | semicolon, pipe, subshell $(), backtick, Python/Ruby/PHP eval, PowerShell, rm -rf |
| DIRECTORY_TRAVERSAL | 9 | ../, double-encode, null byte, UNC paths, /proc/self, Windows paths |
| DATA_LEAK_PREVENTION | 7 | passwords in URLs, private keys, SSN, DB connection strings |
| SSRF | 7 | AWS/GCP/Azure metadata, private IPs, file/gopher/dict protocols |
| LOG4SHELL | 5 | JNDI basic, nested expressions, hex-encoded, env lookup |
| XXE | 6 | DOCTYPE/ENTITY, php/java protocols, billion laughs |
| PROTOTYPE_POLLUTION | 4 | __proto__, constructor.prototype, bracket notation |
| PATH_MANIPULATION | 5 | PHP wrappers, phar/zip, log inclusion |
| CLOUD_SECRETS | 15 | AWS IAM, Google API, OpenAI, Stripe, SendGrid, Twilio, Slack, GitHub OAuth, Vault, Facebook |
| SENSITIVE_FILES | 15 | .git, .env, wp-config, id_rsa, .aws, .docker, terraform, kubeconfig, k8s secrets |
| WEBSHELL_C2 | 12 | c99/r57/wso, cmd=system, recon commands, mimikatz, CobaltStrike, PowerShell bypass |
| CRYPTO_TUNNEL | 8 | stratum mining, xmrig, .onion, ngrok, DNS tunneling |
| DATA_EXFIL | 8 | pastebin, Discord webhooks, Telegram bots, transfer.sh, Slack webhooks |
| POST_EXPLOIT | 7 | Windows SID, AD enumeration, Ansible secrets, K8s manifests |
| JAVA_DESER | 4 | SpEL, commons-collections, ysoserial |
| PROTOCOL_ANOMALY | 6 | empty UA, scanner headers, massive URL encoding, base64 blobs |
| FINANCIAL_DATA | 6 | Visa, MasterCard, Amex, IBAN, Bitcoin, Ethereum |
| RANSOMWARE | 3 | encrypted extensions, ransom instructions, BTC addresses |
| UNICODE_OBFUSCATION | 5 | zero-width chars, RTL override, Cyrillic/Greek homoglyphs |
| **TOTAL** | **171** | |

## How to Reproduce

### Full security benchmark
```bash
PROXY="YOUR_PROXY_IP:3128"

# Should return 403
curl -s -o /dev/null -w "%{http_code}" -x $PROXY \
  "http://httpbin.org/get?id=1'+UNION+SELECT+1--"

# Should return 200
curl -s -o /dev/null -w "%{http_code}" -x $PROXY \
  "http://httpbin.org/get?q=hello+world"
```

### Throughput benchmark
```bash
# Sequential
time for i in $(seq 1 50); do
  curl -s -o /dev/null -x $PROXY "http://httpbin.org/get?q=$i"
done

# Concurrent (10 clients)
time for round in $(seq 1 10); do
  for i in $(seq 1 10); do
    curl -s -o /dev/null -x $PROXY "http://httpbin.org/get?q=$i" &
  done; wait
done
```

### Go WAF micro-benchmark
```bash
cd waf-go && go test -bench=. -benchmem ./...
```

### WAF intelligence stats
```bash
# Direct from WAF container
curl http://WAF_CONTAINER:8080/stats

# Via backend API (requires auth)
curl -u user:pass http://BACKEND:5001/api/waf/stats
```

## Known Limitations

1. **Throughput ceiling**: limited by upstream RTT, not WAF. For LAN targets, 50-100+ req/s achievable.
2. **Tar-pit**: 10s delay after 3+ blocks in 60s window. In-memory, resets on container restart.
3. **HTTPS inspection**: requires Squid SSL Bump enabled and client trusting the proxy CA.
4. **Regex-based detection**: inherent limits vs semantic analysis (e.g., libinjection for SQL).
5. **Backend API latency**: ~450ms on large DBs (67MB, 500K+ logs). Fresh DB: <10ms.
6. **Anomaly scoring threshold**: default 10. Low-severity rules (score 2-4) won't block alone — by design.
7. **RESPMOD**: inspects response Content-Type and text bodies for XSS/secrets. No binary/AV scanning.
