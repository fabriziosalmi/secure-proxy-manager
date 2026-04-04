# Security Policy

## Architecture

| Container | User | Privileges | Notes |
|-----------|------|-----------|-------|
| backend (Go) | `app` (UID 1000) | docker.sock:ro | Reload signals for Squid/dnsmasq |
| waf (Go) | `waf` (UID 1000) | none | ICAP server, internal only |
| web (Nginx) | `nginx` | none | TLS termination, static files |
| proxy (Squid) | `proxy` | NET_ADMIN | Transparent proxy mode |
| dns (dnsmasq) | `root` | none | Internal DNS only |

### Docker Socket

The backend mounts `/var/run/docker.sock:ro` to send SIGHUP to Squid/dnsmasq when blacklists change. Read-only, non-root, no `--privileged`. Remove the mount if not needed (manual reload required).

### Authentication

- JWT Bearer tokens (8h expiry) with **persistent token blacklist** (survives restarts via SQLite)
- bcrypt password hashing (default cost 10) — plaintext fallback removed in v3.1
- Per-IP login rate limiting: 5 attempts / 5 min
- **Global rate limiting**: Token bucket per-IP (20 req/s, 60 burst) on all endpoints
- WebSocket origin validation against CORS allowlist
- HTTPS by default (self-signed 1-year cert or Let's Encrypt)

### Encryption

- **Sensitive settings encrypted at rest**: Webhook URLs, Gotify/Telegram/ntfy tokens stored with AES-256-GCM
- Encryption key auto-generated and persisted to `/data/.enc_key` (mode 0600)
- JWT secret auto-generated and persisted to `/data/.jwt_secret` (mode 0600)
- TLS 1.2/1.3 only, strong ciphers (`HIGH:!aNULL:!MD5:!RC4`), HSTS 1 year

### Content Security Policy

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self' data:;
connect-src 'self' ws: wss:
```

### WAF

- 166 regex + 7 heuristics + 3 ML-lite across 21 Security Packs
- Anomaly scoring, dual-scan (raw + decoded), 55MB body limit
- All inputs validated with max-length constraints
- Circuit breaker protects backend against WAF service failures

### Resilience

- **Circuit breaker**: WAF calls trip after 3 failures, auto-recover after 30s
- **Notification retry**: Failed deliveries retry 3x with exponential backoff (1s, 2s, 4s)
- **Graceful shutdown**: All background workers respond to SIGTERM via context cancellation
- **Atomic file exports**: Temp file + rename pattern prevents torn reads by Squid/dnsmasq

### CI/CD Security

- **gosec**: Automated Go security scanning on every push/PR
- **npm audit**: Frontend dependency vulnerability checking (high severity)
- **Backend tests**: Race detector enabled, 60% coverage threshold enforced
- **Docker build verification**: All 5 images built and verified in CI

## Reporting Vulnerabilities

1. **Do NOT** open a public issue
2. Use [GitHub Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new)
3. We respond within 48 hours

## Supported Versions

| Version | Status |
|---------|--------|
| 3.1.x | Current (security hardening release) |
| 3.0.x | Security fixes only |
| 2.x | EOL |
| <2.0 | EOL |
