# Security Policy

## Architecture

| Container | User | Privileges | Notes |
|-----------|------|-----------|-------|
| backend (Go) | `app` (UID 1000) | docker.sock:ro | Reload signals for Squid/dnsmasq |
| waf (Go) | `app` (UID 1000) | none | ICAP server, no network access |
| web (Nginx) | `nginx` | none | TLS termination, static files |
| proxy (Squid) | `proxy` | NET_ADMIN | Transparent proxy mode |
| dns (dnsmasq) | `root` | none | Internal DNS only |

### Docker Socket

The backend mounts `/var/run/docker.sock:ro` to send SIGHUP to Squid/dnsmasq when blacklists change. Read-only, non-root, no `--privileged`. Remove the mount if not needed (manual reload required).

### Authentication

- JWT Bearer tokens (8h expiry) with token blacklist on logout
- Rate limiting: 5 attempts / 5 min per IP
- bcrypt password hashing (cost 12)
- HTTPS by default (self-signed or Let's Encrypt)

### WAF

- 166 regex + 7 heuristics + 3 ML-lite across 21 Security Packs
- Anomaly scoring, dual-scan (raw + decoded), 55MB body limit
- All inputs validated with max-length constraints

## Reporting Vulnerabilities

1. **Do NOT** open a public issue
2. Use [GitHub Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new)
3. We respond within 48 hours

## Supported Versions

| Version | Status |
|---------|--------|
| 3.x | ✅ Current |
| 2.x | ⚠️ Security fixes only |
| <2.0 | ❌ EOL |
