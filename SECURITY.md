# Security Policy

## Architecture

As shipped in `docker-compose.yml`. Every service runs with a read-only root
filesystem and `no-new-privileges`.

| Container | Runs as | Capabilities | Notes |
|-----------|---------|--------------|-------|
| backend (Go) | root (the image sets no `USER`) | none (`cap_drop: ALL`) | No Docker socket. Reloads are requested with trigger files in `/config`, which the proxy's watchdog applies |
| waf (Go) | `waf` (UID 1000) | none (`cap_drop: ALL`) | ICAP on 1344 and the management API on 8080, internal network only |
| web (nginx) | master as root, workers as `nginx` | `CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE` | TLS termination, static files, `/api` reverse proxy |
| proxy (Squid) | supervisord and the watchdog as root; Squid as `proxy` | Docker's default set plus `NET_ADMIN` (no `cap_drop`) | `NET_ADMIN` is used only for iptables REDIRECT rules; transparent interception is not implemented (no intercept port) |
| dns (dnsmasq) | root (`--user=root`) | `NET_BIND_SERVICE`, `DAC_OVERRIDE` | Internal DNS only, not published on the host |

### Docker Socket

No container mounts the Docker socket.

### Authentication

- JWT Bearer tokens (8h expiry) with **persistent token blacklist** (survives restarts via SQLite)
- bcrypt password hashing (default cost 10); plaintext fallback removed in v3.1
- Per-IP login rate limiting: 5 attempts / 5 min
- **Global rate limiting**: Token bucket per-IP (20 req/s, 60 burst) on all endpoints
- WebSocket origin validation against CORS allowlist
- HTTPS by default (self-signed 1-year cert, or a certificate mounted at `/etc/nginx/ssl/`)

### Encryption

- **Sensitive settings encrypted at rest**: Webhook URLs, Gotify/Telegram/ntfy tokens stored with AES-256-GCM
- Encryption key auto-generated and persisted to `/data/.enc_key` (mode 0600)
- JWT secret auto-generated and persisted to `/data/.jwt_secret` (mode 0600)
- TLS 1.2/1.3 only, ECDHE key exchange with AES-GCM only (`ssl_ciphers` in `ui/nginx.conf.template`), HSTS 1 year

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

- 172 request rules in 21 categories and 5 response rules in 2, plus 6 heuristics (+ per-request feature-vector profiling)
- Anomaly scoring, dual-scan (raw + decoded). Request bodies are inspected up to 1 MB; a larger body is flagged (`WAF-BODY-OVERSIZE`) and the rest is not inspected
- All inputs validated with max-length constraints
- Circuit breaker protects backend against WAF service failures

### Resilience

- **Circuit breaker**: WAF calls trip after 3 failures, auto-recover after 30s
- **Notification retry**: a delivery is attempted 3 times, with 1 s and then 2 s between attempts
- **Graceful shutdown**: All background workers respond to SIGTERM via context cancellation
- **Atomic file exports**: Temp file + rename pattern prevents torn reads by Squid/dnsmasq

### CI/CD Security

- **gosec**: Automated Go security scanning on every push/PR
- **npm audit**: Frontend dependency vulnerability checking (high severity)
- **Backend tests**: Race detector enabled, 60% coverage threshold enforced
- **Docker build verification**: All 5 images built and verified in CI

## Verifying release images

Every published release image is keyless-signed with cosign by the release
workflow, for a `vX.Y.Z` tag of this repository, after it has been scanned.
Each image also carries a BuildKit SBOM and SLSA build provenance attestation.
Verify an image before trusting it; the identity is anchored, so a signature
made by any other workflow or on any other ref does not match:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/fabriziosalmi/secure-proxy-manager/\.github/workflows/multi-arch\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.14.2

# The SBOM and provenance are BuildKit attestations (not cosign artefacts):
docker buildx imagetools inspect ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.14.2 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.14.2 --format '{{ json .Provenance }}'
```

This needs cosign 3 or later: the release signs with cosign 3, and cosign 2
reports "no signatures found" for these bundles. `deploy/install.sh` runs the
same `cosign verify` on every image when cosign 3+ is installed, and stops if
one fails.

## Security Advisories

Component-specific advisories and how SPM mitigates them, e.g. the Squid
"Squidbleed" FTP-gateway leak (CVE-2026-47729), are tracked in
[docs/guide/security-advisories.md](docs/guide/security-advisories.md).

## Reporting Vulnerabilities

1. **Do NOT** open a public issue
2. Use [GitHub Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new)
3. We respond within 48 hours

## Supported Versions

| Version | Status |
|---------|--------|
| 3.14.x | Current: security fixes are released here |
| < 3.14 | Not supported: upgrade to the latest 3.14.x |
