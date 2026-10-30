# Security Policy

## Architecture

As shipped in `docker-compose.yml`. The five core services run with
`no-new-privileges` and a read-only root filesystem (writable paths are tmpfs
or volumes). The optional `tailscale` service has neither.

| Container | Runs as | Capabilities | Notes |
|-----------|---------|--------------|-------|
| backend (Go) | root (the image sets no `USER`) | none (`cap_drop: ALL`) | No Docker socket. Changes reach the proxy and dnsmasq as files in `/config`, which their watchdogs apply |
| waf (Go) | `waf` (UID 1000) | none (`cap_drop: ALL`) | ICAP on 1344 and the management API on 8080, internal network only |
| web (nginx) | master as root, workers as `nginx` | `CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE` | TLS termination, static files, `/api` reverse proxy |
| proxy (Squid) | supervisord and the watchdog as root; Squid as `proxy` | Docker's default set plus `NET_ADMIN` (no `cap_drop`) | `NET_ADMIN` is used for iptables REDIRECT rules; transparent interception is not implemented (no intercept port) |
| dns (dnsmasq) | root (`--user=root`) | `NET_BIND_SERVICE`, `DAC_OVERRIDE` | Squid's resolver, not published on the host |

No container mounts the Docker socket. `./data` (the database, `.jwt_secret`,
`.enc_key`) is mounted in the backend only.

### Authentication

- Admin password stored as a bcrypt hash (Go's default cost, 10). The
  `BASIC_AUTH_PASSWORD` value is compared only while no hash is stored yet.
- JWT access tokens, 8 hours by default, and refresh tokens that end 7 days
  after the login. Revoked tokens are kept in the database and survive a
  restart; a password change invalidates every earlier token.
- Failed Basic logins limited to 5 per client address in 5 minutes.
- Every request limited to 20 per second per client address (burst 60) by the
  backend, and `/api/` to 20 per second (burst 40) by nginx.
- WebSocket: a single-use token offered as a subprotocol, and an `Origin`
  check against `CORS_ALLOWED_ORIGINS` and the page's own host.
- HTTPS for the UI by default: a self-signed certificate valid for 365 days,
  or one mounted at `/etc/nginx/ssl/`.

### Encryption

- Alert channel secrets (webhook URL and bearer token, Gotify URL and token,
  Teams webhook URL, Telegram bot token and chat ID, ntfy URL and topic) are
  stored with AES-256-GCM and are write-only through the API.
- The encryption key is `ENCRYPTION_KEY`, or one generated and kept in
  `data/.enc_key` (mode 0600). The JWT secret is `SECRET_KEY`, or one generated
  and kept in `data/.jwt_secret` (mode 0600).
- UI TLS: TLS 1.2 and 1.3, ECDHE key exchange with AES-GCM ciphers for TLS 1.2
  (`ssl_ciphers` in `ui/nginx.conf.template`), HSTS for one year.

### Content Security Policy

The UI is served by nginx with:

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self' data:;
connect-src 'self'
```

The backend adds its own policy to API responses
(`backend-go/internal/middleware/middleware.go`), which also allows `ws:` and
`wss:` in `connect-src`.

### WAF

- 172 request rules in 21 categories and 5 response rules in 2, plus 6
  heuristics and per-request feature logging.
- Anomaly scoring. The URL is matched both as sent and normalised; headers
  and bodies are matched normalised. Request bodies are
  inspected up to 1 MB; a larger body adds the `WAF-BODY-OVERSIZE` finding and
  the rest is not inspected. Compressed response bodies are not inspected and
  are counted in `waf_respmod_uninspectable_total`.
- REQMOD fails closed: an unreachable WAF blocks requests unless
  `WAF_FAIL_OPEN=1`, and a WAF handler that panics blocks the request.

### Resilience

- **Circuit breaker**: the backend's calls to the WAF management API stop for
  30 seconds after 3 failures.
- **Alert retry**: a delivery is attempted 3 times, with 1 s and then 2 s
  between attempts.
- **Graceful shutdown**: the HTTP server drains first, then the background
  workers stop and are waited for (up to 5 seconds).
- **Atomic file exports**: each list is written to a temporary file, synced
  and renamed, so Squid and dnsmasq never read a partial file.

### CI/CD Security

- **gosec** on both Go modules gates every pull request; **govulncheck**
  reports reachable known vulnerabilities as warnings.
- **npm audit**: HIGH and CRITICAL advisories fail the build unless listed with
  a reason in `scripts/npm-audit-allowlist.json`.
- **Trivy**: fixable HIGH and CRITICAL findings in the dependencies and in the
  third-party images the compose files pin fail the build.
- **Tests**: Go tests with the race detector, with coverage floors of 60%
  (backend) and 70% (WAF).
- **Images**: CI builds the `web`, `backend`, `waf`, `proxy` and `dns` images.

## Verifying release images

Every published release image is keyless-signed with cosign by the release
workflow, for a `vX.Y.Z` tag of this repository, after Trivy has scanned it
for both architectures. Each GHCR image also carries a BuildKit SBOM and SLSA
build provenance attestation. The identity is anchored, so a signature made by
any other workflow or on any other ref does not match:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/fabriziosalmi/secure-proxy-manager/\.github/workflows/multi-arch\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.21.0

# The SBOM and provenance are BuildKit attestations (not cosign artefacts):
docker buildx imagetools inspect ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.21.0 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/fabriziosalmi/secure-proxy-manager-proxy:v3.21.0 --format '{{ json .Provenance }}'
```

This needs cosign 3 or later; `deploy/install.sh` skips the check with a
warning when an older cosign is installed. With cosign 3 or later installed,
the installer runs the same `cosign verify` on every image and stops if one
fails.

## Security Advisories

Component advisories and how SPM mitigates them, such as the Squid
"Squidbleed" FTP-gateway leak (CVE-2026-47729), are in
[docs/guide/security-advisories.md](docs/guide/security-advisories.md).

## Reporting Vulnerabilities

1. **Do not** open a public issue.
2. Use [GitHub Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new).
3. We respond within 48 hours.

## Supported Versions

| Version | Status |
|---------|--------|
| 3.18.x | Current: security fixes are released here |
| < 3.18 | Not supported: upgrade to the latest 3.18.x |
