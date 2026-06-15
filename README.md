# Secure Proxy Manager

A self-hosted forward proxy with a web UI for filtering, inspecting, and logging
outbound HTTP/HTTPS traffic on a network. It combines a Squid proxy, a custom
WAF, a DNS sinkhole, and a management API into a single Docker Compose stack.

Use it to give a home, lab, or small-office network one controllable egress
point: block domains and IPs, inspect requests against WAF rules, sinkhole
malware/ad domains at the DNS layer, and see what every client is reaching.

![Dashboard](docs/screenshots/dashboard.png)

## What it is

The stack is five containers (plus an optional sixth):

| Service | Tech | Role |
|---------|------|------|
| `web` | React 19 + Vite, served by nginx | The management UI and HTTPS entry point. Terminates TLS, proxies the API and WebSocket. |
| `backend` | Go (chi, modernc/sqlite, JWT) | REST API, log ingestion, settings, auth, background workers. ~20 MB RAM. |
| `waf` | Go ICAP service | Inspects proxied requests/responses Squid hands off over ICAP. |
| `proxy` | Squid (Ubuntu 22.04, `squid-openssl`) | The actual forward proxy on port 3128, with ICAP wired to the WAF. |
| `dns` | dnsmasq | DNS resolver that sinkholes blacklisted domains at the network layer. |
| `tailscale` | Tailscale (optional) | Sidecar for remote access over a private network. Enabled with a compose profile. |

The backend talks to Squid and dnsmasq through the Docker Engine API to apply
blacklist and config changes without restarting the host.

## Quick start

Requirements: Docker 20.10+ with Compose v2, ~512 MB RAM, ~2 GB disk. Runs on
x86_64 and ARM64.

**One command (fresh VPS or server):**

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

The installer checks for Docker, generates random admin credentials, builds the
images, and starts the stack. It prints the credentials at the end.

**Manual:**

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
cp .env.example .env
# Set a strong BASIC_AUTH_PASSWORD in .env (the backend refuses to start with an
# empty, common, or <8-char password). Leave SECRET_KEY empty to auto-generate.
docker compose up -d --build
```

Then open <https://localhost:8443> and accept the self-signed certificate. Log in
with the credentials from your `.env` (or the ones the installer printed). On
first login a short wizard helps you pick a starting configuration.

To send traffic through the proxy, point a client at `http://<host>:3128`
(Settings > Client Setup generates per-OS instructions and a PAC file).

## Ports

| Port | Service | Notes |
|------|---------|-------|
| 443, 8443 | Web UI (HTTPS) | Main interface. 8443 is the same UI on an alternate port. |
| 80, 8011 | HTTP | Redirects to HTTPS; also serves ACME challenges for Let's Encrypt. |
| 3128 | Proxy | Point clients here. Only RFC1918/localhost sources are allowed by default. |
| 5001 | Backend API | Bound to `127.0.0.1` on the host; the UI proxies it internally. |

## Configuration

All configuration is environment-driven via `.env` (see `.env.example` for the
full list with comments). The essentials:

| Variable | Default | Purpose |
|----------|---------|---------|
| `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` | required | Admin login. The backend refuses to start if the password is empty, a common default, or shorter than 8 characters. |
| `SECRET_KEY` | auto-generated | JWT signing secret. Leave empty to generate and persist one. If set, it must be unique, random, and 32+ chars; known/example values are rejected at startup. |
| `LETSENCRYPT_DOMAIN` / `LETSENCRYPT_EMAIL` | empty | Set both to obtain a real certificate via certbot instead of the self-signed one. |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:8443` | Allowed UI origin(s). |
| `DNS_UPSTREAM_1..3` | malware-blocking resolvers | Upstream DNS for dnsmasq. Override to use your own (e.g. Pi-hole). |
| `PROXY_IP` | empty | Your LAN IP, to enable WPAD auto-discovery (`wpad.dat`) for browsers. |
| `WAF_BLOCK_THRESHOLD` | `10` | Anomaly score at which a request is blocked (lower is stricter). |
| `WAF_FAIL_OPEN` | `0` | If the WAF handler errors, block (`0`, fail-closed) or allow (`1`) the request. |

Most runtime behaviour (WAF categories, blocklists, filtering toggles,
notifications) is managed from the UI and stored in the database, not in `.env`.

## Features

**Filtering**
- Domain and IP blacklists and whitelists, managed in the UI or via the API,
  importable from URLs or pasted content (with CIDR support for IPs).
- DNS sinkholing of blacklisted domains via dnsmasq, so blocked lookups never
  reach the proxy at all.
- Direct-IP-access blocking and a method whitelist in Squid.
- Optional default-deny egress (off by default): instead of the deny-list
  blacklists, allow outbound traffic only to an explicit CIDR/domain allowlist
  and refuse everything else. Toggled in Settings; destinations managed on the
  Egress Allowlist page.

**WAF**
- 175 regex rules across 23 toggleable categories (SQLi, XSS, traversal, C2,
  data-loss, etc.), each enableable/disableable at runtime.
- 7 behavioural heuristics (entropy, beaconing, PII, sharding, morphing,
  ghosting, sequence) plus DGA detection (bigram + entropy), typosquatting
  detection (edit distance + homoglyphs), and a safe-URL fast-path cache.
- Anti-evasion input normalization and anomaly scoring; fails closed on internal
  errors by default.

**HTTPS inspection (optional)**
- HTTPS is tunnelled via `CONNECT` by default - the WAF sees connection metadata
  (host, port), not request contents.
- Enabling SSL-bump in Settings makes Squid intercept TLS with a locally
  generated CA so the WAF can inspect decrypted requests. This requires
  installing the generated CA (Settings > download CA) on every client that
  should trust it. The CA is generated per deployment at first boot.

**Operations**
- Live dashboard, per-client drill-down, searchable access logs, and an audit
  log of configuration changes.
- Prometheus metrics from the WAF at `:8080/metrics` (aggregate counters only).
- Notifications to a custom webhook, Gotify, Telegram, or Microsoft Teams, with
  retry and backoff.
- WebSocket log streaming, JWT auth with a persistent revocation list, per-IP
  rate limiting, and AES-256-GCM encryption of sensitive settings at rest.
- Optional Let's Encrypt, WPAD/PAC client auto-config, and a Tailscale sidecar.

## Using it

**Point a client at the proxy.** Set the HTTP/HTTPS proxy to `http://<host>:3128`
on the device, or use the PAC file / WPAD auto-discovery from Settings > Client
Setup. Only RFC1918 and localhost sources are permitted by default.

**Block a domain.** Blacklists > Domains > add `example.com`. The change is
exported to Squid and dnsmasq within a couple of seconds. Whitelists take
precedence.

**Inspect HTTPS.** Settings > enable SSL inspection, download the generated CA,
and install it as trusted on your clients. Without this, HTTPS requests are only
filtered by host/IP and DNS, not by WAF body rules.

**Lock egress to an allowlist.** Settings > enable default-deny egress, then add
the approved IPs/CIDRs and domains on the Egress Allowlist page. Local clients
can then reach only those destinations; everything else is refused.

**Import a blocklist.** Blacklists > Import supports popular public lists by URL
or pasted content. Imports are size-bounded and fetched with an SSRF-safe client
that refuses private/internal targets.

## Updating

```bash
cd secure-proxy-manager
git pull
docker compose up -d --build
```

Your `.env`, database, and blacklists live in bind-mounted volumes and are
preserved across updates. The backend checks GitHub for newer releases and shows
a badge in the UI when one is available.

## Backup and restore

The database (`data/`), config (`config/`), and `.env` hold all state.

```bash
docker compose down
cp data/proxy_manager.db proxy_manager.db.bak
tar czf config.bak.tgz config/ .env
docker compose up -d
```

The UI also offers a config export/import under Settings, and the database can be
exported via the API.

## Health and testing

```bash
# Service health
curl -skI https://localhost:8443/            # UI
curl -I http://127.0.0.1:5001/health         # backend API (localhost only)

# Proxy a request
curl -x http://localhost:3128 -I http://example.com

# End-to-end suite (service health, proxy egress, blocking, log pipeline)
bash tests/ci-e2e.sh
```

Go unit tests: `cd backend-go && go test ./...` and `cd waf-go && go test ./...`.
UI tests: `cd ui && npm test`. A local pre-commit check that runs TypeScript,
ESLint, Go vet/test, and the UI build is at `scripts/pre-commit-validate.sh`.

## Troubleshooting

- **Backend container won't start** - check `docker compose logs backend`. The
  most common cause is an empty/weak `BASIC_AUTH_PASSWORD` or a known/short
  `SECRET_KEY`; both are rejected by design.
- **Can't reach the UI** - it is HTTPS on 8443 with a self-signed cert; accept
  the certificate, or use `https://localhost:8443` (not `http://...:8011`).
- **Clients aren't being filtered** - confirm the device's proxy is set to
  `:3128` and the source IP is RFC1918/localhost (other sources are denied).
- **HTTPS isn't inspected** - that is the default; enable SSL-bump and install
  the CA to inspect request contents.

## API

The backend exposes a REST API (77 routes) used by the UI. A machine-readable
listing is available at `GET /api/docs`. Authenticate with HTTP Basic auth, or
exchange credentials at `POST /api/auth/login` for a JWT and send it as a Bearer
token.

## Architecture and deployment docs

- [DEPLOYMENT.md](DEPLOYMENT.md) - step-by-step deployment, reverse-proxy and
  TLS setup, resource tuning.
- [SECURITY.md](SECURITY.md) - security model and how to report issues.
- [BENCHMARKS.md](BENCHMARKS.md) - reproducible performance and detection
  benchmarks.
- [CHANGELOG.md](CHANGELOG.md) - release history.

## Security notes

- The SSL-bump CA is generated per deployment at first boot and never committed;
  treat the private key under `config/` as sensitive and never share it.
- Set strong admin credentials. The proxy only accepts RFC1918/localhost clients
  by default - if you expose port 3128 publicly, put it behind authentication or
  a private network (e.g. the Tailscale sidecar).
- Sensitive settings (webhook URLs, tokens) are encrypted at rest; JWT secrets
  and the encryption key are generated and persisted under `data/`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests are welcome.

## License

[MIT](LICENSE).
