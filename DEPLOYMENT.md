# Secure Proxy Manager — Deployment Guide

Practical instructions for deploying **Secure Proxy Manager v3.8.0** with Docker
Compose. The stack is a set of Go and container services orchestrated by
`docker-compose.yml`:

| Service | Image / tech | Role |
|---------|--------------|------|
| `backend` | Go (chi) + modernc/sqlite (WAL) | REST/WebSocket API, auth, database |
| `web` | nginx | Serves the UI and reverse-proxies the backend |
| `proxy` | Squid (`squid-openssl`, Ubuntu) | The forward proxy on `3128`, ICAP-wired to the WAF |
| `waf` | Go | ICAP WAF that Squid calls to inspect requests |
| `dns` | dnsmasq | DNS resolver / sinkhole for blacklisted domains |
| `tailscale` | Tailscale (optional) | Remote-access sidecar, enabled via a compose profile |

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Services and Ports](#services-and-ports)
- [Configuration](#configuration)
- [Volumes and Persistence](#volumes-and-persistence)
- [HTTPS and the SSL-Bump CA](#https-and-the-ssl-bump-ca)
- [Backups](#backups)
- [Updating](#updating)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- **Docker**: 20.10.0 or higher — https://docs.docker.com/get-docker/
- **Docker Compose v2**: the `docker compose` plugin (not the legacy
  `docker-compose` binary) — https://docs.docker.com/compose/install/
- **System**: ~512 MB RAM and ~2 GB disk to start; more headroom is recommended
  if you enable the Squid disk cache and verbose logging. Runs on x86_64 and
  ARM64.

Verify your environment:

```bash
docker --version
docker compose version
docker ps          # confirms the daemon is running
```

## Quick Start

### One command (fresh VPS or server)

`deploy/install.sh` checks for Docker, clones the repo to
`/opt/secure-proxy-manager`, generates a `.env` with random admin credentials
and a strong `SECRET_KEY` (`openssl rand -hex 32`), builds the images, and
starts the stack. It prints the credentials at the end — **save them, they are
not shown again.**

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

### Manual

```bash
# 1. Clone
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager

# 2. Create your .env
cp .env.example .env

# 3. Set credentials in .env (see notes below), then:
docker compose up -d --build

# 4. Watch it come up
docker compose logs -f
```

A `Makefile` wraps the common commands: `make setup` creates `.env` and the
`data/`, `logs/`, `config/` directories; `make start` runs
`docker compose up -d --build`; `make stop`, `make restart`, `make logs`, and
`make clean` (`down -v`, your `./data` is preserved) round it out.

> **Required before first start:** set `BASIC_AUTH_USERNAME` and
> `BASIC_AUTH_PASSWORD` in `.env`. The backend **refuses to start** if the
> password is empty, a common default (`changeme`, `admin`, `password`,
> `secret`, …), or shorter than 8 characters. There is **no** `admin/admin`
> fallback. Leave `SECRET_KEY` empty to have a strong one auto-generated and
> persisted under `./data` (see [Configuration](#configuration)).

### Access the UI

Open <https://localhost:8443> and accept the self-signed certificate. Plain
`http://localhost:8011` (and host port `80`) redirect to HTTPS. Log in with the
credentials from your `.env` (or the ones the installer printed).

### Point a client at the proxy

- **Host**: `localhost` (or the server's IP) **Port**: `3128` **Protocol**: HTTP
- Only RFC1918/localhost sources are allowed by default; widen this with
  `GUI_IP_WHITELIST` or in the UI.
- Settings → Client Setup generates per-OS instructions and a PAC file.

Test it:

```bash
curl -x http://localhost:3128 http://example.com
docker compose logs proxy | tail -n 20
```

## Services and Ports

Host port mappings come straight from `docker-compose.yml`:

| Host binding | Container | Service | Notes |
|--------------|-----------|---------|-------|
| `443` → `8443`, `8443` → `8443` | `web` | Web UI (HTTPS) | Main interface; `8443` is the same UI on an alternate port |
| `80` → `8011`, `8011` → `8011` | `web` | Web UI (HTTP) | Redirects to HTTPS; also serves ACME challenges for Let's Encrypt |
| `127.0.0.1:5001` → `5000` | `backend` | Backend API | Bound to localhost only; the UI proxies it (incl. WebSocket) internally |
| `${PROXY_BIND_IP:-0.0.0.0}:3128` → `3128` | `proxy` | Forward proxy | Point clients here |
| — (internal) | `waf` | WAF | `1344` (ICAP, Squid → WAF) and `8080` (health / `:8080/metrics`) — **not** published on the host |
| — (internal) | `dns` | dnsmasq | Port `53` inside the `proxy-internal` network; not published on the host |

Networks: `frontend` (bridge, has egress) and `proxy-internal`
(`internal: true`, no gateway). `proxy` and `dns` attach to **both** so they can
reach the internet/upstream resolvers.

To change a published port, edit the `ports:` entry in `docker-compose.yml`,
e.g. `- "9443:8443"`.

## Configuration

All runtime configuration is environment-driven via `.env` (copy from
`.env.example`). Backend defaults are defined in
`backend-go/internal/config/config.go`.

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `BASIC_AUTH_USERNAME` | **required** | Admin login username |
| `BASIC_AUTH_PASSWORD` | **required** | Admin login password. Rejected at startup if empty, a common default, or < 8 chars |
| `SECRET_KEY` | auto-generated | JWT signing secret. Leave empty to generate and persist one under `./data/.jwt_secret`. If you set it, it must be unique, random, and 32+ chars (`openssl rand -hex 32`); known/example values are rejected at startup |

Generate strong values:

```bash
openssl rand -hex 32   # password and/or SECRET_KEY
```

### Network / proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://backend:5000` | Internal backend URL used by `web` (Docker network) |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:8443` | Allowed UI origin(s); add your domain when using Let's Encrypt |
| `PROXY_HOST` | `proxy` | Proxy service hostname (internal) |
| `PROXY_PORT` | `3128` | Proxy service port |
| `PROXY_CONTAINER_NAME` | `secure-proxy-manager-proxy` | Container name used for reload signals |
| `PROXY_BIND_IP` | `0.0.0.0` | Host interface the proxy port binds to |
| `GUI_IP_WHITELIST` | empty | Extra source IP(s) allowed to use the proxy |
| `PROXY_IP` | empty | Your LAN IP, to enable WPAD (`wpad.dat`) auto-discovery for browsers |

### DNS

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_UPSTREAM_1` | `1.1.1.3` | Upstream resolver (malware-blocking by default) |
| `DNS_UPSTREAM_2` | `9.9.9.9` | Upstream resolver |
| `DNS_UPSTREAM_3` | `8.8.8.8` | Upstream resolver |

### WAF

| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_BLOCK_THRESHOLD` | `10` | Anomaly score at which a request is blocked (lower is stricter) |
| `WAF_DISABLED_CATEGORIES` | empty | Comma-separated rule categories to disable |
| `WAF_H_ENTROPY`, `WAF_H_BEACONING`, `WAF_H_PII`, `WAF_H_SHARDING`, `WAF_H_GHOSTING`, `WAF_H_SEQUENCE` | per compose | Heuristic engine toggles (`1`/`0`) |

Most runtime behaviour (WAF categories, blocklists, filtering toggles,
notifications) is managed from the UI and stored in the database, not in `.env`.

### HTTPS / Let's Encrypt

| Variable | Default | Description |
|----------|---------|-------------|
| `LETSENCRYPT_DOMAIN` | empty | Set with `LETSENCRYPT_EMAIL` to obtain a real cert via certbot instead of the self-signed one |
| `LETSENCRYPT_EMAIL` | empty | Contact email for ACME |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `TS_AUTHKEY` | empty | Tailscale auth key; the `tailscale` service runs only under its compose profile (`docker compose --profile tailscale up -d`) |
| `REQUEST_TIMEOUT` | `120` | UI → backend request timeout (seconds) |

## Volumes and Persistence

Bind mounts (created in the repo root; `make setup`/the installer create them):

```
secure-proxy-manager/
├── config/                  # Config + TLS material (mounted into proxy/waf/dns)
│   ├── ssl_cert.pem         # SSL-bump CA cert — generated at first boot (gitignored)
│   ├── ssl_key.pem          # SSL-bump CA key  — generated at first boot (gitignored)
│   ├── ssl_db/              # Squid generated-cert DB (gitignored)
│   ├── ip_blacklist.txt     # Optional seed lists copied into Squid at startup
│   └── domain_blacklist.txt
├── data/                    # Persistent state
│   ├── proxy_manager.db     # SQLite database (created automatically)
│   ├── .jwt_secret          # Auto-generated JWT secret (if SECRET_KEY unset)
│   └── .enc_key             # Auto-generated key for encrypted settings
├── logs/                    # Access log + Squid logs (mounted into backend/proxy)
├── .env                     # Your environment (you create this)
├── docker-compose.yml
└── Makefile
```

Named Docker volumes (managed by Compose):

| Volume | Used by | Purpose |
|--------|---------|---------|
| `squid-cache` | `proxy` | Squid disk cache (`/var/spool/squid`) |
| `letsencrypt` | `web` | Persisted Let's Encrypt certificates |
| `tailscale-data` | `tailscale` | Tailscale node state |

The database is `data/proxy_manager.db` (config default `DATABASE_PATH`
`/data/proxy_manager.db`). Back up `./data` and `./config` to preserve all state
and the SSL-bump CA. `docker compose down -v` removes the named volumes (cache,
letsencrypt) but **not** the bind mounts; `make clean` does the same and reminds
you `./data` is preserved.

## HTTPS and the SSL-Bump CA

There are two distinct TLS surfaces:

1. **Web UI TLS.** `web` serves HTTPS on `8443`/`443` with a self-signed cert by
   default. Set `LETSENCRYPT_DOMAIN` + `LETSENCRYPT_EMAIL` (and a public
   domain + reachable port `80`) to get a real certificate via certbot; certs
   persist in the `letsencrypt` volume.

2. **Proxy SSL-bump CA.** When SSL-bump is enabled (Settings), Squid intercepts
   TLS using a locally generated CA so the WAF can inspect decrypted requests.
   `proxy/startup.sh` generates `config/ssl_cert.pem` and `config/ssl_key.pem`
   on first boot if they are absent (2048-bit RSA, 10-year cert) and initializes
   `config/ssl_db/`. These files are **gitignored** (`config/*.pem`,
   `config/ssl_db/`) and are **never committed** — each deployment has its own
   unique CA. The startup script additionally detects and deletes a
   known-compromised CA key that was historically committed, regenerating a
   fresh one.

   To inspect HTTPS on clients, install the generated CA (Settings → download CA)
   on every device that should trust the bump. Without SSL-bump, HTTPS is
   tunnelled via `CONNECT` and the WAF only sees connection metadata.

## Backups

The database holds all configuration, blocklists, logs, and audit history.

- **From the UI:** Settings → Maintenance → Backup, which calls the
  `GET /api/database/export` endpoint and downloads a JSON export of the
  database tables. `GET /api/maintenance/backup-config` exports the
  configuration separately. Both require authentication.
- **From the host (cold copy):** stop the stack and archive the bind mounts:

  ```bash
  docker compose down
  tar -czf spm-backup-$(date +%Y%m%d).tar.gz data/ config/
  docker compose up -d
  ```

  Restore by extracting the archive back over `data/` and `config/` before
  `docker compose up -d`.

Schedule the cold copy with cron if desired:

```bash
# Daily at 02:00
0 2 * * * cd /opt/secure-proxy-manager && tar -czf /backups/spm-$(date +\%Y\%m\%d).tar.gz data config
```

## Updating

```bash
# 1. Back up first (see above)
cp -r data data.backup && cp -r config config.backup

# 2. Pull the latest code
git pull origin main          # or: deploy/install.sh re-run does a ff-only pull

# 3. Rebuild and restart
docker compose up -d --build

# 4. Verify
docker compose ps
docker compose logs -f
```

The database, generated CA, and named volumes are preserved across updates.

## Troubleshooting

### Cannot reach the web UI

```bash
docker compose ps                 # is `web` (and `backend`) healthy?
docker compose logs web
```

`web` depends on `backend` being healthy. The backend will exit on boot if
`BASIC_AUTH_PASSWORD`/`SECRET_KEY` are invalid — check `docker compose logs
backend` for a fatal message about a weak password or secret.

### Backend won't start

Most often a credential policy failure:

```bash
docker compose logs backend | tail -n 30
grep BASIC_AUTH .env
```

Fix `.env` (password ≥ 8 chars and not a common default; `SECRET_KEY` empty or
32+ random chars) and `docker compose up -d`.

### Proxy not filtering / 502s on upstream fetches

```bash
docker compose logs proxy
docker compose logs waf          # WAF must be healthy; Squid ICAP-calls it
curl -x http://localhost:3128 http://example.com
```

`proxy` depends on both `waf` and `dns` being healthy. It is attached to the
egress-capable `frontend` network as well as `proxy-internal`; if you customise
networking, keep that egress path or every upstream fetch fails.

### Health checks

```bash
curl -sf  http://localhost:8011/health          # web (nginx)
curl -skI https://localhost:8443/                # web over HTTPS
curl -sk  https://localhost:8443/api/health      # backend via the UI proxy
```

The backend's own healthcheck runs `/server -healthcheck` inside the container,
which now probes **readiness** (`/readyz` — pings the database) rather than bare
liveness, so a wedged SQLite surfaces as an unhealthy container. Probe endpoints:

| Endpoint | Meaning |
|----------|---------|
| `/livez`, `/health` | Liveness — process is up (no DB touch). |
| `/readyz`, `/api/ready` | Readiness — DB reachable (`PingContext` + `SELECT 1`); `503` if not. |

### Metrics & observability

The backend and WAF both expose Prometheus metrics on their **internal** ports
(not proxied by nginx, so not reachable from outside the Docker network):

```bash
docker compose exec backend wget -qO- http://localhost:5000/metrics | head   # spm_http_*, spm_db_*, spm_worker_*
docker compose exec waf     wget -qO- http://localhost:8080/metrics | head   # waf_*, waf_reqmod_duration_seconds, waf_trafficlog_*
```

Backend metrics: RED per route (`spm_http_requests_total`,
`spm_http_request_duration_seconds`, `spm_http_requests_in_flight`), DB pool
gauges (`spm_db_connections_*`), worker heartbeats
(`spm_worker_last_success_timestamp_seconds`), plus `go_*`/`process_*`. WAF
metrics add a REQMOD latency histogram and the silent-drop counters
(`waf_trafficlog_enabled`, `waf_trafficlog_dropped_total`,
`waf_notify_dropped_total`).

An opt-in Prometheus + Grafana stack scrapes both:

```bash
docker compose --profile observability up -d
# Prometheus → http://127.0.0.1:9090   Grafana → http://127.0.0.1:3000 (admin / $GRAFANA_ADMIN_PASSWORD)
```

### Logs and shell access

```bash
docker compose logs -f                 # all services
docker compose logs -f backend         # one service (backend|web|proxy|waf|dns)
docker compose logs --tail=100 proxy

docker compose exec backend /bin/sh    # backend/waf are minimal images (sh)
docker compose exec proxy  /bin/bash
```

### Start completely fresh (deletes all data)

```bash
docker compose down -v
rm -rf data logs config/*.pem config/ssl_db
docker compose up -d --build
```

---

**See also:**
- [README.md](README.md) — overview and feature list
- [CHANGELOG.md](CHANGELOG.md) — release history
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guidelines
