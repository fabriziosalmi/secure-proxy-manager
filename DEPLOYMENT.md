# Secure Proxy Manager: Deployment Guide

How to deploy, update, back up and restore Secure Proxy Manager with Docker
Compose. The services are defined in `docker-compose.yml` (built from this
repository) and `deploy/docker-compose.prod.yml` (release images, used by the
installer):

| Service | Image / tech | Role |
|---------|--------------|------|
| `backend` | Go (chi) + SQLite (WAL) | REST and WebSocket API, authentication, database |
| `web` | nginx | Serves the UI and proxies the backend |
| `proxy` | Squid (`squid-openssl`, Ubuntu 26.04) | The forward proxy on `3128`, calling the WAF over ICAP |
| `waf` | Go | ICAP WAF |
| `dns` | dnsmasq | Squid's resolver and the sinkhole for blocked domains |
| `tailscale` | Tailscale | Optional, under the `tailscale` profile |

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Services and Ports](#services-and-ports)
- [Configuration](#configuration)
- [Volumes and Persistence](#volumes-and-persistence)
- [HTTPS and the SSL-Bump CA](#https-and-the-ssl-bump-ca)
  - [Rotating the SSL-bump CA](#rotating-the-ssl-bump-ca)
- [Backups](#backups)
- [Updating](#updating)
- [Rolling back](#rolling-back)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- **Docker** with the **Compose v2** plugin (`docker compose`, not the legacy
  `docker-compose` binary): <https://docs.docker.com/get-docker/>,
  <https://docs.docker.com/compose/install/>
- The release images are built for `linux/amd64` and `linux/arm64`.
- Memory: the compose files limit the containers to 1,280 MiB together
  (`proxy` 512, `waf` 256, `dns` 256, `backend` 128, `web` 128).

```bash
docker --version
docker compose version
docker ps          # the daemon is running
```

## Quick Start

### Installer (Linux server)

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

`deploy/install.sh`, run as root:

1. installs Docker (`get.docker.com`), the Compose plugin and `git` when they
   are missing;
2. clones the repository to `/opt/secure-proxy-manager`, or on a re-run pulls
   it with `git pull --ff-only`;
3. copies `deploy/docker-compose.prod.yml` to `compose.prod.yml` and selects it
   with `COMPOSE_FILE=compose.prod.yml` in `.env`;
4. on a first run writes `.env` with `BASIC_AUTH_USERNAME=admin`, a random
   20-character password, `SECRET_KEY` and `INTERNAL_ALERT_TOKEN`; on a re-run
   adds `INTERNAL_ALERT_TOKEN` and `COMPOSE_FILE` if `.env` lacks them;
5. pulls the release images (`SPM_IMAGE_TAG`, default the current release) and,
   when cosign 3 or later is installed, verifies their signatures and stops if
   one fails;
6. stops the backend and copies `data/` to `data.bak.<timestamp>` (keeping the
   three newest), checks that the host ports are free, and starts the stack.

The credentials are printed at the end and stay in
`/opt/secure-proxy-manager/.env`.

### From a clone

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
cp .env.example .env
# Set BASIC_AUTH_PASSWORD and INTERNAL_ALERT_TOKEN in .env, then:
docker compose up -d --build
docker compose logs -f
```

The `Makefile` wraps the common commands: `make setup` creates `.env` from
the template (if missing) and the `data/`, `logs/`, `config/` and
`config/dnsmasq.d/` directories; `make start` runs `setup` and
`docker compose up -d --build`; `make stop`, `make restart`, `make logs`,
`make build`; `make clean` runs `docker compose down -v --remove-orphans`,
which removes the named volumes and leaves `./data` in place;
`make adversarial` runs the adversarial test harness.

> **Required before the first start:** set `BASIC_AUTH_PASSWORD` in `.env`.
> The backend exits if it is empty, shorter than 8 characters, or one of
> `changeme`, `password`, `admin`, `secret`, `test`, `12345678`, `qwerty`.
> Leave `SECRET_KEY` empty to have one generated and kept in
> `data/.jwt_secret`.

### Access the UI

Open <https://localhost:8443> (or `https://<host>`) and accept the
self-signed certificate. `http://<host>` and port 8011 redirect to HTTPS.

### Point a client at the proxy

- **Host**: the server's address. **Port**: `3128`. **Protocol**: HTTP.
- The proxy accepts clients from private IPv4 ranges, IPv6 unique-local and
  link-local addresses and localhost; any other source gets a 403 before any
  other rule is evaluated. To admit another source, list it in
  `GUI_IP_WHITELIST` (addresses or CIDRs, comma or space separated). Allowed
  IPs in the UI are destinations, not clients.
- Settings > Overview > Connect a device shows per-platform steps and a PAC
  file.

```bash
curl -x http://localhost:3128 -I http://example.com
docker compose logs proxy | tail -n 20
```

## Services and Ports

From `docker-compose.yml`:

| Host binding | Container port | Service | Notes |
|--------------|----------------|---------|-------|
| `443`, `8443` | `8443` | `web` | HTTPS: the UI and `/api/` |
| `80`, `8011` | `8011` | `web` | Redirects to HTTPS except `/health`, `/wpad.dat`, `/.well-known/acme-challenge/` |
| `127.0.0.1:5001` | `5000` | `backend` | Host only; nginx proxies it, WebSocket included |
| `${PROXY_BIND_IP:-0.0.0.0}:3128` | `3128` | `proxy` | Point clients here |
| none | `1344`, `8080` | `waf` | ICAP, and health, metrics and management |
| none | `53` | `dns` | Squid's resolver |

Networks: `frontend` (bridge, with outbound access) and `proxy-internal`
(`internal: true`, no route out). `backend`, `proxy` and `dns` are on both,
`waf` only on `proxy-internal`, `web` only on `frontend`.

To change a published port, edit the `ports:` entry, for example
`- "9443:8443"`. Port 3128 is also checked by the proxy's health check, so
change only its host side.

## Configuration

`.env` sets the variables the compose file passes to the containers; the full
list, with what each service does with it, is in
[docs/guide/configuration.md](docs/guide/configuration.md). Settings stored in
the database (lists, filtering, inspection, alerts, retention) are edited in
the UI.

## Volumes and Persistence

Bind mounts in the project directory (`make setup` and the installer create
them):

```
secure-proxy-manager/
├── config/        # shared with proxy, waf, dns: exported lists, marker and trigger
│   │              # files, status records, ssl_cert.pem and ssl_key.pem (SSL-bump CA),
│   │              # ssl_db/ (generated certificates)
│   └── dnsmasq.d/ # blocklist.hosts for dnsmasq
├── data/          # backend only: proxy_manager.db, .jwt_secret, .enc_key
├── logs/          # Squid access.log and cache.log, dnsmasq.log
└── .env
```

`config/*.pem` and `config/ssl_db/` are gitignored.

Named volumes:

| Volume | Used by | Purpose |
|--------|---------|---------|
| `squid-cache` | `proxy` | Squid disk cache (`/var/spool/squid`) |
| `waf-traffic` | `waf` | WAF traffic feature log |
| `letsencrypt` | `web` | Mounted at `/etc/letsencrypt`; unused by the shipped image |
| `tailscale-data` | `tailscale` | Tailscale node state |

`docker compose down -v` (and `make clean`) removes the named volumes but not
the bind mounts.

## HTTPS and the SSL-Bump CA

There are two TLS surfaces.

1. **The UI.** `web` serves HTTPS on 8443 (and 443) with a certificate mounted
   at `/etc/nginx/ssl/server.crt` and `/etc/nginx/ssl/server.key`, or with a
   self-signed one it generates at start, valid for 365 days. The image has no
   certbot, so `LETSENCRYPT_DOMAIN` alone does not produce a certificate.
   Alternatively terminate TLS on a reverse proxy in front (see
   [Security](docs/guide/security.md#https-for-the-web-ui)).

2. **The SSL-bump CA.** With Settings > Inspection > Inspect HTTPS traffic on,
   Squid decrypts HTTPS with a local CA so the WAF can inspect requests.
   `proxy/generate_squid_conf.sh` creates `config/ssl_cert.pem` and
   `config/ssl_key.pem` at start when either is missing (RSA 2048, valid 825
   days, the key created under `umask 077`) and initialises `config/ssl_db/`.
   Each deployment has its own CA. The generator also detects the CA key that
   was once committed to this repository, deletes it and generates a new one.

   Install the CA on every client that should be inspected: Settings >
   Inspection > Download the CA certificate (.pem). Without SSL bump, HTTPS is a
   `CONNECT` tunnel and the WAF sees only the destination.

### Rotating the SSL-bump CA

The CA is valid for **825 days**. Rotate it before it expires, and give clients the
new CA before the old one stops working: a device that trusts only the old CA
fails HTTPS inspection from the moment it is replaced.

```bash
# 1. See the subject and the expiry date.
docker compose exec proxy openssl x509 -in /config/ssl_cert.pem -noout -subject -enddate

# 2. Stop the stack and keep the old CA until every client is updated.
docker compose down
mv config/ssl_cert.pem config/ssl_cert.pem.old
mv config/ssl_key.pem  config/ssl_key.pem.old

# 3. Clear the generated-certificate database, which belongs to the old CA.
rm -rf config/ssl_db

# 4. Start. The proxy generates a new CA.
docker compose up -d
docker compose exec proxy openssl x509 -in /config/ssl_cert.pem -noout -enddate

# 5. Install the new CA on every client (Settings > Inspection > Download the CA certificate (.pem)).

# 6. Once every client is updated:
rm config/ssl_cert.pem.old config/ssl_key.pem.old
```

To use a CA of your own instead, put its certificate and key at
`config/ssl_cert.pem` and `config/ssl_key.pem` in step 4.

### Rotating the other two keys

`data/.jwt_secret` rotates cleanly: delete it (or set `SECRET_KEY`) and
restart. Every session ends and users sign in again.

`data/.enc_key` **cannot be rotated without loss.** Nothing re-encrypts the
values it protects, so replacing it leaves every stored alert channel secret
undecryptable; the Settings page marks them as unreadable, and they must be
entered again. If you must replace it: note the alert channel settings first,
delete `data/.enc_key`, restart, and enter them again.

## Backups

The database holds the settings, the lists, the access log and the audit log.

- **From the UI**, Settings > Admin and backup:
  - *Download a backup* saves the settings and the five lists
    (`GET /api/maintenance/backup-config`); *Restore from a file* reads such a
    file back and adds what it holds.
  - *Export the database* downloads every table as JSON
    (`GET /api/database/export`), for analysis; Restore cannot read it.
- **Cold copy from the host.** The database is in WAL mode, so copy it only
  with the backend stopped:

  ```bash
  docker compose stop backend
  tar -czf spm-backup-$(date +%Y%m%d).tar.gz data/ config/
  docker compose start backend
  ```

  To restore, stop the stack, extract the archive over `data/` and `config/`,
  and run `docker compose up -d`.

A daily cold copy from cron, stopping the backend for the copy:

```bash
0 2 * * * cd /opt/secure-proxy-manager && docker compose stop backend && tar -czf /backups/spm-$(date +\%Y\%m\%d).tar.gz data config; docker compose start backend
```

The installer's `data.bak.<timestamp>` copies are restored with
`scripts/restore.sh <backup-dir>`: it checks the copy with
`PRAGMA integrity_check` (`sqlite3` is needed, or `--skip-check`), asks you to
type `restore`, stops the stack, moves the current `data/` aside to
`data.before-restore.<timestamp>`, copies the backup in and starts the stack.
Run without arguments it lists the available copies.

## Updating

**Read the CHANGELOG entry for the version you are moving to first.** Some
releases need a change before they work correctly, listed under **Action
required**; the commands below do not apply it. Upgrading from 3.11.x, for
example, needs `INTERNAL_ALERT_TOKEN` in `.env`.

On an installer host, run `deploy/install.sh` again: it pulls the code and
the images, adds variables an older `.env` lacks, and copies `data/` first.
In a clone:

```bash
# 1. Stop the stack, then back up. A copy of data/ taken while the backend runs
#    is not a consistent snapshot of a WAL-mode database.
docker compose down
cp -a data data.backup && cp -a config config.backup

# 2. Pull the latest code
git pull origin main

# 3. Rebuild and restart
docker compose up -d --build

# 4. Verify
docker compose ps
docker compose logs -f
```

The database, the generated CA and the named volumes are kept across updates.

## Rolling back

```bash
# 1. Stop, and keep the current state
docker compose down
cp -a data data.failed-upgrade

# 2. Return to the previous release
git checkout v<previous>      # `git tag --list 'v*' | tail -5` lists them

# 3. Restore the data taken before the upgrade
rm -rf data && cp -a data.backup data

# 4. Rebuild and start
docker compose up -d --build
```

**Restore the pre-upgrade data when you roll back.** Besides columns added on
every start, the schema has one-way steps recorded in `PRAGMA user_version`
(at version 6 in this release): table rebuilds, the `list_sources` table, the
rewrite of `*.name` egress entries to `.name`, and the deletion of retired
settings. An older backend does not undo them.

## Troubleshooting

### Cannot reach the web UI

```bash
docker compose ps                 # is web (and backend) healthy?
docker compose logs web
```

`web` waits for `backend` to be healthy, and the backend exits at start on an
invalid `BASIC_AUTH_PASSWORD` or `SECRET_KEY`. A taken host port (80, 443,
8011, 8443) stops `web` from starting.

### Backend does not start

```bash
docker compose logs backend | tail -n 30
grep BASIC_AUTH .env
```

Fix `.env` (password of 8 or more characters and not a common default;
`SECRET_KEY` empty or 32 or more random characters) and run
`docker compose up -d`.

### Proxy not filtering, or 502 on every request

```bash
docker compose logs proxy
docker compose logs waf           # Squid calls the WAF on every request
curl -x http://localhost:3128 -I http://example.com
```

`proxy` starts only when `waf` and `dns` are healthy. It needs the `frontend`
network for outbound access, and `dns` needs it to reach the upstream
resolvers; keep both attachments if you change the networks.

### Health checks

```bash
curl -sf  http://localhost:8011/health          # nginx in web
curl -skI https://localhost:8443/               # web over HTTPS
curl -sk  https://localhost:8443/api/health     # backend through nginx
```

The backend container's health check runs `/server -healthcheck`, which calls
`/readyz`:

| Endpoint | Meaning |
|----------|---------|
| `/livez`, `/health` | The process is up (no database access) |
| `/readyz`, `/api/ready` | The database answers within 2 seconds; `503` otherwise |

### Metrics

The backend and the WAF expose Prometheus metrics on their internal ports; nginx
does not proxy them:

```bash
docker compose exec backend wget -qO- http://localhost:5000/metrics | head   # spm_*, go_*, process_*
docker compose exec waf     wget -qO- http://localhost:8080/metrics | head   # waf_*
```

Backend metrics include `spm_http_requests_total`,
`spm_http_request_duration_seconds`, `spm_http_requests_in_flight`, the
`spm_db_connections_*` pool gauges, `spm_worker_last_success_timestamp_seconds`
and `spm_log_retention_enabled`. Notification metrics include
`spm_notifications_total{channel, outcome}` (`success` and `failure` per
channel, `channel="queue", outcome="dropped"` when the queue is full),
`spm_notification_last_success_timestamp_seconds{channel}` and
`spm_notifications_held_total{reason, channel}`, the alerts the notification
limits held back on purpose: `reason="grouped"` with `channel="all"` for an
alert counted into a digest, `reason="cap"` with the channel that held a
delivery because it reached its hourly limit. WAF metrics include
`waf_reqmod_duration_seconds`, `waf_trafficlog_enabled`,
`waf_trafficlog_dropped_total` and `waf_notify_dropped_total`.

The `observability` profile starts Prometheus (`127.0.0.1:9090`) and Grafana
(`127.0.0.1:3000`; set `GRAFANA_ADMIN_PASSWORD` in `.env` first) with the
configuration in `./infra/`:

```bash
GRAFANA_ADMIN_PASSWORD='<password>' docker compose --profile observability up -d
```

Prometheus (`infra/prometheus/prometheus.yml`) scrapes `backend:5000/metrics`
and `waf:8080/metrics` every 15 seconds and loads the alert rules in
`infra/prometheus/rules/spm.rules.yml` (`SPMTargetDown`,
`SPMBlacklistExportFailed`, `SPMWafReconcileFailed`,
`SPMNotificationDeliveryFailed`, `SPMDatabaseIntegrityFailed`,
`SPMLogRetentionDisabled`). Grafana provisions Prometheus (`http://prometheus:9090`)
as its default datasource from
`infra/grafana/provisioning/datasources/prometheus.yml`.

### Logs and shell access

```bash
docker compose logs -f                 # all services
docker compose logs -f backend         # one service (backend|web|proxy|waf|dns)
docker compose logs --tail=100 proxy

docker compose exec backend /bin/sh    # backend and waf images have sh
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
- [README.md](README.md): overview
- [CHANGELOG.md](CHANGELOG.md): release history
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution guidelines
