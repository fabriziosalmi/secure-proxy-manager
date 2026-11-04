# Getting Started

## Prerequisites

- Docker with the Compose v2 plugin (the `docker compose` command)
- `git`, to install from a clone

## Option 1: the installer (Linux server)

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

`deploy/install.sh` must run as root. It installs Docker (through
`get.docker.com`) and the Compose plugin and `git` (through `apt-get` or
`yum`) when they are missing, clones the newest release (the highest
`vX.Y.Z` tag, not `main`) to `/opt/secure-proxy-manager` whatever directory
you run it from, and writes a
`.env` with the user `admin`, a random password, `SECRET_KEY` and
`INTERNAL_ALERT_TOKEN`. It uses the production compose file
(`deploy/docker-compose.prod.yml`, copied to `compose.prod.yml`), checks that
the host ports are free, pulls the release images and starts the stack. The
credentials are printed at the end and stay in `/opt/secure-proxy-manager/.env`.
Read the script before you run it. The script itself is read from `main`; to
install a given release, run it with `SPM_VERSION`, for example
`curl -fsSL ... | sudo SPM_VERSION=v3.29.0 bash`.

## Option 2: from a clone

### 1. Clone the repository

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
```

### 2. Create the `.env` file

```bash
cp .env.example .env
```

Open `.env` and set at least:

```bash
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=your_strong_password
INTERNAL_ALERT_TOKEN=output_of_openssl_rand_hex_32
```

::: warning
The backend refuses to start when `BASIC_AUTH_PASSWORD` is empty, shorter than
8 characters, or one of `changeme`, `password`, `admin`, `secret`, `test`,
`12345678`, `qwerty`. The template leaves it empty.
:::

Without `INTERNAL_ALERT_TOKEN` the WAF cannot report blocks to the backend and
refuses the backend's calls for statistics and toggles. Generate it with
`openssl rand -hex 32`.

Leave `SECRET_KEY` empty to have the backend generate one and keep it in
`data/.jwt_secret`, so sessions survive a restart. If you set it, it must be at
least 32 characters and not a known example value.

### 3. Start the services

```bash
docker compose up -d --build
```

The first run builds the backend, WAF, UI, proxy and dns images. To run the
signed release images instead, as the installer does, without building
anything:

```bash
cp deploy/docker-compose.prod.yml compose.prod.yml
docker compose -f compose.prod.yml up -d
```

`compose.prod.yml` pins the release it came with (`SPM_IMAGE_TAG` overrides
it). Keep using `-f compose.prod.yml`, or add `COMPOSE_FILE=compose.prod.yml`
to `.env`, for every later `docker compose` command.

### 4. Open the web UI

Open `https://localhost:8443` (or `https://<host>`) and accept the
self-signed certificate. Plain HTTP on ports 80 and 8011 redirects to HTTPS.
Sign in with the credentials from `.env`; the first sign-in opens a setup
wizard.

### 5. Configure clients

Set the proxy on each device to:

- **Host:** the LAN address of the machine running Secure Proxy Manager
- **Port:** `3128`

Set `PROXY_IP` in `.env` to that address. Settings > Overview > Connect a
device then shows it with the steps per platform, a PAC file and the URL
devices can load it from (`http://<address>/wpad.dat`); without `PROXY_IP` it
shows the host the dashboard was opened on, and warns when that is
`localhost`. The proxy accepts clients from private IPv4 ranges, IPv6 unique-local
and link-local addresses and localhost; `GUI_IP_WHITELIST` admits other
sources. Transparent interception is not supported (see
[Transparent proxy](/guide/security#transparent-proxy)).

#### Servers without a desktop

Programs read the proxy from the environment; apt and the Docker daemon read
their own files. Replace `192.168.1.10` with the server's address. The URL is
`http://` for HTTPS sites too: the proxy speaks plain HTTP and tunnels them.
With the proxy login on, write it as `http://USER:PASSWORD@192.168.1.10:3128`,
with the password URL-encoded.

Every program, from the next login: `/etc/environment` takes one
`NAME=value` per line, without `export`. Some programs read only the
lowercase names and some only the uppercase ones, so set both.

```
http_proxy=http://192.168.1.10:3128
https_proxy=http://192.168.1.10:3128
no_proxy=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
HTTP_PROXY=http://192.168.1.10:3128
HTTPS_PROXY=http://192.168.1.10:3128
NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

apt, in `/etc/apt/apt.conf.d/95proxy`:

```
Acquire::http::Proxy "http://192.168.1.10:3128";
Acquire::https::Proxy "http://192.168.1.10:3128";
```

Docker image pulls, in `/etc/systemd/system/docker.service.d/http-proxy.conf`,
then `sudo systemctl daemon-reload && sudo systemctl restart docker`.
Containers do not inherit it; pass the variables to those that need them.

```
[Service]
Environment="HTTP_PROXY=http://192.168.1.10:3128"
Environment="HTTPS_PROXY=http://192.168.1.10:3128"
Environment="NO_PROXY=localhost,127.0.0.1"
```

A systemd service does not read `/etc/environment`: give it the same
`[Service]` lines with `sudo systemctl edit <service>`, then restart it.

Settings > Overview > Connect a device shows these with the server's address
filled in, under Linux server.

## Verifying the installation

```bash
# Every service running and healthy
docker compose ps

# Backend health through the UI's reverse proxy
curl -sk https://localhost:8443/api/health

# Backend readiness: 200 when the database answers, 503 otherwise
docker compose exec backend wget -qO- http://localhost:5000/readyz

# A request through the proxy
curl -x http://localhost:3128 -I http://example.com
```

`https://localhost:8443/health` is answered by nginx in the `web` container,
not by the backend.

## Updating

Read the CHANGELOG entry for the target version first. Then, in a clone:

```bash
git pull
docker compose up -d --build
```

On a host installed with `install.sh`, run the installer again: it moves the
clone to the newest release, pulls its images and adds variables an older
`.env` lacks. See
[DEPLOYMENT.md](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/DEPLOYMENT.md#updating).

## Metrics

The backend and the WAF expose Prometheus metrics on their internal ports;
nginx does not proxy them:

```bash
docker compose exec backend wget -qO- http://localhost:5000/metrics | head
docker compose exec waf     wget -qO- http://localhost:8080/metrics | head
```

The compose files also define an `observability` profile (Prometheus on
`127.0.0.1:9090` and Grafana on `127.0.0.1:3000`), configured from `./infra/`.
Set `GRAFANA_ADMIN_PASSWORD` in `.env` and start it with:

```bash
docker compose --profile observability up -d
```

Prometheus scrapes `backend:5000/metrics` and `waf:8080/metrics`, evaluates the
alert rules in `infra/prometheus/rules/spm.rules.yml` (`SPMTargetDown`,
`SPMBlacklistExportFailed`, `SPMWAFReconcilePushFailed`,
`SPMNotificationDeliveryFailed`, `SPMDatabaseIntegrityFailed`,
`SPMLogRetentionDisabled`), and Grafana provisions Prometheus as its default
datasource.

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| The UI is not reachable | A host port (80, 443, 8011, 8443) is taken | `docker compose logs web`; free the port or change the host side of the mapping |
| The backend exits at start | Empty or weak `BASIC_AUTH_PASSWORD`, or a weak `SECRET_KEY` | `docker compose logs backend`, fix `.env`, `docker compose up -d` |
| Requests are not filtered | The client does not use the proxy | Point the client at `<host>:3128` |
| Clients are refused with 403 by every site | The client address is not a private or localhost source | Add it to `GUI_IP_WHITELIST` |
| TLS warnings with HTTPS inspection on | The client does not trust the proxy CA | Settings > Inspection > Download the CA certificate (.pem), then install it on the client |
| The dashboard shows no WAF statistics | `INTERNAL_ALERT_TOKEN` is not set on both `waf` and `backend` | Set it in `.env` and run `docker compose up -d` |
