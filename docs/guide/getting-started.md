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
`yum`) when they are missing, clones the repository to
`/opt/secure-proxy-manager` whatever directory you run it from, and writes a
`.env` with the user `admin`, a random password, `SECRET_KEY` and
`INTERNAL_ALERT_TOKEN`. It uses the production compose file
(`deploy/docker-compose.prod.yml`, copied to `compose.prod.yml`), checks that
the host ports are free, pulls the release images and starts the stack. The
credentials are printed at the end and stay in `/opt/secure-proxy-manager/.env`.
Read the script before you run it.

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

The first run builds the backend, WAF, UI, proxy and dns images.

### 4. Open the web UI

Open `https://localhost:8443` (or `https://<host>`) and accept the
self-signed certificate. Plain HTTP on ports 80 and 8011 redirects to HTTPS.
Sign in with the credentials from `.env`; the first sign-in opens a setup
wizard.

### 5. Configure clients

Set the proxy on each device to:

- **Host:** the LAN address of the machine running Secure Proxy Manager
- **Port:** `3128`

Settings > Overview > Connect a device shows the steps per platform and a PAC
file. The proxy accepts clients from private IPv4 ranges, IPv6 unique-local
and link-local addresses and localhost; `GUI_IP_WHITELIST` admits other
sources. Transparent interception is not supported (see
[Transparent proxy](/guide/security#transparent-proxy)).

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

On a host installed with `install.sh`, run the installer again: it pulls the
new release and adds variables an older `.env` lacks. See
[DEPLOYMENT.md](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/DEPLOYMENT.md#updating).

## Metrics

The backend and the WAF expose Prometheus metrics on their internal ports;
nginx does not proxy them:

```bash
docker compose exec backend wget -qO- http://localhost:5000/metrics | head
docker compose exec waf     wget -qO- http://localhost:8080/metrics | head
```

The compose files also define an `observability` profile (Prometheus and
Grafana), but the configuration it mounts from `./infra/` is not in the
repository. Started as shipped, Docker creates
`infra/prometheus/prometheus.yml` as an empty directory and the Prometheus
container fails with "Are you trying to mount a directory onto a file".

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| The UI is not reachable | A host port (80, 443, 8011, 8443) is taken | `docker compose logs web`; free the port or change the host side of the mapping |
| The backend exits at start | Empty or weak `BASIC_AUTH_PASSWORD`, or a weak `SECRET_KEY` | `docker compose logs backend`, fix `.env`, `docker compose up -d` |
| Requests are not filtered | The client does not use the proxy | Point the client at `<host>:3128` |
| Clients are refused with 403 by every site | The client address is not a private or localhost source | Add it to `GUI_IP_WHITELIST` |
| TLS warnings with HTTPS inspection on | The client does not trust the proxy CA | Settings > Inspection > Download the CA certificate (.pem), then install it on the client |
| The dashboard shows no WAF statistics | `INTERNAL_ALERT_TOKEN` is not set on both `waf` and `backend` | Set it in `.env` and run `docker compose up -d` |
