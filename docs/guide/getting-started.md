# Getting Started

## Prerequisites

- Docker 20.10.0+
- Docker Compose v2 (the `docker compose` plugin)
- `git`

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
```

### 2. Create the `.env` file

Copy the template and edit at minimum the credentials:

```bash
cp .env.example .env
```

Open `.env` and set:

```bash
BASIC_AUTH_USERNAME=your_username
BASIC_AUTH_PASSWORD=your_strong_password
```

::: warning
The containers refuse to start with the bundled placeholder credentials. Replace both values before bringing the stack up.
:::

`SECRET_KEY` is auto-generated on first start when left empty, but tokens are then invalidated on every restart. Set a stable value in production:

```bash
SECRET_KEY=$(openssl rand -hex 32)
```

### 3. Start the services

```bash
docker compose up -d
```

The first build downloads images and compiles the backend, WAF, and UI. Subsequent starts are fast.

### 4. Open the web UI

Open `https://localhost:8443` and accept the self-signed certificate, or `http://localhost:8011` if you do not need TLS to the UI itself. Log in with the credentials from `.env`.

### 5. Configure clients

Set the proxy on your devices to:

- **Host:** the LAN IP of the machine running Secure Proxy Manager
- **Port:** `3128`

For transparent proxying without per-client configuration, see [Transparent Proxy Setup](/guide/security#transparent-proxy).

## Automated installer (Linux)

The repository ships an installer script that clones the project to `/opt/secure-proxy-manager`, installs Docker if missing, generates random credentials, and starts the stack:

```bash
sudo bash deploy/install.sh
```

The script is intended for fresh Linux servers (Debian, Ubuntu, RHEL family). Read the source before running.

## Updating

```bash
git pull
docker compose down
docker compose build --no-cache
docker compose up -d
```

## Verifying the installation

```bash
# All services running and healthy
docker compose ps

# Backend health (localhost only)
curl -k https://localhost:8443/health

# Test proxy connectivity
curl -x http://localhost:3128 http://example.com
```

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Web UI not reachable | Port 80/443/8011/8443 already in use | `docker compose logs web` and free the port |
| Authentication failing | `.env` not present or placeholder credentials in use | Set `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD`, then `docker compose up -d` |
| Proxy not filtering | Client not configured to use port 3128 | Verify the client points to `<host>:3128` |
| TLS warning when filtering HTTPS | SSL bump CA not installed on the client | Download the CA via the UI (Security → Download CA) and trust it |
| Permission errors on `./config`, `./data`, `./logs` | Directories owned by another user | `sudo chown -R $USER:$USER config data logs` |
