# Getting Started

## Prerequisites

- Docker 20.10.0+
- Docker Compose 2.0.0+
- `git`

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
```

### 2. Run the initialization script

```bash
chmod +x init.sh
./init.sh
```

The script:
- Checks Docker and Docker Compose are available
- Creates required directories (`config/`, `data/`, `logs/`)
- Prompts you to set a username and password (no defaults accepted)
- Writes a `.env` file

### 3. Manual setup (alternative)

If you prefer to set up without the script:

```bash
mkdir -p config data logs
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
BASIC_AUTH_USERNAME=your_username
BASIC_AUTH_PASSWORD=your_strong_password
```

### 4. Start the services

```bash
docker-compose up -d
```

### 5. Access the web interface

Open `http://localhost:8011` and log in with the credentials you set in `.env`.

### 6. Configure client devices

Set the proxy server on your devices to:

- **Host**: IP address of the machine running Secure Proxy Manager
- **Port**: `3128`

For transparent proxying (no manual client configuration), see [Transparent Proxy Setup](/guide/security#transparent-proxy).

## Updating

```bash
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Verifying the setup

```bash
# Check all services are running
docker-compose ps

# Test proxy connectivity
curl -x http://localhost:3128 http://example.com

# Check API health
curl http://localhost:8011/health
```

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Web UI not accessible | Port conflict or service not started | `docker-compose logs ui` |
| Authentication failing | Missing `.env` | `cp .env.example .env` then restart |
| Proxy not filtering | Client not configured | Check client proxy settings point to port 3128 |
| SSL certificate warnings | Certificate not trusted by client | Install `config/ssl_cert.pem` on client devices |
| Permission errors | Missing directories | Run `./init.sh` or `mkdir -p config data logs && chmod 755 config data logs` |
