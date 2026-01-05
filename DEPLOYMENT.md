# Secure Proxy Manager - Deployment Guide

This guide provides detailed instructions for deploying Secure Proxy Manager using Docker Compose.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Step-by-Step Deployment](#step-by-step-deployment)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)
- [Updating](#updating)

## Prerequisites

Before you begin, ensure you have the following installed:

- **Docker**: Version 20.10.0 or higher
  - Install: https://docs.docker.com/get-docker/
- **Docker Compose**: Version 2.0.0 or higher
  - Install: https://docs.docker.com/compose/install/
- **System Requirements**:
  - Minimum: 1 CPU core, 1GB RAM, 5GB disk space
  - Recommended: 2+ CPU cores, 4GB+ RAM, 20GB+ disk space

### Verify Installation

```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker-compose --version
# or
docker compose version

# Verify Docker is running
docker ps
```

## Quick Start

If you want to get up and running quickly with default settings:

```bash
# 1. Clone the repository
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager

# 2. Run the initialization script
chmod +x init.sh
./init.sh

# 3. Start the services
docker-compose up -d

# 4. Check the logs
docker-compose logs -f

# 5. Access the web interface
# Open your browser to: http://localhost:8011
# Default credentials: admin / admin
```

**⚠️ Important**: The default credentials are `admin` / `admin`. Change these immediately in production!

## Step-by-Step Deployment

### Step 1: Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
```

### Step 2: Prepare the Environment

#### Option A: Using the Initialization Script (Recommended)

The initialization script will create all necessary directories and files:

```bash
chmod +x init.sh
./init.sh
```

This script will:
- Check for Docker and Docker Compose installation
- Create required directories (`config`, `data`, `logs`)
- Create empty blacklist files if they don't exist
- Create a `.env` file from `.env.example` if it doesn't exist
- Set proper permissions

#### Option B: Manual Setup

If you prefer to set up manually:

```bash
# Create required directories
mkdir -p config data logs

# Create empty blacklist files
touch config/ip_blacklist.txt
touch config/domain_blacklist.txt

# Copy the example environment file
cp .env.example .env

# Edit the .env file with your preferred settings
nano .env  # or use your preferred editor
```

### Step 3: Configure Environment Variables

Edit the `.env` file to customize your deployment:

```bash
nano .env
```

**Critical settings to review:**

```bash
# Change these default credentials!
BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=admin

# Generate a strong secret key (optional but recommended)
# Run: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your-generated-secret-key-here

# Set the environment (production for deployment)
FLASK_ENV=production
```

For a complete list of configuration options, see the [Configuration](#configuration) section.

### Step 4: Build and Start the Services

```bash
# Build and start all services in detached mode
docker-compose up -d

# This will:
# 1. Build the Docker images for backend, UI, and proxy services
# 2. Create the necessary volumes
# 3. Start all containers
# 4. Set up the network
```

**First-time startup may take 2-5 minutes** as Docker builds the images and initializes the database.

### Step 5: Verify the Deployment

```bash
# Check the status of all services
docker-compose ps

# All services should show "Up" status:
# - secure-proxy-backend-1
# - secure-proxy-web-1
# - secure-proxy-proxy-1

# View the logs to ensure no errors
docker-compose logs -f

# Press Ctrl+C to exit log view
```

Look for these success messages in the logs:
- Backend: `"Gunicorn is running on http://0.0.0.0:5000"`
- Web UI: `"Running on http://0.0.0.0:8011"`
- Proxy: `"Squid configuration syntax is valid"`

### Step 6: Access the Web Interface

1. Open your web browser and navigate to:
   ```
   http://localhost:8011
   ```

2. Enter your credentials:
   - Username: `admin` (or what you set in `.env`)
   - Password: `admin` (or what you set in `.env`)

3. You should see the Secure Proxy Manager dashboard.

### Step 7: Configure Your Proxy Client

Configure your browser or system to use the proxy:

- **Proxy Host**: `localhost` (or your server's IP address)
- **Proxy Port**: `3128`
- **Protocol**: HTTP

**Example browser configuration:**

**Firefox:**
1. Settings → General → Network Settings → Settings
2. Select "Manual proxy configuration"
3. HTTP Proxy: `localhost`, Port: `3128`
4. Check "Use this proxy server for all protocols"

**Chrome/Edge:**
Use system proxy settings or a proxy extension like SwitchyOmega.

**System-wide (Linux):**
```bash
export http_proxy=http://localhost:3128
export https_proxy=http://localhost:3128
```

### Step 8: Test the Proxy

```bash
# Test HTTP proxy
curl -x http://localhost:3128 http://example.com

# Test with authentication (if you've enabled it)
curl -x http://localhost:3128 -U username:password http://example.com

# Check if a request appears in the logs
docker-compose logs proxy | tail -n 20
```

## Configuration

### Environment Variables

All configuration is done through the `.env` file. Here are the key variables:

#### Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `BASIC_AUTH_USERNAME` | `admin` | Username for web UI and API access |
| `BASIC_AUTH_PASSWORD` | `admin` | Password for web UI and API access |
| `SECRET_KEY` | Auto-generated | Flask session secret (generate with `secrets.token_hex(32)`) |

#### Backend API
| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://backend:5000` | Backend API URL (Docker internal) |
| `REQUEST_TIMEOUT` | `30` | API request timeout in seconds |
| `MAX_RETRIES` | `5` | Maximum API retry attempts |
| `BACKOFF_FACTOR` | `1.0` | Exponential backoff multiplier |

#### Proxy Service
| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_HOST` | `proxy` | Proxy service hostname |
| `PROXY_PORT` | `3128` | Proxy service port |
| `PROXY_CONTAINER_NAME` | `secure-proxy-proxy-1` | Docker container name |

#### Application
| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `production` | Flask environment (`development` or `production`) |

### Directory Structure

After initialization, your directory structure should look like:

```
secure-proxy-manager/
├── config/              # Configuration files
│   ├── ip_blacklist.txt      # IP blacklist (created automatically)
│   ├── domain_blacklist.txt  # Domain blacklist (created automatically)
│   ├── ssl_cert.pem          # SSL certificate (created by proxy)
│   └── ssl_key.pem           # SSL key (created by proxy)
├── data/                # Persistent data
│   └── secure_proxy.db       # SQLite database (created automatically)
├── logs/                # Application logs
│   ├── backend.log           # Backend API logs
│   ├── ui.log                # Web UI logs
│   └── squid/                # Proxy logs (mounted from container)
├── .env                 # Environment configuration (YOU MUST CREATE THIS)
├── .env.example         # Example environment file
├── docker-compose.yml   # Docker Compose configuration
├── init.sh              # Initialization script
└── README.md            # Main documentation
```

### Port Mappings

| Port | Service | Description |
|------|---------|-------------|
| `8011` | Web UI | Main web interface |
| `5001` | Backend API | Direct API access (optional) |
| `3128` | Proxy | HTTP/HTTPS proxy service |

**To change ports**, edit `docker-compose.yml`:

```yaml
services:
  web:
    ports:
      - "8080:8011"  # Change 8080 to your desired port
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: "Cannot access web UI"

**Symptoms:** Browser shows "connection refused" or timeout when accessing `http://localhost:8011`

**Solutions:**
1. Check if the container is running:
   ```bash
   docker-compose ps
   ```

2. Check the logs for errors:
   ```bash
   docker-compose logs web
   ```

3. Verify port is not in use:
   ```bash
   netstat -an | grep 8011  # Linux/Mac
   # or
   netstat -ano | findstr 8011  # Windows
   ```

4. Try accessing via IP instead of localhost:
   ```bash
   # Find your IP
   ip addr show  # Linux
   ipconfig  # Windows
   
   # Access via IP
   http://YOUR_IP:8011
   ```

#### Issue 2: "Permission denied" errors in logs

**Symptoms:** Log messages about permission denied on `/config`, `/data`, or `/logs`

**Solutions:**
1. Ensure directories exist and have correct permissions:
   ```bash
   mkdir -p config data logs
   chmod 755 config data logs
   ```

2. If on Linux with SELinux enabled:
   ```bash
   chcon -Rt svirt_sandbox_file_t config data logs
   # or disable SELinux (not recommended for production)
   ```

3. Rebuild containers:
   ```bash
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

#### Issue 3: "Authentication failed" errors

**Symptoms:** Cannot login with credentials, or backend/UI communication fails

**Solutions:**
1. Verify credentials in `.env` file:
   ```bash
   cat .env | grep BASIC_AUTH
   ```

2. Ensure the `.env` file is loaded:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

3. Check container environment variables:
   ```bash
   docker-compose exec backend env | grep BASIC_AUTH
   docker-compose exec web env | grep BASIC_AUTH
   ```

4. Reset to default credentials:
   - Edit `.env` and set:
     ```
     BASIC_AUTH_USERNAME=admin
     BASIC_AUTH_PASSWORD=admin
     ```
   - Restart services:
     ```bash
     docker-compose restart
     ```

#### Issue 4: "Database errors"

**Symptoms:** Errors about database lock, corruption, or missing tables

**Solutions:**
1. Stop all services:
   ```bash
   docker-compose down
   ```

2. Check database file permissions:
   ```bash
   ls -la data/secure_proxy.db
   ```

3. If corrupt, remove and recreate:
   ```bash
   # Backup first!
   cp data/secure_proxy.db data/secure_proxy.db.backup
   
   # Remove database
   rm data/secure_proxy.db
   
   # Restart to recreate
   docker-compose up -d
   ```

#### Issue 5: "Proxy not filtering traffic"

**Symptoms:** Requests are not logged, blacklists not working

**Solutions:**
1. Verify proxy is running:
   ```bash
   docker-compose logs proxy
   ```

2. Test proxy connectivity:
   ```bash
   curl -x http://localhost:3128 http://example.com
   ```

3. Check blacklist files are loaded:
   ```bash
   docker-compose exec proxy cat /etc/squid/blacklists/ip/local.txt
   docker-compose exec proxy cat /etc/squid/blacklists/domain/local.txt
   ```

4. Reload proxy configuration:
   ```bash
   docker-compose restart proxy
   ```

### Viewing Logs

```bash
# View logs for all services
docker-compose logs -f

# View logs for a specific service
docker-compose logs -f backend
docker-compose logs -f web
docker-compose logs -f proxy

# View last 100 lines
docker-compose logs --tail=100 backend

# Save logs to file
docker-compose logs > deployment.log
```

### Getting Container Shell Access

```bash
# Access backend container
docker-compose exec backend /bin/bash

# Access web container
docker-compose exec web /bin/bash

# Access proxy container
docker-compose exec proxy /bin/bash
```

### Completely Resetting the Deployment

If you need to start fresh:

```bash
# WARNING: This will delete all data!

# Stop and remove containers, volumes, and networks
docker-compose down -v

# Remove local data
rm -rf data logs

# Recreate directories
mkdir -p config data logs

# Start fresh
docker-compose up -d
```

## Production Deployment

For production deployments, follow these additional steps:

### 1. Change Default Credentials

Edit `.env` and set strong credentials:

```bash
BASIC_AUTH_USERNAME=your_secure_username
BASIC_AUTH_PASSWORD=your_strong_password_here
```

Generate a strong password:
```bash
openssl rand -base64 32
```

### 2. Generate Secret Key

```bash
# Generate a secret key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
SECRET_KEY=your_generated_key_here
```

### 3. Enable HTTPS for Web UI

Use a reverse proxy (nginx, Traefik, or Caddy) with SSL/TLS:

**Example nginx configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8011;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4. Restrict Access

Use firewall rules to restrict access to the web UI:

```bash
# Allow only specific IP
sudo ufw allow from YOUR_IP to any port 8011

# Or use nginx IP restrictions
# In your nginx config:
allow YOUR_IP;
deny all;
```

### 5. Set Up Backups

Create a backup script:

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/secure-proxy"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Stop services
docker-compose down

# Backup data
tar -czf "$BACKUP_DIR/data-$TIMESTAMP.tar.gz" data/
tar -czf "$BACKUP_DIR/config-$TIMESTAMP.tar.gz" config/
tar -czf "$BACKUP_DIR/logs-$TIMESTAMP.tar.gz" logs/

# Start services
docker-compose up -d

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

Schedule with cron:
```bash
# Run daily at 2 AM
0 2 * * * /path/to/backup.sh
```

### 6. Set Resource Limits

Edit `docker-compose.yml` to adjust resource limits based on your hardware:

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'        # Adjust based on available CPU
      memory: 2048M      # Adjust based on available RAM
    reservations:
      cpus: '0.5'
      memory: 512M
```

### 7. Enable Monitoring

Set up health monitoring:

```bash
# Check health endpoints
curl -I http://localhost:8011/health
curl -I http://localhost:5001/health

# Set up monitoring with tools like:
# - Prometheus + Grafana
# - UptimeRobot
# - Nagios
```

### 8. Regular Updates

Keep the system updated:

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Updating

To update to the latest version:

```bash
# 1. Backup your data first!
cp -r data data.backup
cp -r config config.backup

# 2. Pull latest changes
git pull origin main

# 3. Rebuild containers
docker-compose down
docker-compose build --no-cache

# 4. Start with new version
docker-compose up -d

# 5. Verify everything works
docker-compose logs -f
```

## Getting Help

If you encounter issues not covered in this guide:

1. **Check the logs**: Most issues are logged with helpful error messages
2. **Search existing issues**: https://github.com/fabriziosalmi/secure-proxy-manager/issues
3. **Create a new issue**: Include logs, your environment, and steps to reproduce
4. **Review the main README**: https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/README.md

---

**For more information, see:**
- [README.md](README.md) - Main documentation
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [CHANGELOG.md](CHANGELOG.md) - Version history
