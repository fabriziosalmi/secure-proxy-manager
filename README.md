# Secure Proxy Manager

A containerized secure proxy with advanced filtering capabilities, real-time monitoring, and a modern web UI.
  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.9+-yellow?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-green?logo=flask)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.0-purple?logo=bootstrap)](https://getbootstrap.com/)

## 🚀 Quick Links

- [**Getting Started**](#-quick-start) - Get up and running in 5 minutes
- [**Deployment Guide**](DEPLOYMENT.md) - Comprehensive step-by-step deployment instructions
- [**API Documentation**](#-api-documentation) - Complete API reference
- [**FAQ**](#-frequently-asked-questions-faq) - Common questions answered
- [**Troubleshooting**](#-troubleshooting) - Solutions to common issues
- [**Contributing**](CONTRIBUTING.md) - How to contribute to the project
- [**Changelog**](CHANGELOG.md) - Version history and updates

## 📑 Table of Contents

- [Screenshots](#screenshots)
- [Features](#-features)
- [Architecture](#️-architecture)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Configuration Options](#️-configuration-options)
- [Advanced Configuration](#️-advanced-configuration)
- [Monitoring and Analytics](#-monitoring-and-analytics)
- [Database Export and Backup](#-database-export-and-backup)
- [Testing and Validation](#-testing-and-validation)
- [FAQ](#-frequently-asked-questions-faq)
- [Troubleshooting](#-troubleshooting)
- [API Documentation](#-api-documentation)
- [Security Best Practices](#-security-best-practices)
- [Future Roadmap](#-future-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgements](#-acknowledgements)
- [Support](#-support)

## Screenshots

![screenshot1](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_1.png?raw=true)
![screenshot2](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_2.png?raw=true)
![screenshot3](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_3.png?raw=true)

## 🌟 Key Features

- **Modern Architecture**: Fast, asynchronous Python backend powered by **FastAPI** with SQLite WAL mode.
- **Real-Time Interface**: Lightning-fast, reactive frontend built with **React, Vite, and Tailwind CSS**, featuring native WebSockets for instant log streaming.
- **Traffic Filtering**: Domain and IP-based blacklisting with regular expression support and automatic IP Geo-Blocking.
- **One-Click Threat Intelligence**: Import popular global blocklists (Spamhaus, Firehol, Pi-hole lists) directly from the UI.
- **Advanced WAF**: Integrated Python ICAP server for Deep Packet Inspection with memory-leak protection and multi-threading limits.
- **SSL Bump**: Inspect and filter encrypted HTTPS traffic with auto-generated certificates.
- **Caching & Optimization**: Bandwidth saving through configurable content caching.
- **Visual Analytics**: Interactive Recharts dashboards for monitoring bandwidth, cache hit rates, and blocked requests.
- **Docker Ready**: Fully containerized multi-tier architecture (React, FastAPI, Squid, WAF) deployed via a single `docker-compose` command.

## 🏗️ Architecture

Secure Proxy Manager employs a modern microservices architecture, completely revamped from its original monolithic Flask design:

1. **Frontend (React/Vite)**: A reactive Single Page Application built with React, Tailwind CSS, and Recharts, providing real-time data visualization and instant WebSocket log streaming.
2. **Backend (FastAPI)**: A high-performance, asynchronous Python backend using FastAPI and Uvicorn. It manages the SQLite database (in WAL mode for concurrency), handles REST APIs, and streams logs via native WebSockets.
3. **UI Proxy (Flask)**: A lightweight reverse proxy serving the React static assets and routing API/WebSocket traffic to the backend, secured with Talisman CSP.
4. **Proxy Engine (Squid)**: The core caching and filtering engine handling HTTP/HTTPS traffic.
5. **WAF Engine (Python ICAP)**: A custom ICAP server that inspects payloads for threats (SQLi, XSS) before they reach the user, equipped with anti-DoS thread pooling and memory-leak prevention.

<div align="center">
  <pre>
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │             │      │             │      │             │
  │  Web UI     │◄────►│  Backend    │◄────►│  Proxy      │
  │  (React)    │      │  API        │      │  (Squid)    │
  │             │      │  (Flask)    │      │             │
  └─────────────┘      └─────────────┘      └─────────────┘
         │                    │                    │
         │                    │                    ▼
         │                    │             ┌─────────────┐
         │                    │             │  WAF Engine │
         │                    │             │  (ICAP Py)  │
         │                    │             └─────────────┘
         ▼                    ▼                    
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │                 Shared Volumes                      │
  │  (Configuration, Logs, Database, Certificates)      │
  │                                                     │
  └─────────────────────────────────────────────────────┘
  </pre>
</div>

### 📁 Project Structure

```
secure-proxy-manager/
├── backend/              # Backend API service
│   ├── app/
│   │   ├── app.py       # Main Flask application with REST API
│   │   └── tests/       # Backend unit tests
│   ├── Dockerfile       # Backend container configuration
│   └── requirements.txt # Python dependencies
├── ui/                  # Web UI service
│   ├── static/          # CSS, JS, and static assets
│   ├── templates/       # HTML templates
│   ├── app.py          # Flask UI application
│   ├── Dockerfile      # UI container configuration
│   └── requirements.txt # Python dependencies
├── proxy/               # Squid proxy service
│   ├── squid.conf      # Squid configuration template
│   ├── startup.sh      # Container startup script
│   └── Dockerfile      # Proxy container configuration
├── config/              # Shared configuration files
│   ├── ip_blacklist.txt
│   ├── domain_blacklist.txt
│   └── ssl_cert.pem    # SSL certificates
├── data/                # Database and persistent data
│   └── secure_proxy.db # SQLite database
├── tests/               # End-to-end tests
│   └── e2e_test.py     # Comprehensive test suite
├── examples/            # Usage examples and scripts
│   └── import_blacklists.md
├── docker-compose.yml   # Service orchestration
├── CONTRIBUTING.md      # Contribution guidelines
├── LICENSE             # MIT License
├── CHANGELOG.md        # Version history
└── README.md           # This file
```

## 📋 Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v20.10.0+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2.0.0+)
- Minimum System Requirements:
  - 1 CPU core
  - 1GB RAM
  - 5GB disk space
- Network Requirements:
  - Port 8011: Web UI (HTTP)
  - Port 3128: Proxy service
  - Port 5001: Backend API (optional, for direct API access)

## 🚦 Quick Start

### For First-Time Users

If this is your first time deploying Secure Proxy Manager, we recommend using the **initialization script** for a guided setup:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
   cd secure-proxy-manager
   ```

2. **Run the initialization script**:
   ```bash
   chmod +x init.sh
   ./init.sh
   ```
   
   This script will:
   - Check prerequisites (Docker, Docker Compose)
   - Create required directories (`config`, `data`, `logs`)
   - **Require you to set up strong credentials (no more default `admin:admin`)**
   - Guide you through the setup process

3. **Provide `.env` file explicitly (Manual setup)**:
   If you don't use `init.sh`, you **MUST** create a `.env` file before starting.
   ```bash
   cp .env.example .env
   # Edit .env and change BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD
   nano .env
   ```
   *Note: The containers will crash on startup if these credentials are not provided.*

4. **Start the application**:
   ```bash
   docker-compose up -d
   ```

4. **Access the web interface**:
   ```
   http://localhost:8011
   ```
   Default credentials: username: `admin`, password: `admin`
   
   **⚠️ Important**: Change these default credentials immediately in production! Edit the `.env` file and restart the services.

   **Note**: The backend API is also accessible directly at `http://localhost:5001` for advanced users or automation scripts.

5. **Configure your client devices**:
   - Set proxy server to your host's IP address, port 3128
   - For transparent proxying, see the [Transparent Proxy Setup](#transparent-proxy-setup) section

### For Experienced Users

If you're familiar with Docker and prefer manual setup:

1. Clone the repository and create required directories:
   ```bash
   git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
   cd secure-proxy-manager
   mkdir -p config data logs
   cp .env.example .env
   ```

2. Edit `.env` to set your credentials, then start:
   ```bash
   docker-compose up -d
   ```

### Need Help?

- **New to Docker?** See our comprehensive [DEPLOYMENT.md](DEPLOYMENT.md) guide
- **Encountering issues?** Check the [Troubleshooting](#-troubleshooting) section below
- **Want detailed setup instructions?** Read the full [Deployment Guide](DEPLOYMENT.md)

## ⚙️ Configuration Options

### Environment Variables

#### Backend Service Variables
| Variable | Description | Default | Used By |
|----------|-------------|---------|---------|
| `FLASK_ENV` | Flask environment mode | `production` | Backend, UI |
| `PROXY_HOST` | Proxy service hostname | `proxy` | Backend |
| `PROXY_PORT` | Proxy service port | `3128` | Backend |
| `BASIC_AUTH_USERNAME` | Basic auth username | `admin` | Backend, UI |
| `BASIC_AUTH_PASSWORD` | Basic auth password | `admin` | Backend, UI |
| `SECRET_KEY` | Flask secret key for sessions | Auto-generated | Backend, UI |
| `PROXY_CONTAINER_NAME` | Docker container name for proxy | `secure-proxy-proxy-1` | Backend |

#### Web UI Service Variables
| Variable | Description | Default | Notes |
|----------|-------------|---------|-------|
| `BACKEND_URL` | Backend API URL | `http://backend:5000` | Internal Docker network |
| `REQUEST_TIMEOUT` | API request timeout (seconds) | `30` | Increase for slow networks |
| `MAX_RETRIES` | Maximum API retry attempts | `5` | For backend connection |
| `BACKOFF_FACTOR` | Retry backoff multiplier | `1.0` | Exponential backoff |
| `RETRY_WAIT_AFTER_STARTUP` | Wait time after startup (seconds) | `10` | Initial backend wait |

**Note:** To customize these values, modify them in `docker-compose.yml` before starting the services.

### 🔐 Security Configuration

**Important Security Considerations:**

1. **Change Default Credentials**: The default username and password (`admin`/`admin`) should be changed immediately in production:
   ```yaml
   # In docker-compose.yml, update both backend and web services:
   - BASIC_AUTH_USERNAME=your_secure_username
   - BASIC_AUTH_PASSWORD=your_secure_password
   ```

2. **HTTPS for Web UI**: For production deployments, use a reverse proxy (e.g., nginx, Traefik) with SSL/TLS to secure the web interface.

3. **Network Isolation**: Consider running the proxy in an isolated network segment with strict firewall rules.

4. **Regular Updates**: Keep the system and Docker images updated with security patches.

5. **Audit Logs**: Regularly review access logs and security events for suspicious activity.

### Security Features

| Feature | Description | Configuration |
|---------|-------------|--------------|
| IP Blacklisting | Block specific IP addresses or ranges | Web UI > Blacklists > IP |
| Domain Blacklisting | Block specific domains (wildcard support) | Web UI > Blacklists > Domains |
| Content Filtering | Block specific file types | Web UI > Settings > Filtering |
| HTTPS Filtering | Inspect and filter HTTPS traffic | Web UI > Settings > Security |
| Rate Limiting | Prevent brute force attacks | Auto-configured |

### Performance Tuning

| Setting | Description | Default | Recommended |
|---------|-------------|---------|------------|
| Cache Size | Disk space allocated for caching | 1GB | 5-10GB for production |
| Max Object Size | Maximum size of cached objects | 50MB | 100MB for media-heavy usage |
| Connection Timeout | Timeout for stalled connections | 30s | 15-60s based on network |
| DNS Timeout | Timeout for DNS lookups | 5s | 3-10s based on DNS infrastructure |
| Max Connections | Maximum concurrent connections | 100 | 100-500 based on hardware |

## 🛠️ Advanced Configuration

### Custom SSL Certificate

For HTTPS filtering with your own certificate:

1. Place your certificate and key in the `config/` directory:
   - `ssl_cert.pem`: Your SSL certificate
   - `ssl_key.pem`: Your private key

2. Enable HTTPS filtering in the web interface:
   - Settings > Security > Enable HTTPS Filtering

3. **Important:** Install the certificate on all client devices to avoid browser security warnings
   - **Windows**: Import to Trusted Root Certification Authorities
   - **macOS**: Add to Keychain and trust for SSL
   - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
   - **Mobile**: Email the certificate and install via device settings

**Note:** HTTPS filtering performs man-in-the-middle inspection. Only use this feature in environments where you have authorization to inspect traffic (e.g., corporate networks, your own devices).

### Transparent Proxy Setup

To use Secure Proxy as a transparent proxy:

1. Configure iptables on your router/gateway:
   ```bash
   iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128
   iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 3129
   ```

2. Enable transparent proxy mode in the web interface:
   - Settings > Advanced > Transparent Mode

### Extending Blacklists

Integrate with external threat intelligence sources. The system supports importing plain text files (one entry per line) and JSON formats.

#### 1-Click Popular Lists Import

We introduced a "Popular Lists" feature directly in the Web UI that allows you to instantly import thousands of known threats with a single click:

**For Domains:**
- *StevenBlack Ad/Malware*: Consolidated host files from multiple sources
- *MalwareDomainList*: Domains known to host malware
- *Phishing Army*: Domains actively involved in phishing

**For IPs:**
- *Firehol Level 1*: A general purpose blocklist protecting against active threats
- *Spamhaus DROP*: Don't Route Or Peer Lists (Direct malware/botnets)
- *Emerging Threats*: Known compromised hosts and botnet C&C

#### Manual Import from URL

```bash
# Import from URL - supports plain text files with one domain per line
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/domain-blacklist.txt"}'


# Import direct content
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"content": "example.com\n*.badsite.org\nmalicious.net"}'
```

#### Import IP Blacklists

```bash
# Import from URL - supports plain text files with one IP per line
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/ip-blacklist.txt"}'

# Import direct content with CIDR notation support
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"content": "192.168.1.100\n10.0.0.5\n172.16.0.0/24"}'
```

#### Supported File Formats

- **Plain Text**: One entry per line (recommended for most blacklists)
- **JSON Array**: `["example.com", "malicious.net"]`  
- **JSON Objects**: `[{"domain": "example.com", "description": "Blocked site"}]`
- **Comments**: Lines starting with `#` are ignored

**Note:** For scheduled automatic blacklist updates, consider setting up a cron job or scheduled task that calls the import endpoints with your preferred blacklist sources.

## 📊 Monitoring and Analytics

### Dashboard Metrics

- **Proxy Status**: Real-time operational status
- **Traffic Statistics**: Request volume over time
- **Resource Usage**: Memory and CPU consumption
- **Cache Performance**: Hit ratio and response time
- **Security Score**: Overall security assessment

### Logging and Analysis

All proxy traffic is logged and can be analyzed in the web interface:

- **Real-Time WebSockets**: View access logs streaming live from Squid to the UI via FastAPI WebSockets.
- **Persistent Storage**: Logs are automatically written to the SQLite database (in WAL mode for concurrency) allowing historical search and pagination.
- **Quick Stats**: Instant metric cards showing Total Requests, Success rates, Blocked traffic, and Errors directly above the logs table.
- **Security Events**: Authentication attempts and blocked requests by the WAF.

### Health Checks

Health status endpoints are available for monitoring:

```bash
curl -I http://localhost:8011/health
```

## 🔄 Database Export and Backup

### Database Export

Export database contents including blacklists, settings, and logs (limited to 10,000 most recent entries):

1. Via API:
   ```bash
   curl -X GET http://localhost:8011/api/database/export \
     -H "Authorization: Basic $(echo -n admin:admin | base64)" \
     > secure-proxy-export.json
   ```

2. Via Direct Backend Access:
   ```bash
   curl -X GET http://localhost:5001/api/database/export \
     -H "Authorization: Basic $(echo -n admin:admin | base64)" \
     > secure-proxy-export.json
   ```

### Manual Database Backup

For complete database backup including all logs:

```bash
# Stop the services
docker-compose down

# Backup the database file
cp data/secure_proxy.db data/secure_proxy.db.backup

# Backup configuration files
tar -czf config-backup.tar.gz config/

# Restart services
docker-compose up -d
```

### Database Restore

To restore from a manual backup:

```bash
# Stop the services
docker-compose down

# Restore the database file
cp data/secure_proxy.db.backup data/secure_proxy.db

# Restore configuration files
tar -xzf config-backup.tar.gz

# Restart services
docker-compose up -d
```

### Database Optimization

Optimize database performance:

```bash
curl -X POST http://localhost:8011/api/database/optimize \
  -H "Authorization: Basic $(echo -n admin:admin | base64)"
```

### Database Statistics

Get database size and statistics:

```bash
curl -X GET http://localhost:8011/api/database/stats \
  -H "Authorization: Basic $(echo -n admin:admin | base64)"
```

## 🧪 Testing and Validation

### Basic Connectivity Test

```bash
curl -x http://localhost:3128 http://example.com
```

### SSL Inspection Test

```bash
curl -x http://localhost:3128 https://example.com --insecure
```

### Blacklist Testing

To test if blacklisting works:
1. Add an IP or domain to the blacklist
2. Attempt to access a resource from that IP or domain
3. Verify the request is blocked (check logs)

### Running the Test Suite

Execute the comprehensive end-to-end test suite:

```bash
# Make sure services are running
docker-compose up -d

# Run tests
cd tests
python3 e2e_test.py

# Run with verbose output
python3 e2e_test.py -v
```

## ❓ Frequently Asked Questions (FAQ)

### General Questions

**Q: What is Secure Proxy Manager?**  
A: It's a containerized web proxy solution built on Squid with a modern management interface for filtering, monitoring, and controlling web traffic.

**Q: Is this suitable for production use?**  
A: Yes, but ensure you follow security best practices, change default credentials, and properly configure SSL certificates for HTTPS filtering.

**Q: Can I use this in a corporate environment?**  
A: Yes, it's designed for enterprise use with features like blacklisting, authentication, and detailed logging. Ensure compliance with your organization's policies.

### Installation & Setup

**Q: Which ports need to be open?**  
A: Port 8011 (Web UI), 3128 (Proxy), and optionally 5001 (Backend API for direct access).

**Q: Can I change the default credentials?**  
A: Yes! Modify `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` in `docker-compose.yml` before starting the services.

**Q: How do I update to the latest version?**  
A:
```bash
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Features & Usage

**Q: How do I import a large blacklist?**  
A: Use the import API endpoints with a URL pointing to your blacklist file:
```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/blacklist.txt"}'
```

**Q: Does it support IPv6?**  
A: Yes, IPv6 addresses can be added to the IP blacklist, including CIDR notation.

**Q: Can I filter HTTPS traffic?**  
A: Yes, by enabling HTTPS filtering and installing the SSL certificate on client devices. Note: This performs man-in-the-middle inspection.

**Q: How do I view blocked requests?**  
A: Check the logs in the Web UI dashboard or query via API: `http://localhost:8011/api/logs/stats`

### Performance & Scaling

**Q: What are the resource requirements?**  
A: Minimum 1 CPU core and 1GB RAM. For production with heavy traffic, 2+ CPU cores and 4GB+ RAM recommended.

**Q: Can I run multiple instances?**  
A: Yes, you can deploy multiple instances behind a load balancer for high availability.

**Q: How much disk space does caching use?**  
A: Default is 1GB. Adjust the cache size in performance tuning settings based on your needs (5-10GB recommended for production).

### Troubleshooting

**Q: Services won't start - what should I check?**  
A:
1. Run the initialization script: `./init.sh`
2. Ensure Docker and Docker Compose are installed and running
3. Check for port conflicts: `docker-compose logs`
4. Verify volumes have correct permissions: `chmod 755 config data logs`
5. Wait for backend health check (may take 10-15 seconds)
6. See the comprehensive [Deployment Guide](DEPLOYMENT.md#troubleshooting) for detailed solutions

**Q: Getting permission errors with config/data/logs directories?**
A: Run the initialization script (`./init.sh`) or manually create directories with proper permissions:
```bash
mkdir -p config data logs
chmod 755 config data logs
```

**Q: Authentication is failing between services?**
A: Ensure you have a `.env` file with credentials set. Copy from `.env.example`:
```bash
cp .env.example .env
docker-compose restart
```

**Q: Why am I getting SSL certificate warnings?**  
A: The SSL certificate needs to be installed on each client device. See [Custom SSL Certificate](#custom-ssl-certificate) section.

**Q: Import is failing - what's wrong?**  
A: Common causes:
- Invalid format (ensure one entry per line or valid JSON)
- Network issues (URL not accessible)
- Authentication failure (check credentials)
- Check logs: `docker-compose logs backend`

## 🔍 Troubleshooting

### Quick Fixes

**First-Time Setup Issues?** 
- Run the initialization script: `./init.sh`
- Or manually: `mkdir -p config data logs && cp .env.example .env && docker-compose up -d`

**For detailed troubleshooting and step-by-step solutions, see the [Deployment Guide](DEPLOYMENT.md#troubleshooting).**

### Common Issues

| Issue | Possible Cause | Resolution |
|-------|---------------|------------|
| Cannot access web UI | Port conflict or service not started | Run `./init.sh`, check `docker-compose ps` |
| Permission denied errors | Missing directories or wrong permissions | Run `./init.sh` or `mkdir -p config data logs && chmod 755 config data logs` |
| Authentication failures | Missing .env file | Copy `.env.example` to `.env` and restart |
| Proxy not filtering | Incorrect network configuration | Verify client proxy settings |
| SSL warnings | Certificate not trusted | Install certificate on client devices |
| Performance issues | Insufficient resources | Increase container resource limits |
| Database errors | Permission issues | Check volume permissions with `ls -la data/` |

### Diagnostic Tools

1. **Service Logs**:
   ```bash
   docker-compose logs -f backend
   docker-compose logs -f ui
   docker-compose logs -f proxy
   ```

2. **Database Check**:
   ```bash
   docker-compose exec backend sqlite3 /data/secure_proxy.db .tables
   ```

3. **Network Validation**:
   ```bash
   docker-compose exec proxy ping -c 3 google.com
   ```

4. **Cache Analysis**:
   ```bash
   docker-compose exec proxy squidclient -h localhost mgr:info
   ```

## 📘 API Documentation

Secure Proxy Manager provides a comprehensive RESTful API for integration and automation with support for plain text and JSON blacklist imports.

**API Base URLs:**
- Via Web UI: `http://localhost:8011/api`
- Direct Backend Access: `http://localhost:5001/api`

**Note:** When accessing the API directly through the backend (port 5001), you bypass the Web UI layer. This can be useful for automation scripts and monitoring tools.

### Authentication

All API endpoints require Basic Authentication:

```bash
# Login to get session (optional)
curl -X POST http://localhost:8011/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# Or use Basic Auth directly (recommended for scripts)
AUTH_HEADER="Authorization: Basic $(echo -n admin:admin | base64)"
```

### 🚫 Blacklist Management

#### Import Domain Blacklists

Perfect for importing standard text files with one domain per line:

```bash
# Import from URL (plain text file)
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/domain-blacklist.txt"}'

# Import direct content
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"content": "malicious.com\n*.ads.example\nbadsite.org"}'
```

**Example domain-blacklist.txt:**
```
malicious.com
badsite.org
*.ads.network
phishing-site.net
# Comments are ignored
unwanted.domain
```

#### Import IP Blacklists

```bash
# Import from URL (plain text file)
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/ip-blacklist.txt"}'

# Import with CIDR notation support
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"content": "192.168.1.100\n10.0.0.0/8\n172.16.0.0/12"}'
```

**Example ip-blacklist.txt:**
```
192.168.1.100
10.0.0.5
203.0.113.0/24
# Malicious IP range
198.51.100.0/24
```

#### Supported File Formats

- ✅ **Plain Text**: One entry per line (most common)
- ✅ **JSON Array**: `["entry1", "entry2"]`
- ✅ **JSON Objects**: `[{"domain": "example.com", "description": "Blocked"}]`
- ✅ **Comments**: Lines starting with `#` are ignored
- ✅ **CIDR Notation**: For IP ranges (`192.168.1.0/24`)
- ✅ **Wildcards**: For domains (`*.example.com`)

### 📋 Available Endpoints

#### Authentication & Session Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/login` | POST | User login with credentials |
| `/api/logout` | POST | User logout |
| `/api/change-password` | POST | Change user password |

#### Proxy Status & Settings
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Get proxy service status |
| `/api/settings` | GET | Get all proxy settings |
| `/api/settings/<setting_name>` | PUT | Update a specific setting |
| `/health` | GET | Health check endpoint |

#### Blacklist Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ip-blacklist` | GET | Get all IP blacklist entries |
| `/api/ip-blacklist` | POST | Add a single IP blacklist entry |
| `/api/ip-blacklist/<id>` | DELETE | Delete an IP blacklist entry |
| `/api/ip-blacklist/import` | POST | **Import IP blacklist from URL/content** |
| `/api/domain-blacklist` | GET | Get all domain blacklist entries |
| `/api/domain-blacklist` | POST | Add a single domain blacklist entry |
| `/api/domain-blacklist/<id>` | DELETE | Delete a domain blacklist entry |
| `/api/domain-blacklist/import` | POST | **Import domain blacklist from URL/content** |
| `/api/blacklists/import` | POST | Generic import (requires type parameter) |

#### Logs & Analytics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/logs/stats` | GET | Get proxy access logs with filtering |
| `/api/logs/clear` | POST | Clear all proxy logs |
| `/api/logs/clear-old` | POST | Clear old proxy logs |
| `/api/traffic/statistics` | GET | Get traffic statistics |
| `/api/clients/statistics` | GET | Get client statistics |
| `/api/domains/statistics` | GET | Get domain statistics |

#### Cache Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cache/statistics` | GET | Get cache performance metrics |
| `/api/maintenance/optimize-cache` | POST | Optimize the proxy cache |

#### Security
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security/score` | GET | Get security assessment score |
| `/api/security/scan` | POST | Perform security scan |
| `/api/security/rate-limits` | GET | Get rate limit information |
| `/api/security/rate-limits/<ip>` | DELETE | Remove rate limit for specific IP |
| `/api/maintenance/check-cert-security` | GET | Check SSL certificate security |

#### Database & Maintenance
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/database/size` | GET | Get database size |
| `/api/database/stats` | GET | Get database statistics |
| `/api/database/optimize` | POST | Optimize database |
| `/api/database/export` | GET | Export database |
| `/api/database/reset` | POST | Reset database |
| `/api/maintenance/reload-config` | POST | Reload proxy configuration |

#### API Documentation
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/docs` | GET | Interactive API documentation |

### 📊 Example API Responses

**Successful Import:**
```json
{
  "status": "success",
  "message": "Import completed: 150 entries imported",
  "imported_count": 150,
  "error_count": 0
}
```

**Import with Errors:**
```json
{
  "status": "success", 
  "message": "Import completed: 145 entries imported, 5 errors",
  "imported_count": 145,
  "error_count": 5,
  "errors": [
    "Invalid domain format: not-a-domain",
    "Invalid IP format: 999.999.999.999"
  ]
}
```

Full interactive API documentation is available at `/api/docs` when the service is running.

## 🔒 Security Best Practices

1. **Change default credentials** immediately after installation
2. **Enable HTTPS** for the admin interface in production
3. **Restrict access** to the admin interface to trusted IPs
4. **Regular backups** of configuration and database
5. **Monitor logs** for suspicious activity
6. **Use strong certificates** for HTTPS filtering

**Recent Security Hardening:**
- Replaced vulnerable string interpolations in SQL queries with strict parameter binding (SQLi mitigated).
- Implemented robust SSRF (Server-Side Request Forgery) protection on blacklist import URLs, blocking localhost and private IP scanning.
- Memory leak protection on the WAF engine via aggressive dictionary garbage collection.
- DoS protection against high-concurrency attacks via a custom `ThreadPoolExecutor` limiting background Python threads.
- De-escalated Squid proxy privileges from `root` to a dedicated `proxy` user.

## 🌱 Future Roadmap

- **Authentication Integration**: LDAP/Active Directory support
- **Advanced Analytics**: ML-based traffic pattern analysis
- **Threat Intelligence**: Integration with external threat feeds
- **Mobile Support**: Improved UI for mobile administration
- **Notification System**: Alerts via webhook

## 🤝 Contributing

Contributions are welcome and appreciated! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:

- Setting up your development environment
- Coding standards and best practices
- Testing requirements
- Pull request process
- Branch naming conventions

Quick contribution steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following our coding standards
4. Run tests to ensure everything works
5. Commit your changes: `git commit -m 'feat: Add some feature'`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a Pull Request with a clear description

For more details, see [CONTRIBUTING.md](CONTRIBUTING.md).

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- [Squid Proxy](http://www.squid-cache.org/) for the core proxy engine
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Bootstrap](https://getbootstrap.com/) for the UI components
- [Docker](https://www.docker.com/) for containerization
- All our contributors who have helped shape this project

## 📞 Support

If you need help or have questions:

- **Bug Reports**: [Create an issue](https://github.com/fabriziosalmi/secure-proxy-manager/issues/new) with detailed information
- **Feature Requests**: [Open an issue](https://github.com/fabriziosalmi/secure-proxy-manager/issues/new) describing your idea
- **Questions**: Check [existing issues](https://github.com/fabriziosalmi/secure-proxy-manager/issues) or create a new one
- **Documentation**: Review this README and [CONTRIBUTING.md](CONTRIBUTING.md)

When reporting issues, please include:
- Your environment (OS, Docker version, etc.)
- Steps to reproduce the problem
- Expected vs actual behavior
- Relevant logs from `docker-compose logs`

---

**Made with ❤️ by the Secure Proxy Manager community**
