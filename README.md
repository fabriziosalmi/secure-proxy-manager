# Secure Proxy Manager

A containerized secure proxy with advanced filtering capabilities, real-time monitoring, and a modern web UI.
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://www.docker.com/)
  [![Python](https://img.shields.io/badge/Python-3.9+-yellow?logo=python)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/Flask-2.0+-green?logo=flask)](https://flask.palletsprojects.com/)
  [![Bootstrap](https://img.shields.io/badge/Bootstrap-5.0-purple?logo=bootstrap)](https://getbootstrap.com/)

## Screenshots

![screenshot1](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_1.png?raw=true)
![screenshot2](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_2.png?raw=true)
![screenshot3](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/screenshot_3.png?raw=true)

## 🚀 Features

- **High-Performance Proxy Engine**: Built on Squid with optimized caching capabilities
- **Advanced Filtering**:
  - IP Blacklisting with CIDR support
  - Domain Blacklisting with wildcard support
  - Content Type Filtering
  - Direct IP Access Control
  - Time-based Access Restrictions
- **Comprehensive Security**:
  - HTTPS Filtering with proper certificate management
  - Rate Limiting protection against brute force attacks
  - Security scoring and recommendations
  - Configurable content policies
- **Modern Dashboard**:
  - Real-time traffic monitoring
  - Resource usage statistics
  - Cache performance metrics
  - Security status visualization
- **Detailed Analytics**:
  - Full request logging and analysis
  - Traffic pattern visualization
  - Blocked request reporting
  - Exportable reports
- **Enterprise Management**:
  - Configuration backup and restore
  - Role-based access control
  - API for automation and integration
  - Health monitoring endpoints

## 🏗️ Architecture

The application consists of three main containerized components:

1. **Proxy Service**: Squid-based proxy with customized configurations for enhanced security
2. **Backend API**: RESTful API built with Flask providing management capabilities
3. **Web UI**: Modern Bootstrap 5 interface for administration and monitoring

<div align="center">
  <pre>
  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
  │             │      │             │      │             │
  │  Web UI     │◄────►│  Backend    │◄────►│  Proxy      │
  │  (Flask)    │      │  API        │      │  (Squid)    │
  │             │      │  (Flask)    │      │             │
  └─────────────┘      └─────────────┘      └─────────────┘
         │                    │                    │
         │                    │                    │
         ▼                    ▼                    ▼
  ┌─────────────────────────────────────────────────────┐
  │                                                     │
  │                 Shared Volumes                      │
  │  (Configuration, Logs, Database, Certificates)      │
  │                                                     │
  └─────────────────────────────────────────────────────┘
  </pre>
</div>

## 📋 Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v20.10.0+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2.0.0+)
- Minimum System Requirements:
  - 1 CPU core
  - 1GB RAM
  - 5GB disk space
- Network Requirements:
  - Open ports for HTTP (8011) and Proxy (3128)

## 🚦 Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fabriziosalmi/secure-proxy.git
   cd secure-proxy
   ```

2. **Start the application**:
   ```bash
   docker-compose up -d
   ```

3. **Access the web interface**:
   ```
   http://localhost:8011
   ```
   Default credentials: username: `admin`, password: `admin`

4. **Configure your client devices**:
   - Set proxy server to your host's IP address, port 3128
   - For transparent proxying, see the Network Configuration section

## ⚙️ Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_HOST` | Proxy service hostname | `proxy` |
| `PROXY_PORT` | Proxy service port | `3128` |
| `BASIC_AUTH_USERNAME` | Basic auth username | `admin` |
| `BASIC_AUTH_PASSWORD` | Basic auth password | `admin` |
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `LOG_LEVEL` | Logging level | `INFO` |

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

1. Place your certificate and key in the `/config` directory:
   - `ssl_cert.pem`: Your SSL certificate
   - `ssl_key.pem`: Your private key

2. Enable HTTPS filtering in the web interface:
   - Settings > Security > Enable HTTPS Filtering

3. Install the certificate on client devices to avoid warnings

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

#### Import Domain Blacklists

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

#### Schedule Automatic Updates

```bash
curl -X POST http://localhost:8011/api/maintenance/update-blacklists \
  -H "Authorization: Basic $(echo -n admin:admin | base64)"
```

## 📊 Monitoring and Analytics

### Dashboard Metrics

- **Proxy Status**: Real-time operational status
- **Traffic Statistics**: Request volume over time
- **Resource Usage**: Memory and CPU consumption
- **Cache Performance**: Hit ratio and response time
- **Security Score**: Overall security assessment

### Logging and Analysis

All proxy traffic is logged and can be analyzed in the web interface:

- **Access Logs**: All requests with filtering and search
- **Security Events**: Authentication attempts and blocked requests
- **System Logs**: Application and service events

### Health Checks

Health status endpoints are available for monitoring:

```bash
curl -I http://localhost:8011/health
```

## 🔄 Backup and Restore

### Configuration Backup

Create a full system backup:

1. Via Web UI:
   - Maintenance > Backup Configuration > Download Backup

2. Via API:
   ```bash
   curl -X GET http://localhost:8011/api/maintenance/backup-config \
     -H "Authorization: Basic $(echo -n admin:admin | base64)" \
     > secure-proxy-backup.json
   ```

### Configuration Restore

Restore from a previous backup:

1. Via Web UI:
   - Maintenance > Restore Configuration > Upload Backup

2. Via API:
   ```bash
   curl -X POST http://localhost:8011/api/maintenance/restore-config \
     -H "Content-Type: application/json" \
     -H "Authorization: Basic $(echo -n admin:admin | base64)" \
     -d @secure-proxy-backup.json
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

## 🔍 Troubleshooting

### Common Issues

| Issue | Possible Cause | Resolution |
|-------|---------------|------------|
| Cannot access web UI | Port conflict | Change port mapping in docker-compose.yml |
| Proxy not filtering | Incorrect network configuration | Verify client proxy settings |
| SSL warnings | Certificate not trusted | Install certificate on client devices |
| Performance issues | Insufficient resources | Increase container resource limits |
| Database errors | Permission issues | Check volume permissions |

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

Secure Proxy provides a comprehensive RESTful API for integration and automation with support for plain text and JSON blacklist imports.

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

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Get proxy service status |
| `/api/settings` | GET/POST | Manage proxy settings |
| `/api/ip-blacklist` | GET/POST/DELETE | Manage individual IP entries |
| `/api/ip-blacklist/import` | POST | **Import IP blacklist from URL/content** |
| `/api/domain-blacklist` | GET/POST/DELETE | Manage individual domain entries |
| `/api/domain-blacklist/import` | POST | **Import domain blacklist from URL/content** |
| `/api/blacklists/import` | POST | Generic import (requires type parameter) |
| `/api/logs` | GET | Get proxy access logs with filtering |
| `/api/logs/import` | POST | Import logs from Squid |
| `/api/maintenance/clear-cache` | POST | Clear the proxy cache |
| `/api/maintenance/reload-config` | POST | Reload proxy configuration |
| `/api/security/score` | GET | Get security assessment score |

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
5. **Keep the system updated** with security patches
6. **Monitor logs** for suspicious activity
7. **Use strong certificates** for HTTPS filtering

## 🌱 Future Roadmap

- **Authentication Integration**: LDAP/Active Directory support
- **Advanced Analytics**: ML-based traffic pattern analysis
- **Threat Intelligence**: Integration with external threat feeds
- **Clustering**: Multi-node deployment for high availability
- **Content Inspection**: DLP capabilities for data protection
- **Mobile Support**: Improved UI for mobile administration
- **Notification System**: Alerts via email, Slack, etc.

## 🤝 Contributing

Contributions are welcome and appreciated!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-name`
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [Squid Proxy](http://www.squid-cache.org/) for the core proxy engine
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Bootstrap](https://getbootstrap.com/) for the UI components
- [Docker](https://www.docker.com/) for containerization
- All our contributors who have helped shape this project

## 📞 Support

- Create an issue in the GitHub repository
- Contact the maintainers at: [your-email@example.com]
- Community forum: [https://community.example.com]
