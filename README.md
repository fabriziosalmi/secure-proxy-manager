# Secure Squid Proxy with Monitoring Dashboard

This project provides a Docker-based Squid proxy server with a web-based monitoring dashboard. The application allows you to easily run a Squid proxy and manage it through a modern, responsive user interface.

## Features

- Dockerized Squid proxy server
- Modern responsive web-based monitoring dashboard
- Dark mode support with system preference detection
- Real-time monitoring of connections and client activity
- Comprehensive configuration management
- Advanced security features:
  - IP and domain blacklisting
  - Direct IP access controls
  - User-agent filtering
  - Malware protection
- Detailed log analysis and visualization
- Proxy control (start, stop, restart, reload)
- Built with Flask backend and HTML/CSS/JavaScript frontend
- Tailwind CSS styling for modern UI

## Project Structure

```
secure-proxy/
├── Dockerfile              # Docker configuration
├── supervisord.conf        # Supervisor config to manage processes
├── squid_config/           # Squid configuration files
│   ├── squid.conf          # Main Squid configuration
│   ├── blacklist_ips.txt   # Blocked IP addresses
│   ├── blacklist_domains.txt # Blocked domains
│   ├── allowed_direct_ips.txt # IPs allowed direct access
│   └── bad_user_agents.txt # Blocked user agents
├── flask_backend/          # Flask API backend
│   ├── app.py              # Flask application
│   └── requirements.txt    # Python dependencies
└── dashboard/              # Frontend files
    ├── index.html          # Dashboard HTML
    ├── logs.html           # Logs page HTML
    ├── settings.html       # Settings page HTML
    ├── style.css           # Dashboard CSS
    └── script.js           # Dashboard JavaScript
```

## Prerequisites

- Docker
- Docker Compose (optional, for easier management)

## Building and Running

### Using Docker

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-proxy.git
   cd secure-proxy
   ```

2. Build the Docker image:
   ```
   docker build -t secure-proxy .
   ```

3. Run the container:
   ```
   docker run -d --name secure-proxy -p 3128:3128 -p 8000:5000 secure-proxy
   ```

### Using Docker Compose

1. Create a `docker-compose.yml` file:
   ```yaml
   version: '3'
   services:
     proxy:
       build: .
       ports:
         - "3128:3128"  # Squid proxy port
         - "5000:5000"  # Dashboard port
       restart: unless-stopped
       volumes:
         - ./squid_config:/etc/squid  # Mount configuration directory
         - squid_logs:/var/log/squid  # Persist logs
   
   volumes:
     squid_logs:
   ```

2. Start the application:
   ```
   docker-compose up -d
   ```

## Accessing the Application

- **Squid Proxy**: Configure your browser or application to use the proxy at `http://localhost:3128`
- **Dashboard**: Access the monitoring dashboard at `http://localhost:5000`

## Dashboard Features

The dashboard consists of three main pages:

### 1. Main Dashboard
- Proxy status and control buttons (start, stop, restart, reload)
- Real-time monitoring of active connections and clients
- Peak connections tracking
- Auto-refresh capability

### 2. Settings
- Basic configuration (port, cache settings)
- Security features management
- Blacklist configuration (IPs and domains)
- Direct IP access controls
- User agent filtering
- Advanced configuration editor

### 3. Logs
- View access, cache, store, and system logs
- Search functionality with regex support
- Log analysis with visualizations
- Download and clear log options

## Configuring the Proxy

The Squid configuration file is located at `squid_config/squid.conf`. You can modify this file to change the proxy settings before building the Docker image.

Many configuration options are available through the dashboard interface, including:

- Changing the listening port
- Adjusting cache settings
- Managing security features
- Setting up blacklists
- Editing the raw configuration file

## Security Features

The proxy includes several security features that can be enabled/disabled via the dashboard:

- IP Blacklisting: Block specific IP addresses
- Domain Blacklisting: Block specific domains
- Direct IP Access Controls: Prevent direct IP address access
- User Agent Filtering: Block requests from specific user agents
- Malware Protection: Block common malware file extensions
- HTTPS Filtering: Inspect HTTPS traffic (requires proper SSL setup)

## Environment Variables

The application supports the following environment variables:

- `SQUID_PORT`: The port Squid listens on (default: 3128)
- `DASHBOARD_PORT`: The port for the monitoring dashboard (default: 5000)
- `SECRET_KEY`: Used for session encryption (auto-generated if not provided)

Example:
```
docker run -d --name secure-proxy -p 8080:8080 -p 5000:5000 -e SQUID_PORT=8080 -e SECRET_KEY="your-secret-key" secure-proxy
```

## Browser Compatibility

The dashboard is tested and compatible with:
- Chrome/Edge (latest versions)
- Firefox (latest version)
- Safari (latest version)
- Mobile browsers (responsive design)

## License

This project is released under the MIT License. See LICENSE file for details.

## Version History

- **v2.1.0** (Current): Added dark mode, real-time monitoring, and enhanced security controls
- **v2.0.0**: Redesigned dashboard with Tailwind CSS and improved API
- **v1.0.0**: Initial release with basic monitoring capabilities