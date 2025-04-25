# Secure Squid Proxy with Monitoring Dashboard

This project provides a Docker-based Squid proxy server with a web-based monitoring dashboard. The application allows you to easily run a Squid proxy and manage it through a simple user interface.

## Features

- Dockerized Squid proxy server
- Web-based monitoring dashboard
- Basic configuration management
- Proxy control (start, stop, restart, reload)
- Built with Flask backend and HTML/CSS/JavaScript frontend
- Tailwind CSS styling

## Project Structure

```
secure-proxy/
├── Dockerfile              # Docker configuration
├── supervisord.conf        # Supervisor config to manage processes
├── squid_config/           # Squid configuration files
│   └── squid.conf          # Main Squid configuration
├── flask_backend/          # Flask API backend
│   └── app.py              # Flask application
└── dashboard/              # Frontend files
    ├── index.html          # Dashboard HTML
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
   ```

2. Start the application:
   ```
   docker-compose up -d
   ```

## Accessing the Application

- **Squid Proxy**: Configure your browser or application to use the proxy at `http://localhost:3128`
- **Dashboard**: Access the monitoring dashboard at `http://localhost:5000`

## Configuring the Proxy

The Squid configuration file is located at `squid_config/squid.conf`. You can modify this file to change the proxy settings before building the Docker image.

Some basic configuration options are also available through the dashboard interface.

## Environment Variables

The application supports the following environment variables:

- `SQUID_PORT`: The port Squid listens on (default: 3128)
- `DASHBOARD_PORT`: The port for the monitoring dashboard (default: 5000)

Example:
```
docker run -d --name secure-proxy -p 8080:8080 -p 5000:5000 -e SQUID_PORT=8080 secure-proxy
```

## License

This project is released under the MIT License. See LICENSE file for details.