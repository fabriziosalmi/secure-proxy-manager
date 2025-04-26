# Secure Proxy

A Dockerized transparent proxy solution with a modern web UI for configuration and monitoring, providing enhanced security features through IP and domain blacklisting.

## Features

- **Transparent HTTP/HTTPS Proxy**: Built on Squid proxy for reliable performance
- **IP Blacklisting**: Block traffic from specific IP addresses or ranges
- **Domain Blacklisting**: Block access to specific domains
- **Direct IP Access Control**: Block direct IP requests with configurable exceptions
- **Modern Web Interface**: Clean, Bootstrap-based UI for configuration and monitoring
- **Detailed Logging**: Track and analyze all proxy traffic
- **Dockerized Deployment**: Easy setup and management with Docker and Docker Compose

## Architecture

The application consists of three main components:

1. **Proxy Service**: Squid-based transparent proxy with custom configurations
2. **Backend API**: Python Flask RESTful API for proxy management
3. **Web UI**: Modern Bootstrap-based interface for administration

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Quick Start

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-proxy.git
   cd secure-proxy
   ```

2. Start the application:
   ```
   docker-compose up -d
   ```

3. Access the web interface:
   ```
   http://localhost:8011
   ```
   Default credentials: username: `admin`, password: `admin`

## Configuration

### Using the Web Interface

After starting the application, you can configure all aspects of the proxy through the web interface:

1. **Dashboard**: View proxy status and recent logs
2. **Blacklists**: Manage IP and domain blacklists
3. **Settings**: Configure proxy behavior and security features
4. **Logs**: View and search detailed proxy access logs

### Network Configuration

To use as a transparent proxy, configure your network devices to use this server (port 3128) as their proxy server, or set up your router to redirect all HTTP/HTTPS traffic through this proxy.

### Docker Compose Configuration

You can adjust the ports, volumes, and environment variables in the `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  web:
    # UI service configuration
    ports:
      - "8011:8011"  # Change the host port if needed
    # ...additional configuration...

  backend:
    # Backend API service configuration
    # ...

  proxy:
    # Squid proxy service configuration
    ports:
      - "3128:3128"  # Change the host port if needed
    # ...additional configuration...
```

## Directory Structure

- `/config`: Contains configuration files
- `/data`: Stores the SQLite database and other persistent data
- `/logs`: Contains proxy and application logs
- `/proxy`: Squid proxy configuration and scripts
- `/backend`: Flask API backend code
- `/ui`: Web interface code

## Security Considerations

- **Default Credentials**: Change the default admin credentials immediately
- **Network Exposure**: Consider your network setup when exposing the proxy port
- **Regular Updates**: Keep the system updated for security patches

## Development

### Building from Source

```
git clone https://github.com/yourusername/secure-proxy.git
cd secure-proxy
docker-compose build
docker-compose up -d
```

### Adding Custom Features

- Squid configuration can be modified in `/proxy/squid.conf`
- Backend API logic is in `/backend/app/app.py`
- UI templates are in `/ui/templates/`

## Troubleshooting

### Common Issues

1. **Proxy not working**:
   - Check if Squid service is running: `docker-compose logs proxy`
   - Verify network configuration

2. **Cannot access web UI**:
   - Check if web service is running: `docker-compose logs web`
   - Verify the exposed port configuration

3. **Database errors**:
   - Check permissions on the `/data` directory

### Logs

Access application logs:
```
docker-compose logs -f
```

For specific service logs:
```
docker-compose logs -f proxy
docker-compose logs -f backend
docker-compose logs -f web
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Future Improvements

- Add support for authentication in proxy
- Implement more advanced traffic analysis
- Add custom filtering rules
- Support for SSL inspection (with proper security considerations)
- Integration with external threat intelligence feeds

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.