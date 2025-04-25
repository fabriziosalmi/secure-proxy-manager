# Secure Squid Proxy with Dashboard

A comprehensive, secure implementation of Squid proxy with a modern web-based dashboard for management and monitoring.

## Features

- **Secure Squid Configuration**: Hardened proxy with comprehensive security controls
- **Domain Blacklisting**: Block malicious domains and unwanted content
- **Modern Dashboard**: React-based UI with Tailwind CSS for easy management
- **Monitoring & Analytics**: Real-time statistics and traffic visualization
- **Containerized Architecture**: Docker-based deployment for easy setup and scaling
- **Access Controls**: Fine-grained access management
- **Log Analysis**: Advanced log viewing and filtering

## Requirements

- Docker and Docker Compose
- Node.js (for development only)
- Linux/macOS/Windows with Docker support

## Quick Start

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-proxy.git
   cd secure-proxy
   ```

2. Start the services using Docker Compose:
   ```
   docker-compose up -d
   ```

3. Access the dashboard at http://localhost:8080

4. Configure your client to use the proxy at `localhost:3128`

## Architecture

The project consists of two main components:

1. **Squid Proxy Service**: Provides the actual proxy functionality with security features
2. **Web Dashboard**: Provides a user-friendly interface for managing and monitoring the proxy

Both components are containerized using Docker for easy deployment and isolation.

## Configuration

### Squid Configuration

The main Squid configuration file is located at `config/squid/squid.conf`. You can modify this file to adjust the proxy settings according to your needs.

Key settings include:
- Port configuration
- Access control lists
- Cache settings
- Security parameters

### Blacklist Management

Domain blacklists are stored in `config/blacklists/domains.txt`. You can edit this file directly or use the dashboard to manage blocked domains.

### Dashboard Configuration

The dashboard is configured to connect to the Squid proxy service automatically when deployed using Docker Compose. For development or custom deployments, you may need to adjust the proxy connection settings.

## Development

### Prerequisites

- Node.js (version 14 or higher)
- npm or yarn
- Docker and Docker Compose

### Dashboard Development

1. Navigate to the dashboard directory:
   ```
   cd src/dashboard
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the development server:
   ```
   npm start
   ```

The dashboard will be available at http://localhost:3000 with hot-reloading enabled.

### Building for Production

To build the dashboard for production:

```
cd src/dashboard
npm run build
```

This will create optimized static files in the `build` directory.

## Proxy Management

The `scripts/proxy-manager.sh` script provides a convenient way to manage the Squid proxy service when not using Docker:

```
sudo ./scripts/proxy-manager.sh [command]
```

Available commands:
- `start`: Start the Squid proxy service
- `stop`: Stop the Squid proxy service
- `restart`: Restart the Squid proxy service
- `status`: Check the status of the Squid proxy service
- `validate`: Validate the Squid configuration
- `logs`: View recent logs
- `clear`: Clear the Squid cache

## Security Considerations

This implementation includes several security features:

1. **Restricted Access**: By default, the proxy only allows connections from local networks
2. **Domain Blacklisting**: Blocks known malicious domains
3. **Protocol Restrictions**: Only allows safe protocols
4. **SSL Inspection**: Optional SSL/TLS inspection for enhanced security (requires additional setup)
5. **Authentication**: Optional user authentication for access control

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.