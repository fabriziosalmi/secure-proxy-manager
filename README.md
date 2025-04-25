# Secure Squid Proxy Configuration Generator

This project automates the generation of a Squid proxy configuration file (`squid.conf`) using a YAML configuration file (`config.yaml`). It supports features like IP blacklisting, DNS blacklisting, OWASP protection, blocking VPN/Tor/Cloudflare/AWS/Microsoft/Google IPs and more.

## Features

- **IP Blacklisting**: Block traffic to specific IPs from local files or remote URLs.
- **DNS Blacklisting**: Block domains from local files or remote URLs.
- **OWASP Protection**: Block common web attack patterns using regex rules.
- **SSL Interception**: Optional SSL traffic interception with certificate and key support.
- **Block VPN/Tor/Cloudflare/AWS/Microsoft/Google IPs**: Block traffic from IP ranges of popular services.
- **Flexible Caching**: Configure cache size, type, and maximum object size.
- **Docker Support**: Easy deployment with Docker and Docker Compose.

## Prerequisites

- Python 3.x
- Docker and Docker Compose (for containerized deployment)

## Usage

### Configuration

Edit the `config.yaml` file to customize your proxy settings.

### Generate Squid Configuration

```bash
python generate_squid_conf.py [config_file] [output_file]
```

Arguments:
- `config_file`: Path to your config YAML file (default: `config.yaml`)
- `output_file`: Path where the config should be saved (default: `squid.conf`)

### Docker Deployment

#### Using Docker Compose (Recommended)

1. Generate the configuration:
   ```bash
   python generate_squid_conf.py
   ```

2. Start the Squid proxy using Docker Compose:
   ```bash
   docker-compose up -d
   ```

3. To view logs:
   ```bash
   docker-compose logs -f
   ```

4. To stop the proxy:
   ```bash
   docker-compose down
   ```

#### Using Docker Directly

1. Generate the configuration:
   ```bash
   python generate_squid_conf.py
   ```

2. Build and run the Docker image:
   ```bash
   docker build -t squid-proxy .
   docker run -d -p 3128:3128 -v $(pwd)/squid.conf:/etc/squid/squid.conf:ro -v $(pwd)/docker_files:/etc/squid:ro --name squid-proxy squid-proxy
   ```

### Using the Proxy

Configure your browser or application to use the proxy at `http://localhost:3128`.

## Configuration Options

The `config.yaml` file supports the following options:

### Network Settings
- `port`: The port to run the proxy on (default: 3128)
- `ssl_port`: The port for SSL interception (if enabled)
- `ssl_intercept`: Enable/disable SSL interception
- `ssl_cert_path`: Path to SSL certificate (for SSL interception)
- `ssl_key_path`: Path to SSL key (for SSL interception)

### Access Control
- `allowed_ips`: IPs or networks allowed to use the proxy

### Blacklists
- `ip_blacklist_sources`: Sources for IP blacklists
- `dns_blacklist_sources`: Sources for DNS blacklists

### Protection Features
- `owasp_protection`: Enable/disable OWASP protection
- `owasp_rules_file`: Rules file for OWASP protection
- `block_vpn`, `block_tor`, etc.: Enable/disable blocking of specific services
- `vpn_ip_sources`, `tor_ip_sources`, etc.: Sources for IP blocks

### Logging
- `logging.access_log`: Path to access log
- `logging.cache_log`: Path to cache log
- `logging.log_format`: Log format

### Caching
- `cache.enabled`: Enable/disable caching
- `cache.cache_type`: Cache storage type (ufs, aufs, diskd, rock)
- `cache.cache_dir`: Directory for cache storage
- `cache.cache_size`: Size of cache in MB
- `cache.max_object_size`: Maximum size of cached objects

## Testing with GitHub Actions

This repository includes a GitHub Actions workflow to test the configuration generation process on multiple Python versions. The workflow runs on every push to the `main` branch.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
