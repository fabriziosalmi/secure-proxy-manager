# Squid Proxy Configuration Generator

This project automates the generation of a Squid proxy configuration file (`squid.conf`) using a YAML configuration file (`config.yaml`). It supports features like IP blacklisting, DNS blacklisting, OWASP protection, blocking VPN/Tor/Cloudflare/AWS/Microsoft/Google IPs and more.

## Features

- **IP Blacklisting**: Block IPs from local files or remote URLs.
- **DNS Blacklisting**: Block domains from local files or remote URLs.
- **OWASP Protection**: Block common web attack patterns using regex rules.
- **Block VPN/Tor/Cloudflare/AWS/Microsoft/Google IPs**: Block IP ranges from predefined sources.

## Prerequisites

- Python 3.x
- Docker (optional, for running Squid in a container)

## Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fabriziosalmi/secure-proxy.git
   cd secure-proxy
   ```

2. **Edit the `config.yaml` file**:
   Customize the configuration to suit your needs. Refer to the [Configuration Options](#configuration-options) section for details.

3. **Generate the `squid.conf` file**:
   Run the Python script to generate the Squid configuration:
   ```bash
   python generate_squid_conf.py
   ```

4. **Build and run the Docker image**:
   Build the Docker image and run the Squid proxy:
   ```bash
   docker build -t squid-proxy .
   docker run -d -p 3128:3128 --name squid-proxy squid-proxy
   ```

5. **Test the proxy**:
   Configure your browser or application to use the proxy at `http://localhost:3128`.

## Configuration Options

The `config.yaml` file supports the following options:

- **Network settings**: Define the proxy port, SSL port, and SSL interception.
- **Allowed IPs**: Specify IPs or ranges allowed to use the proxy.
- **IP/DNS Blacklisting**: Add local files or remote URLs for IP/DNS blacklists.
- **OWASP Protection**: Enable/disable OWASP protection and specify the rules file.
- **Block VPN/Tor/Cloudflare/AWS/Microsoft/Google IPs**: Enable/disable blocking and specify sources.
- **User-Agent Rewriting**: Rewrite or block specific User-Agent strings.
- **Logging**: Configure access and cache logs.
- **Cache**: Enable/disable caching and configure cache size.

Refer to the `config.yaml` file for examples.

## Testing with GitHub Actions

This repository includes a GitHub Actions workflow to test the configuration generation process. The workflow runs on every push to the `main` branch.

To view the workflow, check the `.github/workflows/test.yml` file.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
