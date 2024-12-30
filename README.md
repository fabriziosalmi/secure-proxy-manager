      
# Dockerized Squid Proxy with Blocklists, Whitelisting, and More

This project provides a Dockerized Squid proxy server with configurable blocklists (DNS and IP), whitelisting, external DNS, HTTPS support, and basic authentication, all managed via a `config.yaml` file. Environment variables can be used to override default configuration parameters.

## Features

*   **Configurable Blocklists:**
    *   Supports multiple DNS blocklist sources.
    *   Supports multiple IP blocklist sources.
    *   Aggregates blocklists into single files for Squid.
*   **Whitelisting:**
    *   Allows specific IPs and domains.
*   **External DNS:**
    *   Configurable external DNS resolvers for better performance.
*   **HTTPS Support:**
    *   Squid can listen on HTTPS port with configurable certs
*   **Basic Authentication:**
    *   Usernames and passwords configurable in `config.yaml`.
*   **No Direct IP Connections:**
    *   Option to disable direct connections by IP address, forcing clients to use DNS hostnames.
*   **Dockerized:**
    *   Easy to deploy and manage using Docker and Docker Compose.
*  **Configurable via env vars:**
    *   All main configurations are in `config.yaml`, can be overwritten by env vars

## Project Structure

    

Use code with caution.Markdown

my-squid-proxy/
├── Dockerfile
├── config.yaml
├── docker-compose.yaml
├── squid-config/
│ ├── squid.conf.template
│ └── generate_squid_conf.sh
├── data/
│ └── blocklists/
│ ├── dns_blocklist.txt
│ └── ip_blocklist.txt
│ └── ssl/
│ ├── squid.pem
│ └── squid.key
└── README.md

      
*   **`Dockerfile`:** Defines the Docker image build process.
*   **`config.yaml`:** Configuration file for Squid settings, blocklists, and more.
*   **`docker-compose.yaml`:**  Defines how the container should run, mapping ports, mounting volumes, and defining env vars.
*   **`squid-config/squid.conf.template`:** Template for generating the Squid configuration file (`squid.conf`).
*   **`squid-config/generate_squid_conf.sh`:** Shell script that downloads blocklists, generates the `squid.conf`, and authentication file, including env var support.
*   **`data/blocklists/`:** Directory where blocklist files are saved.
*   **`data/ssl/`:** Directory to store SSL key and certificate files.

## Getting Started

### Prerequisites

*   Docker installed on your machine.
*   Docker Compose installed on your machine.

### Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd my-squid-proxy
    ```
2.  **Generate SSL Keys:**
    *   Generate a private key and a self-signed certificate (or use your own). Example for testing purposes only:
        ```bash
         openssl genrsa -out data/ssl/squid.key 2048
         openssl req -new -x509 -key data/ssl/squid.key -out data/ssl/squid.pem -days 3650
        ```
    *   Place `squid.key` and `squid.pem` in the `data/ssl/` directory.
3.  **Configuration:**
    *   Modify the `config.yaml` file to suit your needs. You can customize:
        *   Squid port and cache settings.
        *   External DNS resolvers.
        *   HTTPS settings including cert/key path
        *   Blocklists sources (DNS and IP).
        *   Whitelisted IPs and domains.
        *   Authentication settings.
        *   Allow or block direct IP connections
    *  Alternatively, env vars can be set in docker run command or the `docker-compose.yaml`.
4.  **Build and Run:**
    ```bash
    docker-compose build
    docker-compose up -d
    ```
5.  **Access Squid Proxy**
    *   Configure your clients to use the Squid proxy at `http://<your-host-ip>:3128` or `https://<your-host-ip>:3129` for HTTPS (if you have it enabled).

## Configuration Options (`config.yaml`)

The `config.yaml` file controls all the key aspects of the Squid proxy.  Environment variables can be set to override these values. Here's a breakdown of its sections and corresponding env var names:

*   **`squid`:**
    *   `port`: HTTP port for the squid proxy (default: 3128). Env var: `SQUID_PORT`
    *   `cache_size`: Cache size in MB. Env var: `SQUID_CACHE_SIZE`
    *   `cache_dir`: Directory for cache files. Env var (no var override)
    *   `external_dns.enabled`: Enable or disable external DNS. Env var: `SQUID_EXTERNAL_DNS_ENABLED`
    *   `external_dns.resolvers`: List of external DNS servers. Env var: `SQUID_EXTERNAL_DNS_RESOLVERS`
    *   `https.enabled`: Enable or disable HTTPS. Env var: `SQUID_HTTPS_ENABLED`
    *   `https.port`: HTTPS port for the squid proxy (default: 3129). Env var: `SQUID_HTTPS_PORT`
    *   `https.ssl_cert`: HTTPS SSL Cert path. Env var: `SQUID_HTTPS_SSL_CERT`
    *   `https.ssl_key`: HTTPS SSL Key path. Env var: `SQUID_HTTPS_SSL_KEY`
*   **`blocklists`:**
    *   `dns.enabled`: Enable or disable DNS blocklists. Env var: `BLOCKLISTS_DNS_ENABLED`
    *   `dns.sources`: List of DNS blocklist sources. Each entry should have the following:
        *   `name`: A descriptive name for the blocklist.
        *   `url`: The URL to download the blocklist from.
        *   `format`: `hosts`
        *   env vars: no vars for sources
    *   `dns.local_file`: Local file path for the merged DNS blocklist. Env var (no var override)
    *   `ip.enabled`: Enable or disable IP blocklists. Env var: `BLOCKLISTS_IP_ENABLED`
     *   `ip.sources`: List of IP blocklist sources. Each entry should have the following:
        *   `name`: A descriptive name for the blocklist.
        *   `url`: The URL to download the blocklist from.
        *    `format`: `netset`
          *   env vars: no vars for sources
    *   `ip.local_file`: Local file path for the merged IP blocklist. Env var (no var override)
*   **`whitelist`:**
    *   `enabled`: Enable or disable whitelisting. Env var: `WHITELIST_ENABLED`
    *   `ips`: List of whitelisted IPs and IP ranges, comma separated. Env var: `WHITELIST_IPS`
    *   `domain_allowlist`: List of whitelisted domains, comma separated. Env var: `WHITELIST_DOMAIN_ALLOWLIST`
*    **`network`:**
    *    `allow_direct`: `true` to allow direct IP connection, `false` to prevent. Env var: `NETWORK_ALLOW_DIRECT`
*   **`authentication`:**
    *    `enabled`: Enable or disable authentication. Env var: `AUTHENTICATION_ENABLED`
    *    `users`: List of users. Each entry should have the following:
        *  `username`: User login
        * `password`: User password, comma separated. Env var: `AUTHENTICATION_USERS`
    *   `method`: Authentication method (currently only "basic" is supported).  Env var (no var override)

## Updating the Configuration

1.  Modify the `config.yaml` file or use environment variables
2.  Restart the container for changes to take effect:
    ```bash
    docker-compose restart
    ```

## Contributing

Feel free to contribute by submitting pull requests or reporting issues.

## License

This project is licensed under the [MIT license] - see the LICENSE.md file for details.
