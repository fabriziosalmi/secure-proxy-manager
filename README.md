# Dockerized Squid Proxy with Blocklists, Whitelisting, and More

This project provides a Dockerized Squid proxy server with configurable blocklists (DNS and IP), whitelisting, external DNS, HTTPS support, and basic authentication, all managed via a `config.yaml` file.

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
*   **Configurable:**
    *   All main configurations are in `config.yaml`.

## Project Structure

```
my-squid-proxy/
├── Dockerfile
├── config.yaml
├── docker-compose.yaml
├── squid-config/
│   ├── squid.conf.template
│   └── generate_squid_conf.sh
├── data/
│   └── blocklists/
│       ├── dns_blocklist.txt
│       └── ip_blocklist.txt
│   └── ssl/
│       ├── squid.pem
│       └── squid.key
└── README.md
```

*   **`Dockerfile`:** Defines the Docker image build process.
*   **`config.yaml`:** Configuration file for Squid settings, blocklists, and more.
*   **`docker-compose.yaml`:**  Defines how the container should run, mapping ports, and mounting volumes.
*   **`squid-config/squid.conf.template`:** Template for generating the Squid configuration file (`squid.conf`).
*   **`squid-config/generate_squid_conf.sh`:** Shell script that downloads blocklists, generates the `squid.conf`, and authentication file.
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
    *   See the inline comments in `config.yaml` for details.
4.  **Build and Run:**
    ```bash
    docker-compose build
    docker-compose up -d
    ```
5.  **Access Squid Proxy**
    *   Configure your clients to use the Squid proxy at `http://<your-host-ip>:3128` or `https://<your-host-ip>:3129` for HTTPS (if you have it enabled).

## Configuration Options (`config.yaml`)

The `config.yaml` file controls all the key aspects of the Squid proxy. Here's a breakdown of its sections:

*   **`squid`:**
    *   `port`: HTTP port for the squid proxy (default: 3128).
    *   `cache_size`: Cache size in MB.
    *   `cache_dir`: Directory for cache files.
    *   `external_dns.enabled`: Enable or disable external DNS
    *   `external_dns.resolvers`: List of external DNS servers.
     *   `https.enabled`: Enable or disable HTTPS.
     *   `https.port`: HTTPS port for the squid proxy (default: 3129).
     *   `https.ssl_cert`: HTTPS SSL Cert path
     *   `https.ssl_key`: HTTPS SSL Key path

*   **`blocklists`:**
    *   `dns.enabled`: Enable or disable DNS blocklists.
    *   `dns.sources`: List of DNS blocklist sources. Each entry should have the following:
        *   `name`: A descriptive name for the blocklist.
        *   `url`: The URL to download the blocklist from.
        *   `format`: `hosts`
    *   `dns.local_file`: Local file path for the merged DNS blocklist.
    *   `ip.enabled`: Enable or disable IP blocklists.
     *   `ip.sources`: List of IP blocklist sources. Each entry should have the following:
        *   `name`: A descriptive name for the blocklist.
        *   `url`: The URL to download the blocklist from.
        *    `format`: `netset`
    *   `ip.local_file`: Local file path for the merged IP blocklist.
*   **`whitelist`:**
    *   `enabled`: Enable or disable whitelisting.
    *   `ips`: List of whitelisted IPs and IP ranges.
    *  `domain_allowlist`: List of whitelisted domains.
*    **`network`:**
    *    `allow_direct`: `true` to allow direct IP connection, `false` to prevent.
*   **`authentication`:**
    *    `enabled`: Enable or disable authentication.
    *    `users`: List of users. Each entry should have the following:
        *  `username`: User login
        * `password`: User password
    *   `method`: Authentication method (currently only "basic" is supported).

## Updating the Configuration

1.  Edit the `config.yaml` file to make the changes you desire.
2.  Restart the container for changes to take effect:
    ```bash
    docker-compose restart
    ```

## Contributing

Feel free to contribute by submitting pull requests or reporting issues.

## License

This project is licensed under the [Your License] - see the LICENSE.md file for details.
```

**Explanation:**

*   **Overview:**  Provides a brief description of the project and its features.
*   **Features:** Lists the key capabilities of the Squid proxy.
*   **Project Structure:** Explains the purpose of each file and directory in the project.
*   **Getting Started:** Provides step-by-step instructions for setting up and running the proxy.
*   **Configuration Options:** Explains each configuration parameter of the `config.yaml` file.
*   **Updating Configuration:** Describes the process of making changes and restarting the proxy.
*   **Contributing:** Provides info for those who want to participate in this project.
*   **License:** Indicates the license under which the project is distributed.

**How to Use:**

1.  Save the text above in a file named `README.md` at the root of your `my-squid-proxy` directory.
2.  You can then view this file when navigating to your repository, or by using a markdown reader.
