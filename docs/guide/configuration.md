# Configuration

## Environment Variables

All configuration is done via the `.env` file in the project root, which is read by `docker-compose.yml`.

### Required

| Variable | Description |
|---|---|
| `BASIC_AUTH_USERNAME` | HTTP Basic Auth username for the web UI and API |
| `BASIC_AUTH_PASSWORD` | HTTP Basic Auth password (use a strong password) |

### Backend

| Variable | Default | Description |
|---|---|---|
| `DATABASE_PATH` | `/data/secure_proxy.db` | Path to the SQLite database inside the container |
| `PROXY_HOST` | `proxy` | Squid container hostname (Docker service name) |
| `PROXY_PORT` | `3128` | Squid proxy port |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:8011,http://web:8011` | Comma-separated list of allowed CORS origins |
| `PROXY_CONTAINER_NAME` | `secure-proxy-proxy-1` | Docker container name used to send reconfigure signals |

### Web UI

| Variable | Default | Description |
|---|---|---|
| `BACKEND_URL` | `http://backend:5000` | Backend API URL (internal Docker network) |
| `REQUEST_TIMEOUT` | `30` | API request timeout in seconds |
| `MAX_RETRIES` | `5` | Maximum retry attempts for backend connection |
| `BACKOFF_FACTOR` | `1.0` | Exponential backoff multiplier for retries |

### WAF

| Variable | Default | Description |
|---|---|---|
| `BACKEND_URL` | `http://backend:5000` | Backend URL for sending WAF alert notifications |
| `BASIC_AUTH_USERNAME` | — | Must match the backend credential for `/api/internal/alert` |
| `BASIC_AUTH_PASSWORD` | — | Must match the backend credential |

## Squid Configuration

The `proxy/startup.sh` script generates `squid.conf` at container start. You can provide a custom configuration by placing it at:

- `/config/custom_squid.conf` (highest priority)
- `/config/squid.conf`
- `/config/squid/squid.conf`

If none of these exist, the base configuration in `startup.sh` is used.

::: warning
The startup script enforces direct-IP blocking rules regardless of your custom config. If they are missing, they are appended automatically.
:::

### Key Squid defaults

| Setting | Value |
|---|---|
| Proxy port | `3128` |
| Memory cache | 256 MB |
| Disk cache | 2 GB at `/var/spool/squid` |
| Max object size | 100 MB |
| Connect timeout | 30 seconds |
| DNS timeout | 5 seconds |

## WAF Custom Rules

Create `/config/waf_custom_rules.txt` with one regex pattern per line. Lines starting with `#` are ignored. Patterns are compiled with `re.IGNORECASE`.

Example:
```
# Block requests containing specific keywords
badterm
(?i)malicious-pattern
```

The file is loaded at WAF container startup. Restart the `waf` service to reload.

## SSL Certificates

If `/config/ssl_cert.pem` and `/config/ssl_key.pem` do not exist, they are auto-generated at startup (self-signed, 10-year validity, RSA 2048).

To use your own certificate:

```bash
cp your-cert.pem config/ssl_cert.pem
cp your-key.pem config/ssl_key.pem
docker-compose restart proxy
```

Clients must trust this certificate to avoid browser warnings when HTTPS filtering is enabled.

### Installing the certificate on clients

| Platform | Steps |
|---|---|
| Windows | Import to "Trusted Root Certification Authorities" via `certmgr.msc` |
| macOS | Add to Keychain, then set trust for SSL |
| Linux | Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` |
| Mobile | Email the `.pem` file to the device and install via settings |
