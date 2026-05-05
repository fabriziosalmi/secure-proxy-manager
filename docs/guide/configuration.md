# Configuration

All configuration lives in the `.env` file in the project root, which is read by `docker-compose.yml`. A small number of additional, mostly-optional values can be overridden by exporting them in the calling shell.

## Authentication (required)

| Variable | Description |
|---|---|
| `BASIC_AUTH_USERNAME` | HTTP Basic auth username for the web UI and API |
| `BASIC_AUTH_PASSWORD` | HTTP Basic auth password (use a strong password) |
| `SECRET_KEY` | HMAC key used to sign JWT access and refresh tokens. Auto-generated when empty, but tokens then invalidate on every restart — set a stable value in production |

## TLS for the web UI

| Variable | Default | Description |
|---|---|---|
| `LETSENCRYPT_DOMAIN` | _empty_ | When set together with `LETSENCRYPT_EMAIL`, the `web` service obtains a real certificate via Let's Encrypt |
| `LETSENCRYPT_EMAIL` | _empty_ | Email address used for the ACME account |
| `CORS_ALLOWED_ORIGINS` | `https://localhost:8443` | Comma-separated list of origins allowed by the backend CORS policy. Add your public hostname when fronting the UI behind your own domain. |

## Networking

| Variable | Default | Description |
|---|---|---|
| `BACKEND_URL` | `http://backend:5000` | Backend URL the `web` service uses on the internal Docker network |
| `REQUEST_TIMEOUT` | `120` | Web UI request timeout in seconds |
| `PROXY_HOST` | `proxy` | Squid container hostname (used by the backend to send reload requests) |
| `PROXY_PORT` | `3128` | Squid proxy port |
| `PROXY_BIND_IP` | `0.0.0.0` | Host interface that the Squid port is bound to. Set to `127.0.0.1` to restrict access to the local machine |
| `PROXY_CONTAINER_NAME` | `secure-proxy-manager-proxy` | Docker container name used when issuing reconfigure signals |
| `PROXY_IP` | _empty_ | LAN IP of the host. When set, dnsmasq publishes a WPAD record for browser auto-discovery |
| `GUI_IP_WHITELIST` | _empty_ | Comma-separated client IPs allowed to connect to the proxy on the management ports even when blocked by other rules |

## WAF

| Variable | Default | Description |
|---|---|---|
| `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD` | (required) | Used to authenticate the WAF when it calls back to `POST /api/internal/alert` |
| `WAF_BLOCK_THRESHOLD` | `10` | Anomaly score at or above which a request is blocked |
| `WAF_DISABLED_CATEGORIES` | _empty_ | Comma-separated rule category names to disable globally (for example `DEBUG_LEAK,RESPONSE_ANOMALY`) |
| `WAF_H_ENTROPY` | `1` | Toggle the Shannon entropy heuristic |
| `WAF_H_ENTROPY_MAX` | `7.5` | Maximum allowed entropy before the heuristic contributes to the score |
| `WAF_H_BEACONING` | `1` | Toggle C2 beaconing detection |
| `WAF_H_PII` | `1` | Toggle the PII leak heuristic |
| `WAF_H_SHARDING` | `1` | Toggle the destination sharding heuristic |
| `WAF_H_MORPHING` | `0` | Toggle the header morphing heuristic (off by default; noisy) |
| `WAF_H_GHOSTING` | `1` | Toggle the protocol ghosting heuristic |
| `WAF_H_SEQUENCE` | `0` | Toggle the request sequence heuristic (off by default; needs tuning) |

Each toggle accepts `1`/`0` or `true`/`false`.

## DNS

| Variable | Default | Description |
|---|---|---|
| `DNS_UPSTREAM_1` | `1.1.1.3` | Primary upstream resolver (Cloudflare malware-blocking) |
| `DNS_UPSTREAM_2` | `9.9.9.9` | Secondary upstream resolver (Quad9) |
| `DNS_UPSTREAM_3` | `8.8.8.8` | Tertiary upstream resolver (Google) |

## Tailscale (optional sidecar)

| Variable | Default | Description |
|---|---|---|
| `TS_AUTHKEY` | _empty_ | Tailscale authentication key. The sidecar refuses to start without one |
| `TAILSCALE_HOSTNAME` | `secure-proxy` | Hostname registered on the tailnet |

The sidecar only runs under `docker compose --profile tailscale`.

## Squid configuration

The `proxy/startup.sh` script generates `squid.conf` at container start. You cannot replace the base configuration entirely — the startup script enforces certain protections (direct-IP block ACLs, ICAP integration, log paths) regardless. You can append custom directives by placing them at:

```
/config/custom_squid_extra.conf
```

The file is concatenated to the generated `squid.conf` at startup. If a legacy `/config/custom_squid.conf` exists, it is renamed to `custom_squid_extra.conf` automatically.

::: warning
Custom directives are appended after the base configuration; later directives override earlier ones in Squid only for a subset of options. Test your additions with `docker compose exec proxy squid -k parse` before relying on them.
:::

### Default Squid settings

| Setting | Default |
|---|---|
| Listening port | `3128` |
| Memory cache (`PROXY_MEMORY_CACHE_MB`) | `256` MB |
| Disk cache (`PROXY_CACHE_SIZE_MB`) | `2000` MB at `/var/spool/squid` |
| Maximum object size | `100` MB |
| `connect_timeout` | `30 seconds` |
| `dns_timeout` | `5 seconds` |

These can be overridden through the **Settings** page of the web UI, which writes the values to `/config/squid_settings.env`.

## WAF custom rules

Create `/config/waf_custom_rules.txt` with one regex per line. Lines starting with `#` are ignored. Each line is rejected if longer than 512 characters or if it contains a NUL byte. Restart the `waf` service to reload:

```bash
docker compose restart waf
```

Example:

```
# Block requests containing internal codename
project-codename
(?i)pre-release-build
```

## SSL certificates (HTTPS filtering)

If `/config/ssl_cert.pem` and `/config/ssl_key.pem` are missing, the proxy generates a self-signed RSA-2048 certificate valid for 3 650 days (ten years) at first start.

To install your own certificate:

```bash
cp your-cert.pem config/ssl_cert.pem
cp your-key.pem config/ssl_key.pem
docker compose restart proxy
```

Clients must trust this certificate to avoid browser warnings when SSL bump (HTTPS filtering) is active.

### Installing the CA on clients

| Platform | Steps |
|---|---|
| Windows | Import to **Trusted Root Certification Authorities** via `certmgr.msc` |
| macOS | Add to **Keychain Access**, then mark **Always Trust** for SSL |
| Linux | Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates` |
| iOS / Android | Email the `.pem` file to the device, install via Settings → General → VPN and Device Management (iOS) or Security → Install certificate (Android) |
