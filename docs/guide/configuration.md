# Configuration

All configuration lives in the `.env` file in the project root, which is read by `docker-compose.yml`. A small number of additional, mostly-optional values can be overridden by exporting them in the calling shell.

## Authentication (required)

| Variable | Description |
|---|---|
| `BASIC_AUTH_USERNAME` | HTTP Basic auth username for the web UI and API |
| `BASIC_AUTH_PASSWORD` | HTTP Basic auth password (use a strong password) |
| `SECRET_KEY` | HMAC key used to sign JWT access and refresh tokens. Auto-generated when empty, but tokens then invalidate on every restart; set a stable value in production |

## TLS for the web UI

| Variable | Default | Description |
|---|---|---|
| `LETSENCRYPT_DOMAIN` | _empty_ | Used only by an image that includes certbot; the shipped image does not include certbot, so the `web` container cannot obtain a Let's Encrypt certificate itself: with these set it serves a self-signed certificate and logs why. To use a CA certificate, mount it at `/etc/nginx/ssl/server.crt` and `/etc/nginx/ssl/server.key`, or terminate TLS on a reverse proxy in front |
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
| `GUI_IP_WHITELIST` | _empty_ | Extra client source IPs or CIDRs (comma- or space-separated) allowed to use the proxy, beyond RFC1918 and localhost. Listed sources are governed by the same rules as LAN clients |

## WAF

| Variable | Default | Description |
|---|---|---|
| `INTERNAL_ALERT_TOKEN` | (empty) | Service credential between the backend and the WAF: the WAF presents it on `POST /api/internal/alert`, and the backend presents it to the WAF management API (stats, category and heuristic toggles, reset). Without it the dashboard reports the WAF statistics as unavailable and toggles do not apply. Generate with `openssl rand -hex 32` and set it on **both** the `waf` and `backend` services. It replaces `BASIC_AUTH_*` on that path so the WAF, the component that parses attacker-controlled request bodies, no longer holds the admin credential. Left empty, the backend still accepts admin auth there, but the shipped compose no longer passes the admin credential to the WAF, so alerts are dropped with a log line in both containers |
| `WAF_BLOCK_THRESHOLD` | `10` | Anomaly score at or above which a request is blocked |
| `WAF_DISABLED_CATEGORIES` | _empty_ | Comma-separated rule category names to disable globally (for example `DEBUG_LEAK,RESPONSE_ANOMALY`) |
| `WAF_H_ENTROPY` | `1` | Toggle the Shannon entropy heuristic |
| `WAF_H_ENTROPY_MAX` | `7.5` | Maximum allowed entropy before the heuristic contributes to the score |
| `WAF_H_BEACONING` | `1` | Toggle C2 beaconing detection |
| `WAF_H_PII` | `1` | Toggle the PII leak heuristic |
| `WAF_H_SHARDING` | `1` | Toggle the destination sharding heuristic |
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

`proxy/generate_squid_conf.sh` generates `squid.conf` at container start and on every reload. You cannot replace the base configuration: the access policy, the direct-IP block ACLs, the ICAP wiring and the log paths are always generated. You can append extra directives by placing them at:

```
/config/custom_squid_extra.conf
```

The file is appended to the generated `squid.conf`. If a legacy `/config/custom_squid.conf` exists, it is renamed to `custom_squid_extra.conf` automatically. A file that defines `http_port`, `https_port`, `icap_service`, `cache_dir` or `access_log` is treated as a full configuration and is not appended; the proxy logs a warning instead.

::: warning
Extras are appended after the generated access policy, which ends in `http_access deny all`. Squid stops at the first `http_access` rule that matches, so an `http_access` line in this file is never evaluated. Use the extras file for tuning directives, and test it with `docker compose exec proxy squid -k parse`.
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

## Default-deny egress (optional)

By default the proxy is a deny-list gateway: clients may reach any destination that is not blacklisted. You can optionally switch it into a default-deny egress gateway, where local clients can reach **only** the destinations on an explicit allowlist and everything else is refused with a Squid 403.

This mode is off by default and is configured entirely from the web UI and API, not via `.env`:

- Enable it with the **Default-deny egress** toggle on the **Settings** page (next to SSL inspection). It maps to the `egress_default_deny` setting, which defaults to `false`.
- Manage allowed destinations on the **Egress Allowlist** page (add, delete, search, paginate). Each entry is either an IP/CIDR or a domain; the type is auto-classified when you add it. A client is allowed if the destination matches the IP allowlist or the domain allowlist; LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and the addresses on Allowed IPs stay reachable. A domain entry matches that exact name; `.example.com` covers the domain and every name under it.

When the toggle is off, behaviour is unchanged and no destinations are blocked by this feature. Use default-deny egress when you need a strict "allow only these destinations" outbound policy: for example, letting an application reach only an approved ACME server, package mirror, or internal API.

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
