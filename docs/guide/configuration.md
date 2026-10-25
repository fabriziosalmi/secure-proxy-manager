# Configuration

Deployment configuration lives in `.env` in the project root. Docker Compose
reads it to fill the `environment:` entries of `docker-compose.yml` (and of
`compose.prod.yml` on an installer host); a variable reaches a container only
if the compose file passes it to that service. Everything else (the lists,
filtering, inspection, alerts, retention) is a setting stored in the database
and edited in the UI under Settings.

## Authentication (required)

| Variable | Service | Description |
|---|---|---|
| `BASIC_AUTH_USERNAME` | backend | Admin user name. Required |
| `BASIC_AUTH_PASSWORD` | backend | Admin password. It is stored as a bcrypt hash when the user is first created; after that the stored hash is what counts, and the password is changed in the UI, not here. Required: the backend exits if it is empty, shorter than 8 characters, or one of `changeme`, `password`, `admin`, `secret`, `test`, `12345678`, `qwerty` (any case) |
| `SECRET_KEY` | backend | HMAC key for the JWTs. Empty: generated once and kept in `data/.jwt_secret`. Set: at least 32 characters, at least 8 distinct characters, not a known example value, or the backend exits |
| `INTERNAL_ALERT_TOKEN` | backend, waf | Service credential between the two. The WAF sends it on `POST /api/internal/alert`; the backend sends it to the WAF management API (statistics, category and heuristic toggles, reset). Generate with `openssl rand -hex 32`. Empty: the WAF has no credential, so block alerts are dropped and the WAF refuses the backend's management calls |

## Web UI and TLS

| Variable | Default | Description |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | `https://localhost:8443` | Comma-separated origins the backend names in CORS responses and accepts for the WebSocket (a WebSocket from the same host name as the page is accepted too). `*` is dropped |
| `LETSENCRYPT_DOMAIN`, `LETSENCRYPT_EMAIL` | empty | Read by the `web` entrypoint, which tries certbot. The shipped image has no certbot, so with both set it logs the reason and falls back to a mounted or self-signed certificate. To use a CA certificate, mount it at `/etc/nginx/ssl/server.crt` and `/etc/nginx/ssl/server.key`, or terminate TLS on a reverse proxy in front |
| `BACKEND_URL` | `http://backend:5000` | Where nginx sends `/api/` |
| `REQUEST_TIMEOUT` | `120` | nginx read and send timeout for `/api/`, in seconds |

## Proxy and network

| Variable | Default | Description |
|---|---|---|
| `PROXY_BIND_IP` | `0.0.0.0` | Host address port 3128 is published on. `127.0.0.1` limits it to the host |
| `GUI_IP_WHITELIST` | empty | Extra client source addresses or CIDRs (comma or space separated) allowed to use the proxy, beyond private IPv4 ranges, IPv6 unique-local and link-local addresses and localhost. Listed sources follow the same rules as LAN clients. Invalid entries are skipped |
| `PROXY_HOST` | `proxy` | Host name of the proxy container; the backend counts its address as the stack's own traffic, not a client |
| `PROXY_IP` | empty | When set, dnsmasq answers `wpad`, `wpad.local` and `wpad.lan` with this address. dnsmasq is used only by Squid, so LAN clients see these records only if your own DNS serves them too. The PAC file itself is at `http://<host>/wpad.dat` whatever this is set to |
| `WAF_FAIL_OPEN` | `0` | Passed to the proxy only. `1` sets Squid's REQMOD `bypass=1`, so requests pass uninspected while the WAF is unreachable. `0` fails closed |
| `SPM_SQUID_DOMAIN_ACL_MAX` | `250000` | Proxy. Squid denies the blocked domains itself while the list has at most this many names; above it only the DNS sinkhole applies |
| `SPM_DNS_BLOCKLIST_MAX_DOMAINS` | `1000000` | Backend. Most entries the domain blacklist may hold (see [Size limit](./blacklists.md#size-limit)) |

`PROXY_PORT` and `PROXY_CONTAINER_NAME` are passed to the backend, which does
not read them. The proxy port is fixed at 3128 by the port mapping and the
health check in the compose file.

## WAF

| Variable | Default | Description |
|---|---|---|
| `WAF_BLOCK_THRESHOLD` | `10` | Anomaly score at or above which a request is blocked. A value that is not a positive integer is ignored with a warning |
| `WAF_DISABLED_CATEGORIES` | empty | Comma-separated rule categories switched off at start, for example `PROTOCOL_ANOMALY,FINANCIAL_DATA`. `GET /api/waf/categories` lists the names |
| `WAF_H_ENTROPY`, `WAF_H_BEACONING`, `WAF_H_PII`, `WAF_H_SHARDING`, `WAF_H_GHOSTING` | `1` | Heuristics at WAF start (`1`/`0`, `true`/`false`, `yes`/`no`, `on`/`off`) |
| `WAF_H_SEQUENCE` | `0` | Sequence validation heuristic at WAF start |
| `WAF_H_ENTROPY_MAX` | `7.5` | Entropy above which the entropy heuristic scores |
| `WAF_TRAFFIC_LOG_PATH` | `/var/lib/waf/waf_traffic.jsonl` | The WAF's per-request feature log, on the `waf-traffic` volume |

The heuristics are also settings (Settings > Inspection). With
`INTERNAL_ALERT_TOKEN` set, the backend pushes the stored values to the WAF at
start and every 30 seconds until the WAF matches them, so the stored settings
win over the `WAF_H_*` values after start.

## DNS

| Variable | Default | Description |
|---|---|---|
| `DNS_UPSTREAM_1` | `1.1.1.3` | First upstream resolver |
| `DNS_UPSTREAM_2` | `9.9.9.9` | Second upstream resolver |
| `DNS_UPSTREAM_3` | `8.8.8.8` | Third upstream resolver |

## Optional services

| Variable | Default | Description |
|---|---|---|
| `TS_AUTHKEY` | empty | Auth key for the `tailscale` service, started only with `docker compose --profile tailscale up -d` |
| `TAILSCALE_HOSTNAME` | `secure-proxy` | Host name of the `tailscale` container |
| `GRAFANA_ADMIN_PASSWORD` | empty | Grafana in the `observability` profile refuses to start without it. The profile's `./infra/` configuration is not in the repository (see [Getting Started](./getting-started.md#metrics)) |
| `SPM_IMAGE_TAG` | the release | Production compose only: the image tag to pull |
| `COMPOSE_FILE` | | Set to `compose.prod.yml` by the installer |

## Backend variables the compose files do not pass

The backend reads these, with the defaults shown, but the shipped compose files
do not pass them. To use one, add it to the backend's `environment:` list.

| Variable | Default | Description |
|---|---|---|
| `JWT_EXPIRE_DURATION` | `8h` | Access token lifetime (Go duration). Refresh tokens end 7 days after the login whatever this is |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed logins per client address within the window |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | The failed-login window |
| `ENCRYPTION_KEY` | generated | 64 hex characters. Empty: generated once and kept in `data/.enc_key`. Encrypts the alert channel secrets |
| `GEOIP_URL` | empty | Replaces the country feed: `<GEOIP_URL>?cc=<code>` is fetched instead of ipdeny.com and GitHub |
| `WAF_SERVICE_USERNAME`, `WAF_SERVICE_PASSWORD` | `BASIC_AUTH_*` | Basic credential for the WAF management API, used only when `INTERNAL_ALERT_TOKEN` is empty |
| `LOG_FORMAT` | JSON | `pretty` for console-formatted logs |

`DATABASE_PATH` (`/data/proxy_manager.db`), `CONFIG_DIR` (`/config`),
`LOG_PATH` (`/logs/access.log`), `DNS_LOG_PATH` (`/logs/dnsmasq.log`), `PORT`
(`5000`), `WAF_URL` (`http://waf:8080`) and `PROXY_URL`
(`http://proxy:3128`) describe the container layout; leave them alone unless
you change the mounts.

## Squid configuration

`proxy/generate_squid_conf.sh` writes `squid.conf` at container start and on
every reload. The access policy, the ICAP wiring and the log format are always
generated. Extra directives go in:

```
/config/custom_squid_extra.conf
```

The file is appended to the generated configuration. A legacy
`/config/custom_squid.conf` is renamed to `custom_squid_extra.conf` when no
extras file exists. A file that defines `http_port`, `https_port`,
`icap_service`, `cache_dir` or `access_log` is treated as a full configuration
and not appended; the proxy logs a warning instead. If the configuration does
not parse at boot, the proxy regenerates it once without the extras file.

::: warning
Extras come after the generated access policy, which ends in
`http_access deny all`. Squid stops at the first `http_access` rule that
matches, so an `http_access` line in this file is never evaluated. Use it for
tuning directives, and check it with `docker compose exec proxy squid -k parse`.
:::

### Squid values the settings control

| Squid directive | Value |
|---|---|
| `cache_mem` | Settings > Proxy engine > Memory cache (MB), stored default 256 |
| `cache_dir ufs /var/spool/squid` | Settings > Proxy engine > Disk cache (MB), stored default 1000. Until a settings save writes `/config/squid_settings.env`, the generator uses 2000 |
| `maximum_object_size` | 100 MB |
| `request_body_max_size` | 10 MB |
| `connect_timeout`, `dns_timeout` | 30 seconds, 5 seconds |
| `positive_dns_ttl` | 1 minute |

Every save in Settings rewrites `/config/squid_settings.env`; saving a
section that holds proxy settings also reloads the proxy. The generator also reads `PROXY_CACHE_SIZE_MB` and
`PROXY_MEMORY_CACHE_MB`, but the compose files do not pass them to the proxy.

## Default-deny egress (optional)

By default the proxy is a deny-list gateway: clients reach any destination that
is not blocked. Default-deny egress lets local clients reach only the entries
on the Egress allowlist, LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and
Allowed IPs; everything else gets a Squid 403.

It is off by default and set in the UI, not in `.env`:

- Turn on Settings > Filtering > Only allowlisted destinations (the
  `egress_default_deny` setting). The page refuses to save it while the
  allowlist is empty.
- Manage the destinations on the Egress allowlist page. An entry is an
  address, a CIDR range or a domain. A domain entry matches that exact name;
  `.example.com` covers the domain and every name under it; `*.example.com` is
  refused.

See [Lists](./blacklists.md#destination-allowlist-default-deny-egress) for the
API.

## WAF custom rules

Put one regular expression (Go RE2 syntax) per line in
`/config/waf_custom_rules.txt`. Lines starting with `#` are comments. A line
longer than 512 characters, containing a NUL byte, that does not compile, or
that matches the empty string or every one of four benign samples is skipped
with a log line. The rules are read when the WAF starts:

```bash
docker compose restart waf
```

Each custom rule is matched case-insensitively and adds 7 to the anomaly
score. With the default threshold of 10, one custom rule match alone does not
block a request; it blocks when another rule adds at least 3, or when
`WAF_BLOCK_THRESHOLD` is 7 or lower.

```
# Raise the score of requests that mention an internal codename
project-codename
pre-release-build
```

## SSL bump CA (HTTPS inspection)

If `/config/ssl_cert.pem` or `/config/ssl_key.pem` is missing, the proxy
generates an RSA 2048 CA valid for 825 days at start. To use your own CA, or to
rotate this one, follow
[Rotating the SSL-bump CA](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/DEPLOYMENT.md#rotating-the-ssl-bump-ca).

Clients must trust the CA while HTTPS inspection is on. Download it from
Settings > Inspection > Download the CA certificate (.pem), which also shows
these steps:

| Platform | Steps (from the folder with `secure-proxy-ca.pem`) |
|---|---|
| Windows | Administrator prompt: `certutil -addstore -f Root secure-proxy-ca.pem` |
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain secure-proxy-ca.pem` |
| Debian, Ubuntu | `sudo cp secure-proxy-ca.pem /usr/local/share/ca-certificates/secure-proxy-ca.crt && sudo update-ca-certificates` (the name must end in `.crt`) |
| Fedora, RHEL | `sudo cp secure-proxy-ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust` |
| iOS, iPadOS | Open the file on the device, install it in Settings, General, VPN and Device Management, then turn it on in Settings, General, About, Certificate Trust Settings |
| Android | Settings, Security, Encryption and credentials, Install a certificate, CA certificate. Apps built for Android 7 or later do not trust a user-installed CA |
| Firefox | Settings, Privacy and Security, Certificates, View Certificates, Authorities, Import |
