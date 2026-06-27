# Architecture

Secure Proxy Manager is a multi-service Docker Compose application. Each service has a single responsibility.

## Services

```
                            Browser / Client
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  web  (host ports 80, 443, 8011, 8443)                          │
│  Nginx reverse proxy + compiled React SPA static assets         │
│  Reverse-proxies /api/* and /api/ws/* to backend:5000           │
│  Optional Let's Encrypt for real certificates                   │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP / WebSocket (frontend network)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  backend  (127.0.0.1:5001 → container:5000)                     │
│  Go (chi router) + SQLite in WAL mode at /data/secure_proxy.db  │
│  REST API, WebSocket log stream, JWT issuance, audit log        │
│  Workers: log tailer, blocklist auto-refresh, CVE checker       │
│  Writes blacklist/whitelist files to /config/*.txt              │
└────────┬───────────────────────────────────────────────────────┘
         │ writes /config files; SIGHUP/reload the proxy
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  proxy  (host port 3128)                                        │
│  Squid + supervisor (proxy-internal network)                    │
│  startup.sh generates squid.conf and applies dynamic settings   │
│  Reads /config/{ip,domain}_blacklist.txt and ip_whitelist.txt   │
│  Logs to /var/log/squid/access.log (mounted as ./logs)          │
│                         │ ICAP REQMOD + RESPMOD                 │
│                         ▼                                       │
│              waf  (internal port 1344)                          │
│              Go ICAP server                                     │
│              170 regex rules + 7 behavioural heuristics         │
│              Notifies backend at POST /api/internal/alert       │
│                                                                 │
│              dns  (internal port 53)                            │
│              dnsmasq sinkhole (resolves blocked domains to      │
│              0.0.0.0); whitelisted domains are excluded         │
└─────────────────────────────────────────────────────────────────┘
```

The `frontend` network connects `web` to `backend`. The `proxy-internal` network is declared `internal: true` and connects `backend`, `proxy`, `waf`, and `dns`; nothing on this network can reach the public internet directly.

## Service details

### `web` — Nginx reverse proxy

- Serves the compiled React SPA.
- Reverse-proxies `/api/*` and `/api/ws/*` to the backend at `backend:5000`.
- Applies HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
- Generates its Nginx configuration at startup. When `LETSENCRYPT_DOMAIN` and `LETSENCRYPT_EMAIL` are set, it provisions Let's Encrypt certificates; otherwise a self-signed certificate is used.

### `backend` — Go API server

- Built from `backend-go/` using the chi router.
- Container listens on port `5000`; the host bind is `127.0.0.1:5001:5000`, so the API is not reachable from the LAN.
- SQLite database in WAL mode for concurrent reads and writes (`/data/secure_proxy.db`).
- `log_tailer` worker reads `/var/log/squid/access.log` and inserts parsed entries into the `proxy_logs` table.
- `blacklist_refresh` worker re-imports configured public lists at the interval defined by the `auto_refresh_hours` setting.
- Applies blacklist and whitelist changes by writing files under `/config/` and signalling the proxy or DNS service to reload.
- When default-deny egress is enabled, exports the `dst_allowlist` table to `/config/dst_allow_ip.txt` (CIDR entries) and `/config/dst_allow_domain.txt` (domain entries), both written atomically, and writes the flag file `/config/egress_default_deny` to reflect the toggle.
- WebSocket endpoint at `/api/ws/logs` broadcasts new log entries to connected UI clients.
- Liveness at `/livez` (and `/health`); readiness at `/readyz` (pings the database) — the container healthcheck uses readiness, so a wedged database is reported as unhealthy.
- Prometheus metrics at `/metrics` (RED metrics per route, DB connection-pool gauges, per-worker heartbeats, Go runtime), plus a structured access-log line per request. The endpoint is internal-only — nginx does not proxy it.

### `proxy` — Squid

- Forward proxy on port `3128`.
- `proxy/startup.sh` generates `squid.conf` from a base template plus optional extras from `/config/custom_squid_extra.conf`, validates with `squid -k parse`, then initialises the cache with `squid -z`.
- `blacklist_watchdog.py` polls the `/config` list files by mtime (roughly every two seconds) — including `dst_allow_ip.txt` and `dst_allow_domain.txt` — and runs `squid -k reconfigure` when one changes, so backend writes to the allowlist take effect without a restart.
- ICAP integration forwards REQMOD and RESPMOD adaptations to the WAF.
- Direct-IP access is blocked by ACL rules; whitelisted destination IPs in `ip_whitelist.txt` bypass that block.
- When `/config/egress_default_deny` is present, `startup.sh` injects two ACLs — `acl egress_dst_allow_ip dst "<path>/dst_allow_ip.txt"` and `acl egress_dst_allow_dom dstdomain "<path>/dst_allow_domain.txt"` — and, immediately before the first `http_access allow localnet`, the rule `http_access deny localnet !egress_dst_allow_ip !egress_dst_allow_dom`. Local clients are then allowed only when the destination matches the IP allowlist or the domain allowlist; every other destination is refused. The toggle is off by default, so this mode is opt-in and the proxy otherwise reaches any destination not on a blacklist.
- SSL bump uses the CA certificate at `/config/ssl_cert.pem` (auto-generated on first start if absent).
- The container `iptables` rules redirect transparent intercepted traffic on ports 80 and 443 to 3128 inside the container.

### `waf` — Go ICAP server

- Listens for ICAP `REQMOD` (and limited `RESPMOD`) on port `1344`.
- Applies 170 regex rules across 21 categories (SQL injection, XSS, directory traversal, command injection, Unicode homograph obfuscation, response XSS, response secret leak, and more).
- Seven behavioural heuristics: entropy thresholding, C2 beaconing detection, PII leak counting, destination sharding, protocol ghosting, header morphing, sequence validation. Each heuristic is individually toggleable via the `WAF_H_*` environment variables.
- Anomaly scoring with a configurable threshold (`WAF_BLOCK_THRESHOLD`, default `10`).
- Anti-evasion input normalization: multi-pass URL/HTML decode, inline SQL/HTML comment stripping (so `UNION/**/SELECT` is caught), and NFKC Unicode folding to defeat fullwidth/homoglyph keyword variants.
- Loads custom regex patterns from `/config/waf_custom_rules.txt` at startup (one pattern per line, `#` for comments); over-broad patterns that would match everything are rejected.
- Tar-pits repeat offenders: clients seen with three or more blocks within sixty seconds are delayed by ten seconds per request.
- Notifies the backend of blocks via authenticated `POST /api/internal/alert`.
- Emits an `ISTag` (RFC 3507) on ICAP responses, derived from the ruleset and bumped on category toggles, so Squid invalidates cached verdicts when rules change.
- Prometheus metrics at `:8080/metrics`: aggregate counters, a REQMOD latency histogram, and coverage-gap counters (traffic-log enabled/dropped, oversize bodies, uninspectable compressed responses).

### `dns` — dnsmasq sinkhole

- Provides DNS resolution to the proxy via the internal network.
- Sinkhole-resolves blacklisted domains to `0.0.0.0`. Domain whitelist entries are excluded from the sinkhole list, so they resolve normally even if they also appear in the blacklist.
- Upstream resolvers default to `1.1.1.3`, `9.9.9.9`, `8.8.8.8` (override with `DNS_UPSTREAM_1/2/3`).
- When `PROXY_IP` is set, dnsmasq publishes a WPAD record so browsers on the LAN can auto-discover the proxy.

### `tailscale` — optional sidecar

- Joins the stack to a Tailscale tailnet for secure remote access.
- Activated with `docker compose --profile tailscale up -d`.
- Requires `TS_AUTHKEY` (and optionally `TAILSCALE_HOSTNAME`).

## Request flow

1. The client sends an HTTP or HTTPS request to Squid on port `3128`.
2. Squid issues an ICAP `REQMOD` to the WAF. The WAF inspects the URL, headers, and (for write methods) the request body; if the anomaly score exceeds the threshold it returns an HTTP 403 ICAP response and notifies the backend.
3. If the WAF allows the request, Squid evaluates its ACLs: IP blacklist (source), domain blacklist (destination), direct-IP rule, and the IP whitelist that bypasses it. When default-deny egress is enabled, a local client is allowed only if the destination is on the IP or domain allowlist; any other destination is refused with a 403.
4. If Squid allows the request, it is forwarded to the destination. For HTTPS with SSL bump enabled, the connection is decrypted, inspected, and re-encrypted.
5. Squid writes an entry to `/var/log/squid/access.log`.
6. The backend `log_tailer` reads the new entry, parses it, inserts a row into `proxy_logs`, and broadcasts it to subscribed WebSocket clients.

## Volumes

| Volume | Purpose |
|---|---|
| `./config` | Shared configuration: blacklist/whitelist text files, egress allowlist files (`dst_allow_ip.txt`, `dst_allow_domain.txt`) and the `egress_default_deny` flag, SSL certificate, custom Squid extras, dynamic settings |
| `./data` | SQLite database |
| `./logs` | Mounted as `/var/log/squid` inside the proxy container |
| `squid-cache` (named) | Squid disk cache |
| `letsencrypt` (named) | Let's Encrypt certificates and account state |
| `tailscale-data` (named) | Tailscale node state (only when the profile is active) |
