# Architecture

Secure Proxy Manager is a multi-service Docker Compose application. Each service has a single responsibility.

## Services

```
Browser / Client
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  ui  (port 8011)                                                │
│  Nginx reverse proxy                                            │
│  Serves compiled React SPA static assets                        │
│  Proxies /api/* and /api/ws/* to backend:5000                   │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP / WebSocket
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  backend  (127.0.0.1:5001 → container:5000)                     │
│  FastAPI + Uvicorn                                              │
│  SQLite (WAL mode) at /data/secure_proxy.db                     │
│  REST API + WebSocket log streaming                             │
│  Writes blacklists/whitelists to /config/*.txt                  │
└────────┬───────────────────────────────────────────────────────┘
         │ reads/writes /config
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  proxy  (port 3128)                                             │
│  Squid + supervisor                                             │
│  startup.sh generates squid.conf from base config + settings   │
│  Reads /config/ip_blacklist.txt, /config/domain_blacklist.txt   │
│  Reads /config/ip_whitelist.txt                                 │
│  Logs to /var/log/squid/access.log (tailed by backend)         │
│                         │ ICAP                                  │
│                         ▼                                       │
│              waf  (port 1344)                                   │
│              Go ICAP server                                     │
│              171 regex rules + 7 behavioral heuristics          │
│              Notifies backend via /api/internal/alert           │
└─────────────────────────────────────────────────────────────────┘
```

## Service details

### `ui` — Nginx reverse proxy (port 8011)

- Serves the compiled React SPA static assets
- All `/api/*` and `/api/ws/*` paths are reverse-proxied to the backend
- Applies security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- Configuration is generated from `nginx.conf.template` at container startup

### `backend` — FastAPI (port 5000 internal, 127.0.0.1:5001 external)

- REST API for all management operations
- WebSocket endpoint at `/api/ws/logs` for real-time log streaming
- SQLite database in WAL mode for concurrent read/write
- Tails the Squid access log and parses new entries into the database
- Generates and writes blacklist/whitelist text files to `/config/` after each change
- Sends a `squid -k reconfigure` signal to the proxy container after config changes

### `proxy` — Squid (port 3128)

- Core forward proxy engine
- `startup.sh` runs on container start: generates `squid.conf`, validates syntax, initializes cache
- ICAP integration forwards all requests to the WAF service for inspection
- Direct IP access is blocked by ACL rules (optional bypass via whitelist)
- SSL bump with auto-generated certificate at `/config/ssl_cert.pem`

### `waf` — Go ICAP (port 1344)

- Listens for ICAP `REQMOD` requests from Squid
- Applies 171 regex rules across 21 categories (SQL injection, XSS, directory traversal, command injection, unicode homograph obfuscation, and more)
- 7 behavioral heuristics: entropy thresholding, C2 beaconing detection, PII leak detection, destination sharding, protocol ghosting, header morphing, sequence validation
- Anomaly scoring with configurable threshold (`WAF_BLOCK_THRESHOLD`)
- Shannon entropy analysis via JSONL traffic profiling
- Supports custom rules from `/config/waf_custom_rules.txt`
- Rate-limits repeat offenders with a tar-pit delay
- Notifies the backend API of blocks via `POST /api/internal/alert`

### `dns` — dnsmasq DNS blackhole

- Internal DNS resolver for the proxy network
- Sinkhole-blocks domains from the domain blacklist at the DNS layer (resolves to `0.0.0.0`)
- Domain whitelist entries are excluded from the blocklist
- Upstream resolvers default to `1.1.1.3`, `9.9.9.9`, `8.8.8.8` (configurable)

### `tailscale` — Tailscale sidecar (optional)

- Secure overlay network for remote access
- Activated with the `--profile tailscale` compose flag
- Requires `TS_AUTHKEY` environment variable



1. Client sends HTTP request to Squid (port 3128)
2. Squid sends `ICAP REQMOD` to WAF — WAF inspects URL and headers
3. If WAF blocks: returns 403 to client, notifies backend
4. If WAF allows: Squid checks ACLs (IP blacklist, domain blacklist, direct IP rules, whitelist)
5. If Squid allows: request is forwarded to the destination server
6. Squid writes an access log entry
7. Backend log-tailer picks up the entry, writes it to SQLite, and broadcasts it over WebSocket to connected UI clients

## Volumes

| Volume | Purpose |
|---|---|
| `./config` | Shared config between backend and proxy (blacklists, SSL cert) |
| `./data` | SQLite database (backend) |
| `./logs` | Application logs |
