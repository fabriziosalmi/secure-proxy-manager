# Architecture

Secure Proxy Manager is a multi-service Docker Compose application. Each service has a single responsibility.

## Services

```
Browser / Client
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  ui  (port 8011)                                                │
│  Flask reverse proxy                                            │
│  Serves React SPA static assets                                 │
│  Proxies /api/* and /ws/* to backend:5000                       │
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
│              Python ICAP server                                 │
│              Inspects request URLs for attack patterns          │
│              Notifies backend via /api/internal/alert           │
└─────────────────────────────────────────────────────────────────┘
```

## Service details

### `ui` — Flask reverse proxy (port 8011)

- Serves the compiled React SPA from `ui/src/`
- All `/api/*` and `/ws/*` paths are reverse-proxied to the backend
- Applies security headers via Flask-Talisman (CSP, HSTS, etc.)
- Handles HTTP Basic Auth for API requests on behalf of the frontend

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

### `waf` — Python ICAP (port 1344)

- Listens for ICAP `REQMOD` requests from Squid
- Applies regex rules for SQL injection, XSS, directory traversal, command injection, unicode homograph obfuscation
- Supports custom rules from `/config/waf_custom_rules.txt`
- Rate-limits repeat offenders with a tar-pit delay
- Notifies the backend API of blocks via `POST /api/internal/alert`

## Data flow

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
