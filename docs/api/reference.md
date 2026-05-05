# API Reference

Base URLs:

- Through the `web` reverse proxy (recommended): `https://localhost:8443/api`
- Directly to the backend (localhost only): `http://127.0.0.1:5001/api`

Every endpoint accepts either HTTP Basic or JWT bearer authentication unless noted otherwise. Most successful responses follow the envelope `{"status": "success", "data": ...}`; the authentication endpoints (`/api/auth/login`, `/api/auth/refresh`, `/api/ws-token`, `/api/logout`, `/api/change-password`) return a flat object with `status` and the payload fields at the top level. Errors are always `{"status": "error", "detail": "..."}`.

## Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Validate credentials, return access and refresh JWTs |
| `POST` | `/api/auth/refresh` | Exchange a refresh token for a new pair |
| `POST` | `/api/logout` | Revoke the JWT used to authenticate the request |
| `POST` | `/api/change-password` | Change the admin password |
| `GET`  | `/api/ws-token` | Issue a single-use WebSocket token |
| `GET`  | `/health` | Liveness check (no auth) |
| `GET`  | `/api/health` | Liveness check via API prefix (no auth) |

## Blacklist and whitelist

| Method | Path | Description |
|---|---|---|
| `GET`    | `/api/ip-blacklist` | List IP blacklist entries |
| `POST`   | `/api/ip-blacklist` | Add an IP blacklist entry |
| `DELETE` | `/api/ip-blacklist/{id}` | Delete an IP blacklist entry |
| `POST`   | `/api/ip-blacklist/bulk-delete` | Delete multiple IP blacklist entries |
| `DELETE` | `/api/ip-blacklist/clear-all` | Remove all IP blacklist entries |
| `POST`   | `/api/ip-blacklist/import` | Import IPs from URL or inline content |
| `GET`    | `/api/domain-blacklist` | List domain blacklist entries |
| `POST`   | `/api/domain-blacklist` | Add a domain blacklist entry |
| `DELETE` | `/api/domain-blacklist/{id}` | Delete a domain blacklist entry |
| `POST`   | `/api/domain-blacklist/bulk-delete` | Delete multiple domain blacklist entries |
| `DELETE` | `/api/domain-blacklist/clear-all` | Remove all domain blacklist entries |
| `POST`   | `/api/domain-blacklist/import` | Import domains from URL or inline content |
| `POST`   | `/api/blacklists/import` | Unified import (`type` = `"ip"` or `"domain"`) |
| `POST`   | `/api/blacklists/import-geo` | Import country-IP ranges by country code |
| `GET`    | `/api/ip-whitelist` | List IP whitelist entries |
| `POST`   | `/api/ip-whitelist` | Add an IP whitelist entry |
| `DELETE` | `/api/ip-whitelist/{id}` | Delete an IP whitelist entry |
| `GET`    | `/api/domain-whitelist` | List domain whitelist entries (DNS-bypass) |
| `POST`   | `/api/domain-whitelist` | Add a domain whitelist entry |
| `DELETE` | `/api/domain-whitelist/{id}` | Delete a domain whitelist entry |

## Logs and analytics

| Method | Path | Description |
|---|---|---|
| `GET`  | `/api/logs` | Paginated proxy access logs |
| `GET`  | `/api/logs/stats` | Aggregate counts (total, blocked, IP blocks) |
| `GET`  | `/api/logs/timeline` | Per-hour traffic series |
| `POST` | `/api/logs/clear` | Clear all logs |
| `POST` | `/api/logs/clear-old` | Delete logs older than the retention period |
| `GET`  | `/api/status` | Proxy service status |
| `GET`  | `/api/traffic/statistics` | Traffic statistics |
| `GET`  | `/api/clients/statistics` | Client statistics |
| `GET`  | `/api/domains/statistics` | Top accessed domains |
| `GET`  | `/api/security/score` | Security score and recommendations |
| `GET`  | `/api/security/cve` | CVE check for the bundled Squid version |
| `GET`  | `/api/analytics/shadow-it` | Shadow-IT detection |
| `GET`  | `/api/analytics/user-agents` | Service-type breakdown by user agent |
| `GET`  | `/api/analytics/file-extensions` | File extension distribution |
| `GET`  | `/api/analytics/top-domains` | Top domains for the cloud visualisation |
| `GET`  | `/api/dashboard/summary` | Aggregated dashboard data in a single call |
| `GET`  | `/api/audit-log` | Audit log of administrative actions |
| `GET`  | `/api/waf/stats` | WAF statistics |
| `GET`  | `/api/waf/categories` | WAF rule categories with toggle state |
| `POST` | `/api/waf/categories/toggle` | Enable or disable a category at runtime |
| `POST` | `/api/waf/test-rule` | Evaluate a regex rule against a sample request |
| `POST` | `/api/counters/reset` | Reset all counters |

## Settings and maintenance

| Method | Path | Description |
|---|---|---|
| `GET`    | `/api/settings` | List all settings |
| `PUT`    | `/api/settings/{name}` | Update a single setting |
| `POST`   | `/api/settings` | Bulk update settings (flat name → value object) |
| `GET`    | `/api/database/size` | Database file size |
| `GET`    | `/api/database/export` | Export database as JSON (sensitive columns redacted) |
| `GET`    | `/api/database/stats` | Row counts and database size |
| `POST`   | `/api/database/optimize` | Run `VACUUM` + `REINDEX` |
| `POST`   | `/api/database/reset` | Truncate every exported table except `users` |
| `GET`    | `/api/cache/statistics` | Squid cache metrics |
| `POST`   | `/api/maintenance/reload-config` | Signal Squid to reload configuration |
| `POST`   | `/api/maintenance/reload-dns` | Reload dnsmasq |
| `POST`   | `/api/maintenance/clear-cache` | Clear the Squid disk cache |
| `GET`    | `/api/maintenance/backup-config` | Download a configuration backup |
| `POST`   | `/api/maintenance/restore-config` | Restore configuration from a backup |
| `GET`    | `/api/maintenance/check-cert-security` | Inspect SSL bump certificate strength |
| `GET`    | `/api/security/download-ca` | Download the proxy CA certificate |
| `GET`    | `/api/security/rate-limits` | List IPs that are currently rate-limited |
| `DELETE` | `/api/security/rate-limits/{ip}` | Clear the rate-limit lockout for an IP |
| `POST`   | `/api/notifications/test` | Send a test notification (Gotify, Telegram, webhook, Teams, SIEM) |

## Internal

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/internal/alert` | Receives WAF block notifications. Authentication required; the WAF authenticates with `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` |
| `POST` | `/api/dns/detect` | Probe a target subnet for Pi-hole or AdGuard instances |

## WebSocket

| Path | Protocol | Description |
|---|---|---|
| `/api/ws/logs?token=<token>` | `ws://` or `wss://` | Real-time log stream (single-use token) |
