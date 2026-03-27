# API Reference

Base URLs:

- **Via UI proxy** (recommended): `http://localhost:8011/api`
- **Direct backend access** (localhost only): `http://localhost:5001/api`

All endpoints require HTTP Basic Authentication unless noted otherwise.

## Endpoint summary

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Validate credentials, returns JWT token |
| `POST` | `/api/logout` | Invalidate current session |
| `POST` | `/api/change-password` | Change the admin password |
| `GET` | `/api/ws-token` | Get a single-use WebSocket auth token |
| `GET` | `/health` | Health check (no auth required) |
| `GET` | `/api/health` | Health check via API prefix (no auth required) |

### Blacklist & Whitelist

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/ip-blacklist` | List IP blacklist entries |
| `POST` | `/api/ip-blacklist` | Add an IP blacklist entry |
| `DELETE` | `/api/ip-blacklist/{id}` | Delete an IP blacklist entry |
| `POST` | `/api/ip-blacklist/bulk-delete` | Delete multiple IP blacklist entries |
| `DELETE` | `/api/ip-blacklist/clear-all` | Remove all IP blacklist entries |
| `GET` | `/api/domain-blacklist` | List domain blacklist entries |
| `POST` | `/api/domain-blacklist` | Add a domain blacklist entry |
| `DELETE` | `/api/domain-blacklist/{id}` | Delete a domain blacklist entry |
| `POST` | `/api/domain-blacklist/bulk-delete` | Delete multiple domain blacklist entries |
| `DELETE` | `/api/domain-blacklist/clear-all` | Remove all domain blacklist entries |
| `POST` | `/api/blacklists/import` | Import from URL or inline content |
| `POST` | `/api/blacklists/import-geo` | Import geo-based IP block by country code |
| `GET` | `/api/ip-whitelist` | List IP whitelist entries |
| `POST` | `/api/ip-whitelist` | Add an IP whitelist entry |
| `DELETE` | `/api/ip-whitelist/{id}` | Delete an IP whitelist entry |
| `GET` | `/api/domain-whitelist` | List domain whitelist entries (DNS bypass) |
| `POST` | `/api/domain-whitelist` | Add a domain to the DNS whitelist |
| `DELETE` | `/api/domain-whitelist/{id}` | Delete a domain whitelist entry |

### Logs & Analytics

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/logs` | Get log entries (`?limit=N`) |
| `GET` | `/api/logs/stats` | Get log statistics |
| `GET` | `/api/logs/timeline` | 24h traffic timeline |
| `POST` | `/api/logs/clear` | Clear all logs |
| `POST` | `/api/logs/clear-old` | Delete logs older than the retention period |
| `GET` | `/api/status` | Get proxy service status |
| `GET` | `/api/traffic/statistics` | Traffic statistics |
| `GET` | `/api/clients/statistics` | Client statistics |
| `GET` | `/api/domains/statistics` | Top accessed domains statistics |
| `GET` | `/api/security/score` | Get security score |
| `GET` | `/api/analytics/shadow-it` | Shadow IT detection (35+ SaaS services) |
| `GET` | `/api/analytics/user-agents` | Service type breakdown |
| `GET` | `/api/analytics/file-extensions` | File extension distribution |
| `GET` | `/api/analytics/top-domains` | Top accessed domains for cloud visualization |
| `GET` | `/api/dashboard/summary` | Aggregated dashboard data in a single call |
| `GET` | `/api/analytics/report/pdf` | Download PDF analytics report |
| `GET` | `/api/waf/stats` | WAF engine statistics (rules, blocks, entropy) |
| `POST` | `/api/counters/reset` | Reset all counters |

### Settings & Maintenance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings` | Get all settings |
| `PUT` | `/api/settings/{name}` | Update a setting |
| `POST` | `/api/settings` | Bulk update settings |
| `GET` | `/api/database/size` | Get database file size |
| `GET` | `/api/database/export` | Export database (sensitive fields redacted) |
| `GET` | `/api/database/stats` | Database size and record counts |
| `POST` | `/api/database/optimize` | Run VACUUM + ANALYZE |
| `POST` | `/api/database/reset` | Reset the database |
| `GET` | `/api/cache/statistics` | Squid cache metrics |
| `POST` | `/api/maintenance/reload-config` | Signal Squid to reload config |
| `POST` | `/api/maintenance/reload-dns` | Reload dnsmasq DNS configuration |
| `POST` | `/api/maintenance/clear-cache` | Clear the Squid proxy cache |
| `GET` | `/api/maintenance/backup-config` | Download a configuration backup |
| `POST` | `/api/maintenance/restore-config` | Restore configuration from backup |
| `GET` | `/api/maintenance/check-cert-security` | Check SSL certificate security |
| `GET` | `/api/security/download-ca` | Download the proxy CA certificate |
| `GET` | `/api/security/rate-limits` | List current rate-limited IPs |
| `DELETE` | `/api/security/rate-limits/{ip}` | Remove rate limit for specific IP |

### WebSocket

| Path | Protocol | Description |
|---|---|---|
| `/api/ws/logs?token=TOKEN` | `ws://` | Real-time log stream |
