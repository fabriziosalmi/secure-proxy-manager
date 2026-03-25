# API Reference

Base URLs:

- **Via UI proxy** (recommended): `http://localhost:8011/api`
- **Direct backend access** (localhost only): `http://localhost:5001/api`

All endpoints require HTTP Basic Authentication unless noted otherwise.

## Endpoint summary

### Authentication

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/login` | Validate credentials |
| `POST` | `/api/change-password` | Change the admin password |
| `GET` | `/api/ws-token` | Get a single-use WebSocket auth token |
| `GET` | `/health` | Health check (no auth required) |

### Blacklist & Whitelist

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/blacklists/ip` | List IP blacklist entries |
| `POST` | `/api/blacklists/ip` | Add an IP blacklist entry |
| `DELETE` | `/api/blacklists/ip/{id}` | Delete an IP blacklist entry |
| `GET` | `/api/blacklists/domains` | List domain blacklist entries |
| `POST` | `/api/blacklists/domains` | Add a domain blacklist entry |
| `DELETE` | `/api/blacklists/domains/{id}` | Delete a domain blacklist entry |
| `POST` | `/api/blacklists/import` | Import from URL or inline content |
| `POST` | `/api/blacklists/import-geo` | Import geo-based IP block |
| `GET` | `/api/ip-whitelist` | List IP whitelist entries |
| `POST` | `/api/ip-whitelist` | Add an IP whitelist entry |
| `DELETE` | `/api/ip-whitelist/{id}` | Delete an IP whitelist entry |

### Logs & Analytics

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/logs` | Get log entries (`?limit=N`) |
| `GET` | `/api/logs/stats` | Get log statistics |
| `GET` | `/api/logs/timeline` | 24h traffic timeline |
| `POST` | `/api/logs/clear` | Clear all logs |
| `GET` | `/api/security/score` | Get security score |
| `GET` | `/api/analytics/report/pdf` | Download PDF analytics report |

### Settings & Maintenance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings` | Get all settings |
| `PUT` | `/api/settings/{name}` | Update a setting |
| `GET` | `/api/database/export` | Export database (sensitive fields redacted) |
| `GET` | `/api/database/stats` | Database size and record counts |
| `POST` | `/api/database/optimize` | Run VACUUM + ANALYZE |
| `GET` | `/api/cache/statistics` | Squid cache metrics |
| `POST` | `/api/maintenance/reload-config` | Signal Squid to reload config |

### WebSocket

| Path | Protocol | Description |
|---|---|---|
| `/api/ws/logs?token=TOKEN` | `ws://` | Real-time log stream |
