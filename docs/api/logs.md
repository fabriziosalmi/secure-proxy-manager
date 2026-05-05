# Logs and Analytics API

All endpoints require authentication (Basic or JWT). Response bodies follow the envelope `{"status": "success", "data": ...}` unless noted.

---

## Get log entries

```
GET /api/logs
```

Returns proxy access log entries with pagination metadata.

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `limit` | `100` | Maximum number of entries to return |
| `offset` | `0` | Pagination offset |
| `sort` | `timestamp` | Sort column: `timestamp`, `source_ip`, `destination`, `status`, `bytes`, `method` |
| `order` | `desc` | `asc` or `desc` |

**Response:**

```json
{
  "status": "success",
  "data": [
    {
      "id": 1234,
      "timestamp": "2026-03-25 14:32:10",
      "client_ip": "192.168.1.10",
      "method": "CONNECT",
      "destination": "example.com:443",
      "status": "200 Connection established",
      "bytes": 4096
    }
  ],
  "total": 15420,
  "limit": 100,
  "offset": 0
}
```

When GDPR mode is enabled in settings, `client_ip` is masked.

---

## Log statistics

```
GET /api/logs/stats
```

**Response:**

```json
{
  "status": "success",
  "data": {
    "total_count": 15420,
    "blocked_count": 342,
    "ip_blocks_count": 18,
    "last_import": "2026-03-25 14:32:10"
  }
}
```

`blocked_count` is the number of entries whose `status` indicates a 403 or other DENIED/BLOCKED outcome. `ip_blocks_count` is the subset of those that targeted a raw IP destination.

---

## Traffic timeline

```
GET /api/logs/timeline
```

Hourly request and block counts.

**Query parameters:**

| Parameter | Default | Range |
|---|---|---|
| `hours` | `24` | `1`–`720` |

**Response:**

```json
{
  "status": "success",
  "data": [
    { "time": "2026-03-25 13:00:00", "total": 45, "blocked": 3 },
    { "time": "2026-03-25 14:00:00", "total": 62, "blocked": 7 }
  ]
}
```

---

## Clear all logs

```
POST /api/logs/clear
```

Deletes every row in `proxy_logs`. The action is recorded in the audit log.

**Response:**

```json
{ "status": "success", "message": "All logs cleared" }
```

---

## Clear old logs

```
POST /api/logs/clear-old
```

Deletes log entries older than the configured retention period (`log_retention_days` setting, default `30`).

**Response:**

```json
{ "status": "success", "message": "Cleared old logs", "deleted": 1234 }
```

---

## Security score

```
GET /api/security/score
```

A 0–100 score derived from the current settings (direct-IP blocking, WAF state, HTTPS filtering, rate limiting, and so on) plus a list of recommendations.

**Response:**

```json
{
  "status": "success",
  "data": {
    "score": 85,
    "max_score": 100,
    "recommendations": [
      "Enable HTTPS filtering for full request inspection."
    ]
  }
}
```

---

## Other analytics endpoints

The following return JSON in the standard envelope; payload shape mirrors what the dashboard renders:

| Path | Purpose |
|---|---|
| `GET /api/dashboard/summary` | Aggregated dashboard data in a single call |
| `GET /api/traffic/statistics` | Traffic statistics |
| `GET /api/clients/statistics` | Top clients |
| `GET /api/domains/statistics` | Top accessed domains |
| `GET /api/analytics/shadow-it` | Shadow-IT detection |
| `GET /api/analytics/user-agents` | Service-type breakdown by user agent |
| `GET /api/analytics/file-extensions` | File-extension distribution |
| `GET /api/analytics/top-domains` | Top domains for the cloud visualisation |
| `GET /api/waf/stats` | WAF statistics (rules, blocks, entropy) |
| `GET /api/waf/categories` | WAF rule categories with toggle state |
| `GET /api/audit-log` | Audit log entries (admin actions) |

See the [API reference](/api/reference) for the consolidated list.
