# Logs & Analytics API

All endpoints require Basic Auth.

---

## Get log entries

```
GET /api/logs?limit=100
```

Returns the most recent proxy access log entries.

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `limit` | `100` | Maximum number of entries to return |

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1234,
      "timestamp": "2026-03-25T14:32:10",
      "client_ip": "192.168.1.10",
      "method": "CONNECT",
      "destination": "example.com:443",
      "status": "200 Connection established",
      "bytes": 4096
    }
  ]
}
```

---

## Log statistics

```
GET /api/logs/stats
```

Returns aggregated counts.

**Response:**
```json
{
  "status": "success",
  "total_count": 15420,
  "blocked_count": 342,
  "ip_blocks_count": 18
}
```

---

## Traffic timeline

```
GET /api/logs/timeline
```

Returns hourly request/block counts for the last 24 hours. Used by the dashboard chart.

**Response:**
```json
[
  { "time": "13:00", "total": 45, "blocked": 3 },
  { "time": "14:00", "total": 62, "blocked": 7 }
]
```

---

## Clear all logs

```
POST /api/logs/clear
```

Deletes all log entries from the database.

**Response:**
```json
{
  "status": "success",
  "message": "Logs cleared"
}
```

---

## Security score

```
GET /api/security/score
```

Returns a 0–100 security score based on current settings.

**Response:**
```json
{
  "score": 85,
  "details": {
    "direct_ip_blocking": true,
    "waf_enabled": true,
    "https_filtering": false
  }
}
```

---

## PDF analytics report

```
GET /api/analytics/report/pdf
```

Generates and returns a PDF report summarizing traffic statistics, top blocked domains, and security score.

Returns a `application/pdf` response.
