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
      "source_ip": "192.168.1.10",
      "method": "CONNECT",
      "destination": "sink.example:443",
      "status": "TCP_DENIED/403",
      "bytes": 4862,
      "blocked": true,
      "reason": "domain_blacklist_dns"
    }
  ],
  "meta": { "total": 15420, "limit": 100, "offset": 0 },
  "total": 15420,
  "limit": 100,
  "offset": 0
}
```

When GDPR mode is enabled in settings, `source_ip` is masked. The top-level
`total`, `limit` and `offset` are deprecated copies of `meta`.

`reason` is the rule that blocked the request, recorded by Squid or the WAF
when the request was logged (see `docs/design/block-reasons.md`):
`ip_blacklist`, `domain_blacklist`, `domain_blacklist_dns`, `direct_ip`,
`egress_policy`, `waf`, `proxy_auth`, `time_restriction`, `content_filter`,
`source_gate`, `port_policy`, `protocol_policy`, `other`; `none` when it was
not blocked; `unclassified` for a row logged before reasons were recorded;
`domain_blacklist_dns_reconstructed` for such a row that the start-up step
of schema version 3 reassigned: a `/503` to a name on the domain blacklist,
logged after the name was added (see `docs/design/block-reasons.md`).
The list holds every row, including the DNS sinkhole's own rows (method
`DNS`, source the proxy container), which no statistic counts.

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
    "blocked_by_reason": [
      { "reason": "domain_blacklist_dns", "label": "Domain blacklist (DNS)", "count": 300 },
      { "reason": "domain_blacklist", "label": "Domain blacklist", "count": 24 },
      { "reason": "direct_ip", "label": "Direct IP", "count": 18 }
    ],
    "last_import": "2026-03-25 14:32:10"
  }
}
```

Counts are client requests: the DNS sinkhole's own rows are left out.
`blocked_count` is the number of requests with a block reason (rows logged
before reasons were recorded keep the flag they were given then, from the
status). `ip_blocks_count` is the subset with reason `direct_ip`, plus older
rows whose URL targeted a raw IPv4 address. `blocked_by_reason` breaks
`blocked_count` down by reason.

---

## Traffic timeline

```
GET /api/logs/timeline
```

Hourly request and block counts.

**Query parameters:**

| Parameter | Default | Range |
|---|---|---|
| `hours` | `24` | `1` to `720` |

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

A 0 to 100 score derived from the current settings (direct-IP blocking, WAF state, HTTPS filtering, rate limiting, and so on) plus a list of recommendations.

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
