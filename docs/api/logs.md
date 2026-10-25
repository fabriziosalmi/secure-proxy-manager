# Logs and Analytics API

All endpoints require authentication (Basic or JWT). Response bodies follow the envelope `{"status": "success", "data": ...}` unless noted.

---

## Get log entries

```
GET /api/logs
```

Returns proxy access log entries matching the filters, with pagination
metadata.

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `limit` | `25` | Maximum number of entries to return, 1 to 500 |
| `offset` | `0` | Pagination offset |
| `sort` | `timestamp` | Sort column: `timestamp`, `source_ip`, `destination`, `status`, `bytes`, `method`, `id` |
| `order` | `desc` | `asc` or `desc` |
| `source_ip` | | One source address, exact. A named source is listed even when it is internal |
| `outcome` | | `allowed` or `blocked`, from the `blocked` flag |
| `reason` | | The rule that blocked the request (a `reason` value below); selects blocked rows only |
| `q` | | A substring of `destination`, ASCII case-insensitive; `%` and `_` match themselves |
| `include_internal` | `false` | Include the stack's own traffic (see below) |
| `before_id` | | Cursor: only rows with a lower `id`. Sets the order to `id` descending and ignores `offset` |

A malformed filter value is refused with `400`.

**Internal sources.** The backend classifies each source address: loopback,
the backend itself, the proxy, the Docker host and any other address on the
networks the backend shares with the proxy are the stack's own traffic, not a
device (the same classification as the client list). They are left out
unless `include_internal=true` or `source_ip` names one of them; `meta.internal`
then counts the matching rows that were left out.

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
      "reason": "domain_blacklist_dns",
      "reason_label": "Domain blacklist (DNS)",
      "internal": false,
      "kind": "Private network address"
    }
  ],
  "meta": { "total": 15420, "limit": 100, "offset": 0, "internal": 2880 },
  "total": 15420,
  "limit": 100,
  "offset": 0
}
```

`meta.total` counts the rows the filters match. `kind` says what the source
is where the backend can tell ("Internal: the backend", "Internal: this
host", "Private network address", "Public address"), and is empty
otherwise.

To page back through the log, pass the `id` of the last row received as
`before_id`; a page shorter than `limit` is the last one.

When GDPR mode is enabled in settings, `source_ip` is masked (the source is
classified before it is masked). The top-level `total`, `limit` and `offset`
are deprecated copies of `meta`.

`reason` is the rule that blocked the request, recorded by Squid or the WAF
when the request was logged (see `docs/design/block-reasons.md`):
`ip_blacklist`, `domain_blacklist`, `domain_blacklist_dns`, `direct_ip`,
`egress_policy`, `waf`, `proxy_auth`, `time_restriction`, `content_filter`,
`source_gate`, `port_policy`, `protocol_policy`, `other`; `none` when it was
not blocked; `unclassified` for a row logged before reasons were recorded;
`domain_blacklist_dns_reconstructed` for such a row that the start-up step
of schema version 3 reassigned: a `/503` to a name on the domain blacklist,
logged after the name was added (see `docs/design/block-reasons.md`).
With `include_internal=true` the list holds every row, including the DNS
sinkhole's own rows (method `DNS`, source the proxy container), which no
statistic counts.

**Cost, measured on 1M rows** (20 devices, two internal sources holding 10% of
the rows, 10% blocked over five rules; `limit=100`, best of three, Apple M4
Pro, `TestLogFilters1M` in `backend-go/internal/handlers/logs_plan_test.go`):

| Filter | Plan | Time |
|---|---|---|
| none (internal sources left out) | page in id order; counts: every row, then the internal rows by `idx_proxy_logs_source_ip` | 17 ms |
| `include_internal=true` | page in id order; count by a covering index | 12 ms |
| `source_ip` | `idx_proxy_logs_source_ip` | 3 ms |
| `reason=waf` (1% of rows) | `idx_proxy_logs_blocked_reason` | 10 ms |
| `reason=ip_blacklist` (0.1%) | `idx_proxy_logs_blocked_reason` | 1 ms |
| `outcome=blocked` | `idx_proxy_logs_blocked` | 69 ms |
| `outcome=allowed` | every row less the blocked ones | 87 ms |
| `before_id` (deep) | rowid range | 18 ms |
| `q` | no index can serve `LIKE '%x%'`: the table is read | 200 to 290 ms |

Init creates `idx_proxy_logs_blocked_reason` on the first start after an
upgrade; on the same 1M rows that took 138 ms. Without it a rule filter read
every blocked row
(133 to 139 ms); counting "not internal" and "allowed" directly read the
whole table (123 and 226 ms).

---

## Export log entries

```
GET /api/logs/export
```

Streams, as CSV, every row `GET /api/logs` selects for the same filters
(`source_ip`, `outcome`, `reason`, `q`, `include_internal`, `before_id`),
newest first. `limit`, `offset` and `sort` do not apply. Columns: `id`,
`timestamp_utc`, `source_ip`, `internal`, `kind`, `method`, `destination`,
`status`, `bytes`, `blocked`, `reason`, `reason_label`. A cell that starts
with `=`, `+`, `-` or `@` is written with a leading apostrophe, so a
spreadsheet shows it as text rather than running it as a formula (a method
logged as `-` is exported as `'-`).

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
