# Logs and Analytics API

All endpoints require authentication (Basic or JWT). Responses use the
envelope `{"status": "success", "data": ...}` unless noted.

---

## Get log entries

```
GET /api/logs
```

Returns access log rows matching the filters, with pagination metadata.

**Query parameters:**

| Parameter | Default | Description |
|---|---|---|
| `limit` | `25` | Rows to return, 1 to 500 |
| `offset` | `0` | Pagination offset |
| `sort` | `timestamp` | `timestamp`, `source_ip`, `destination`, `status`, `bytes`, `method` or `id`; anything else is `timestamp` |
| `order` | `desc` | `asc` or `desc` |
| `source_ip` | | One source address, exact. A named source is listed even when it is internal |
| `outcome` | | `allowed` or `blocked` (`all` or empty: both), from the `blocked` flag |
| `reason` | | The rule that blocked the request (a `reason` value below); selects blocked rows only |
| `q` | | A substring of `destination`, case-insensitive for ASCII; `%` and `_` match themselves. At most 256 bytes |
| `include_internal` | `false` | `true` includes the stack's own traffic (see below) |
| `before_id` | | Cursor: only rows with a lower `id`. Sets the order to `id` descending and ignores `offset` |

A malformed filter value is refused with `400`.

**Internal sources.** The backend classifies each source address: loopback,
the backend itself, the proxy, the Docker host and any other address on the
networks the backend shares with the proxy are the stack's own traffic, not a
device (the same classification as the client list). They are left out unless
`include_internal=true` or `source_ip` names one of them; `meta.internal` then
counts the matching rows that were left out.

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
  "meta": { "total": 15420, "limit": 25, "offset": 0, "internal": 2880 },
  "total": 15420,
  "limit": 25,
  "offset": 0
}
```

`meta.total` counts the rows the filters match. `kind` says what the source is
where the backend can tell (for example "Internal: the backend", "Internal:
this host", "Internal: the proxy", "Private network address", "Public
address"), and is empty otherwise.

To page back through the log, pass the `id` of the last row received as
`before_id`; a page shorter than `limit` is the last one.

With GDPR mode on (Settings > Logs and privacy), `source_ip` is masked (the
last IPv4 octet, or the last IPv6 group, becomes `x`); the source is
classified before it is masked. The top-level `total`, `limit` and `offset`
are deprecated copies of `meta`.

`reason` is the rule that blocked the request, recorded by Squid or the WAF
when the request was logged (see
[Block reasons](../design/block-reasons.md)): `ip_blacklist`,
`domain_blacklist`, `domain_blacklist_dns`, `direct_ip`, `egress_policy`,
`waf`, `proxy_auth`, `proxy_auth_unset` (proxy login is on and no proxy
credentials are set, so every client is refused), `time_restriction`,
`content_filter`, `source_gate`, `port_policy`, `protocol_policy`,
`lists_unverified` (the fail-closed lists gate: a blocklist the backend's
manifest did not vouch for at boot, so the proxy denied every client request
until a verified copy was loaded), `other`; `none` when it was not blocked;
`unclassified` for a row logged before reasons were recorded;
`domain_blacklist_dns_reconstructed` for such a row that schema version 3
reassigned at start-up: a `/503` to a name on the domain blacklist, logged
after the name was added. With `include_internal=true` the list also holds the
DNS sinkhole's own rows (method `DNS`, source the proxy container), which no
statistic counts.

**Cost, measured on 1,000,000 rows.** `TestLogFilters1M` in
`backend-go/internal/handlers/logs_plan_test.go` (`SPM_LOGS_1M=1`): 20
devices, two internal sources holding 10% of the rows, 10% blocked over five
rules, `limit=100`, best of three. Run on 2026-10-25 on an Apple M4 with
go1.27.2:

| Filter | Plan (page; count) | Time |
|---|---|---|
| none (internal sources left out) | scan; covering index count minus `idx_proxy_logs_source_ip` | 17.4 ms |
| `include_internal=true` | scan; covering index count | 12.4 ms |
| `source_ip` | `idx_proxy_logs_source_ip` | 2.7 ms |
| `reason=waf` (1% of rows) | `idx_proxy_logs_blocked_reason` | 10.2 ms |
| `reason=ip_blacklist` (0.1%) | `idx_proxy_logs_blocked_reason` | 1.2 ms |
| `outcome=blocked` | `idx_proxy_logs_blocked` | 70.6 ms |
| `outcome=allowed` | scan; every row less the blocked ones | 88.0 ms |
| `before_id` (deep) | rowid range | 17.2 ms |
| `q` | no index serves `LIKE '%x%'`: the table is read | 208 to 287 ms |

Creating `idx_proxy_logs_blocked_reason`, which start-up does once after an
upgrade, took 126 ms on the same rows.

---

## Export log entries

```
GET /api/logs/export
```

Streams, as CSV, every row `GET /api/logs` selects for the same filters
(`source_ip`, `outcome`, `reason`, `q`, `include_internal`, `before_id`),
newest first, read 2,000 rows at a time. `limit`, `offset` and `sort` do not
apply. The file is named `access-log-<date>.csv`. Columns: `id`,
`timestamp_utc`, `source_ip`, `internal`, `kind`, `method`, `destination`,
`status`, `bytes`, `blocked`, `reason`, `reason_label`. A cell that starts
with `=`, `+`, `-`, `@`, a tab or a carriage return is written with a leading
apostrophe, so a spreadsheet shows it as text rather than running it as a
formula (a method logged as `-` is exported as `'-`). With GDPR mode on,
`source_ip` is masked here too.

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
`blocked_count` is the number of blocked requests (rows logged before reasons
were recorded keep the flag they were given then, from the status).
`ip_blocks_count` is the subset with reason `direct_ip`, plus older rows whose
URL targeted a raw IPv4 address. `blocked_by_reason` breaks `blocked_count`
down by reason. `last_import` is the newest row's timestamp.

---

## Traffic timeline

```
GET /api/logs/timeline
```

Requests and blocks per hour, client requests only, internal sources left out.

| Parameter | Default | Range |
|---|---|---|
| `hours` | `24` | `1` to `720`; a value outside the range is `24` |

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

Deletes every row in `proxy_logs` and records the action in the audit log.

```json
{ "status": "success", "message": "All logs cleared" }
```

`POST /api/counters/reset` also deletes every row, and resets the WAF's
counters; its `data` says how many rows went (`logs_cleared`) and whether the
WAF reset (`waf_reset`).

---

## Clear old logs

```
POST /api/logs/clear-old?days=30
```

Deletes rows older than `days` days (default `30`; a value below 1 is `30`).
It does not read the `log_retention_days` setting, which drives the daily
automatic pruning.

```json
{ "status": "success", "message": "Cleared old logs", "deleted": 1234 }
```

---

## Security score (retired)

```
GET /api/security/score
```

Answers `410 Gone`. The score added points for four settings that nothing
enforced (`enable_ip_blacklist`, `enable_domain_blacklist`, `block_direct_ip`,
`enable_waf`): Squid always denies the blacklists and direct-IP URLs and the
WAF is always on the ICAP path. Settings > Overview lists what needs attention,
worked out from the running configuration.

---

## Audit log

```
GET /api/audit-log?category=changes&limit=50&offset=0
```

Newest first, 50 rows a page by default (`limit` up to 200). `category` is
`all` (default), `changes` or `signins` (the actions `login`, `login_failed`,
`logout`), filtered on the server, so `meta.total` and the pages are those of
the filtered log. `meta.retention_days` is how long a row is kept (365). Every
change to a list (add, remove, bulk remove, clear, import, removal of a
source, restore) writes a row. Sign-in, failed sign-in and sign-out rows carry
the client address in `target`.

```json
{
  "status": "success",
  "data": [
    { "id": 812, "username": "admin", "action": "add_domain_blacklist", "target": "ads.example", "details": "", "timestamp": "2026-10-25 08:00:00" }
  ],
  "meta": { "total": 812, "limit": 50, "offset": 0, "retention_days": 365 }
}
```

---

## Other analytics endpoints

These return JSON in the standard envelope, in the shape the UI renders:

| Path | Purpose |
|---|---|
| `GET /api/status` | Proxy reachability (`proxy_status`, `proxy_host`, `proxy_port`), version, commit, today's client request count (`requests_count`), `proxy_auth` state when recorded, update availability (`update_available`, `update_url`), and Squid CVE state (`squid_version`, `squid_cves`, `cves_checked`: `false` when the major version has no table in `cve_checker.go`, such as Squid 7.x) |
| `GET /api/security/cve` | The Squid version (`version`), whether its major version has an advisory table (`cves_checked`), and the matched advisories (`cves`) |
| `GET /api/dashboard/summary` | The dashboard's data in one call |
| `GET /api/traffic/statistics?period=day` | Requests and blocks per bucket (`hour`, `day`, `week`, `month`) |
| `GET /api/clients/statistics` | Top 50 clients, then the internal sources |
| `GET /api/clients/{ip}/details` | One client's totals, top domains and recent requests |
| `GET /api/domains/statistics` | Top 50 domains |
| `GET /api/analytics/shadow-it` | Requests of the last 7 days to known services, by host |
| `GET /api/analytics/user-agents` | Requests of the last 7 days by method and kind of service |
| `GET /api/analytics/file-extensions` | Requests of the last 7 days by file extension |
| `GET /api/analytics/top-domains` | Top 50 domains |
| `GET /api/analytics/blocked-by-day` | Blocked requests per day by rule for 7 days (`tz`, default UTC) |
| `GET /api/analytics/coverage` | What protection is on now |
| `GET /api/waf/stats` | WAF statistics, from the WAF |
| `GET /api/waf/categories` | WAF rule categories and whether each is on |

See the [API reference](/api/reference) for the full list.
