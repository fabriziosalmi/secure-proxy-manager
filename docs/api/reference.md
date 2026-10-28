# API Reference

Base URLs:

- Through the `web` service (recommended): `https://<host>/api` or
  `https://localhost:8443/api`
- Directly to the backend, from the host only: `http://127.0.0.1:5001/api`

Every route needs HTTP Basic, JWT bearer or session cookie authentication (see
[Authentication](./authentication.md)) except
`POST /api/auth/login`, `POST /api/auth/refresh`, `GET /api/health`,
`GET /api/ready`, `GET /health`, `GET /livez`, `GET /readyz` and `GET /metrics`.
The WebSocket authenticates with a single-use token (see
[WebSocket](./websocket.md)). A running backend lists every registered route at
`GET /api/docs` (authenticated).

Most successful responses are `{"status": "success", "data": ...}`. The
authentication endpoints (`/api/auth/login`, `/api/auth/refresh`,
`/api/ws-token`, `/api/logout`, `/api/change-password`) return a flat object
with `status` and the payload fields at the top level. Errors are
`{"status": "error", "detail": "..."}`; a 500 also carries
`"code": "internal_error"` and a generic `detail`, with the cause in the
backend log.

### Collections

Endpoints that return a collection put it under `data` and the pagination
under `meta`:

```json
{
  "status": "success",
  "data": [ ... ],
  "meta": { "total": 1234, "limit": 100, "offset": 0 }
}
```

`total`, `limit` and `offset` are also emitted at the top level. They are
deprecated; read `meta`.

### Contract version

Every response carries an `X-API-Version` header: the version of the request
and response shapes, `1` at this commit. It changes only when a shape a client
depends on changes, unlike `version` in `/api/health`, which is the release.

## Authentication and health

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Check credentials, return an access and a refresh JWT, or with `X-SPM-Session: cookie` set the HttpOnly session cookie (no auth) |
| `POST` | `/api/auth/refresh` | Exchange a refresh token for a new pair (no auth) |
| `POST` | `/api/logout` | Revoke the bearer or session-cookie token of the request (clearing the cookie), and the refresh token in an optional `{"refresh_token": ...}` body |
| `POST` | `/api/change-password` | Change the admin password |
| `GET`  | `/api/ws-token` | Issue a single-use WebSocket token |
| `GET`  | `/api/session` | Who is signed in, how (`cookie`, `bearer`, `basic`) and `expires_at` |
| `GET`  | `/api/health` | Status, version, commit (no auth) |
| `GET`  | `/api/ready`, `/readyz` | `200` when the database answers, `503` otherwise (no auth) |
| `GET`  | `/health`, `/livez` | `200` while the process runs (no auth) |
| `GET`  | `/metrics` | Prometheus metrics (no auth; nginx does not proxy it) |
| `GET`  | `/api/docs` | The list of registered routes |

## Lists

`{list}` is one of `ip-blacklist`, `domain-blacklist`, `ip-whitelist`,
`domain-whitelist`. Details: [Blacklist and Whitelist API](./blacklists.md).

| Method | Path | Description |
|---|---|---|
| `GET`    | `/api/{list}` | List entries (`limit` 1 to 1000, default 100; `offset`; `search`) |
| `POST`   | `/api/{list}` | Add an entry |
| `DELETE` | `/api/{list}/{id}` | Delete an entry |
| `POST`   | `/api/ip-blacklist/bulk-delete`, `/api/domain-blacklist/bulk-delete` | Delete entries by ID |
| `DELETE` | `/api/ip-blacklist/clear-all`, `/api/domain-blacklist/clear-all` | Delete every entry |
| `GET`    | `/api/{list}/sources` | Where the entries came from, one row per source |
| `DELETE` | `/api/{list}/sources/{id}` | Delete the entries one source added (`{id}` or `unrecorded`) |
| `GET`    | `/api/{list}/export` | Every entry, one per line, as text |
| `POST`   | `/api/blacklists/import` | Import into the IP or domain blacklist from a URL or pasted content |
| `POST`   | `/api/blacklists/import-geo` | Import countries' IPv4 blocks into the IP blacklist |
| `POST`   | `/api/ip-whitelist/import`, `/api/domain-whitelist/import` | Add a pasted list to an allowed list as one pasted-list source |
| `GET`    | `/api/blacklists/enforcement` | What enforces each list, from the proxy's records |
| `POST`   | `/api/ip-blacklist/import`, `/api/domain-blacklist/import` | Retired: `410 Gone`, use `/api/blacklists/import` |

## Egress allowlist

Used only while the `egress_default_deny` setting is `true` (default
`false`); the setting is changed through `POST /api/settings`. See
[Egress allowlist](./blacklists.md#egress-allowlist) and
[Egress provider lists](./blacklists.md#egress-providers).

| Method | Path | Description |
|---|---|---|
| `GET`    | `/api/egress-allowlist` | List manual entries |
| `POST`   | `/api/egress-allowlist` | Add a manual entry (`{"entry": "<ip, cidr or domain>", "description": "<optional>"}`) |
| `DELETE` | `/api/egress-allowlist/{id}` | Delete a manual entry |
| `POST`   | `/api/egress-allowlist/bulk-delete` | Delete manual entries by ID |
| `DELETE` | `/api/egress-allowlist/clear-all` | Delete every manual entry |
| `GET`    | `/api/egress-providers` | List built-in catalog and custom URL egress provider lists |
| `PUT`    | `/api/egress-providers/{name}` | Enable or disable a provider list (`confirm_shared: true` required to enable a shared network) |
| `POST`   | `/api/egress-providers/url` | Add and fetch a custom URL provider list (`{"label": "...", "url": "..."}`) |
| `DELETE` | `/api/egress-providers/url/{id}` | Delete a custom URL provider list and its prefixes |
| `POST`   | `/api/egress-providers/{name}/refresh` | Fetch and validate the provider list now |
| `POST`   | `/api/egress-providers/{name}/apply-held` | Apply a held update for a provider list |

## Logs and analytics

Details: [Logs and Analytics API](./logs.md).

| Method | Path | Description |
|---|---|---|
| `GET`  | `/api/logs` | Access log rows, with filters (source, outcome, rule, destination, internal traffic) and a cursor |
| `GET`  | `/api/logs/export` | The same rows as streamed CSV |
| `GET`  | `/api/logs/stats` | Total, blocked and direct-IP counts, blocks by rule |
| `GET`  | `/api/logs/timeline` | Requests and blocks per hour (`hours`, default 24) |
| `POST` | `/api/logs/clear` | Delete every log row |
| `POST` | `/api/logs/clear-old` | Delete rows older than `days` (query parameter, default 30) |
| `POST` | `/api/counters/reset` | Delete every log row and reset the WAF's counters |
| `GET`  | `/api/status` | Proxy reachability, version, today's request count, Squid version, CVE count (`squid_cves`) and whether that major version has an advisory table (`cves_checked`), update availability |
| `GET`  | `/api/dashboard/summary` | The dashboard's data in one call (`top_clients` aggregated by network and `recent_blocks` masked when `gdpr_mode` is on) |
| `GET`  | `/api/traffic/statistics` | Requests and blocks per bucket (`period` = `hour`, `day`, `week`, `month`) |
| `GET`  | `/api/clients/statistics` | Top 50 clients (or `/24` and `/64` networks when `gdpr_mode` is on), then the internal sources |
| `GET`  | `/api/clients/{ip}/details` | One client's or `/24` / `/64` network CIDR's totals, top domains and recent requests |
| `GET`  | `/api/domains/statistics` | Top 50 destinations of the last 24 hours with their requests and a `status`: `Blocked` when a request to it was blocked or the proxy enforces the name from the blocklist (exact name, not on the allowed list), `Allowed` otherwise |
| `GET`  | `/api/analytics/shadow-it` | Requests of the last 7 days to known services (file sharing, messaging, AI, social) |
| `GET`  | `/api/analytics/user-agents` | Requests of the last 7 days by method and kind of service |
| `GET`  | `/api/analytics/file-extensions` | Requests of the last 7 days by file extension |
| `GET`  | `/api/analytics/top-domains` | Top 50 domains |
| `GET`  | `/api/analytics/blocked-by-day` | Blocked requests per day by rule, today and the 6 days before (`tz`, default UTC) |
| `GET`  | `/api/analytics/coverage` | Which protections are switched on now: list sizes, WAF rules, HTTPS inspection, alerts and the other access settings |
| `GET`  | `/api/audit-log` | Audit log, newest first, 50 a page (`limit` up to 200). `category` = `all`, `changes` or `signins` filters on the server; `meta.retention_days` is 365 |
| `GET`  | `/api/security/score` | Retired: `410 Gone` |
| `GET`  | `/api/security/cve` | The Squid version (`version`), whether its major version has an advisory table (`cves_checked`) and the advisories matched to it (`cves`) |
| `GET`  | `/api/waf/stats` | WAF statistics (from the WAF) |
| `GET`  | `/api/waf/categories` | WAF rule categories and whether each is on |
| `POST` | `/api/waf/categories/toggle` | Turn a category on or off in the running WAF |
| `GET`  | `/api/waf/heuristics` | The heuristics the running WAF applies, or `available: false` with the reason |
| `POST` | `/api/waf/test-rule` | Match a Go regular expression against the destinations of recent requests (at most 10,000 read) |

## Settings and maintenance

Details: [Settings and Maintenance API](./settings.md).

| Method | Path | Description |
|---|---|---|
| `GET`    | `/api/settings` | Every setting; secrets are write-only |
| `PUT`    | `/api/settings/{name}` | Set one value and write the proxy file it needs |
| `POST`   | `/api/settings` | Store several values and write the proxy files they drive |
| `GET`    | `/api/database/size` | Database size (`size_bytes`, `size_mb`) |
| `GET`    | `/api/database/stats` | Row count per table |
| `GET`    | `/api/database/export` | Every table as JSON, `password`, `secret` and `token` columns redacted; client addresses in `proxy_logs` are unmasked (`contains_unmasked_addresses: true` when `gdpr_mode` is on) |
| `POST`   | `/api/database/optimize` | `VACUUM` and `REINDEX` |
| `POST`   | `/api/database/reset` | Delete every row of every table except `users` |
| `GET`    | `/api/cache/statistics` | Squid cache statistics as the proxy last collected them |
| `POST`   | `/api/maintenance/reload-config` | Export the lists, ask the proxy to regenerate and reload, and report what it did |
| `POST`   | `/api/maintenance/reload-dns` | Export the lists and ask dnsmasq to reload |
| `POST`   | `/api/maintenance/clear-cache` | Clear the Squid cache (see [Settings and Maintenance](./settings.md#clear-proxy-cache)) |
| `GET`    | `/api/maintenance/backup-config` | The settings and the five lists, as a backup |
| `POST`   | `/api/maintenance/restore-config` | Add what a backup holds |
| `GET`    | `/api/maintenance/check-cert-security` | Whether the CA file and the certificate database exist |
| `GET`    | `/api/security/download-ca` | The SSL-bump CA certificate (`/config/ssl_cert.pem`) |
| `GET`    | `/api/security/rate-limits` | Failed-login counts per address |
| `DELETE` | `/api/security/rate-limits/{ip}` | Clear one address's count |
| `POST`   | `/api/notifications/test` | Send one test alert to every channel that has all its settings (webhook, Gotify, Telegram, ntfy, Teams), outside the [notification limits](./settings.md#notification-limits); `data.channels` reports each delivery |

## Internal

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/internal/alert` | WAF block notifications, on the backend's port only (`backend:5000` inside the stack); the web container answers `404` for `/api/internal/`. With `INTERNAL_ALERT_TOKEN` set, only `Authorization: Bearer <that token>` is accepted; without it, normal admin authentication. The alerts pass the [notification limits](./settings.md#notification-limits) |
| `POST` | `/api/dns/detect` | Probe a subnet for Pi-hole or AdGuard instances (at most 2 scans at a time) |
| `GET`  | `/debug/pprof/...` | Go runtime profiles (authenticated) |

## WebSocket

| Path | Description |
|---|---|
| `/api/ws/logs` | Live log feed; offer the subprotocols `spm.v1` and `spm-ws-token.<token>` with a token from `/api/ws-token`. See [WebSocket](./websocket.md) |
