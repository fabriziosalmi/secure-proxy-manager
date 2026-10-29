# Settings and Maintenance API

All endpoints require authentication (Basic or JWT). Responses use the envelope `{"status": "success", "data": ...}` unless noted.

---

## List all settings

```
GET /api/settings
```

```json
{
  "status": "success",
  "data": [
    { "setting_name": "ssl_bump_enabled", "setting_value": "false" },
    { "setting_name": "cache_size",       "setting_value": "2000"  }
  ]
}
```

Values are strings. The defaults a new database gets are in
`DefaultSettings` in `backend-go/internal/database/db.go`. A boolean setting
(every default that is `"true"` or `"false"`, plus `wizard_completed`) takes
exactly `"true"` or `"false"`; any other value, `"1"` included, answers `400`.

The alert channel settings are secrets: `webhook_url`, `webhook_bearer_token` (sent as `Authorization: Bearer <token>` with each webhook delivery), `gotify_url`, `gotify_token`, `teams_webhook_url`, `telegram_bot_token`, `telegram_chat_id`, `ntfy_url` and `ntfy_topic` (`crypto.SensitiveKeys` in the backend), and so is `proxy_auth_password` (see [Proxy login](#proxy-login)). They are stored encrypted and are write-only: their row carries `"secret": true`, an empty `setting_value`, `"is_set": true` when a value is stored, and `"decrypt_failed": true` when the stored value cannot be decrypted with the current key (`ENCRYPTION_KEY`, or the key the backend generated in its state directory when that is unset).

```json
{ "setting_name": "gotify_token", "setting_value": "", "secret": true, "is_set": true }
```

---

## Update a single setting

```
PUT /api/settings/{setting_name}
```

```json
{ "value": "true" }
```

The key in the path must consist of letters, digits and underscores, at most 100 characters, and must not be an internally managed or retired setting (`400` otherwise). The value is capped at 10,000 characters and checked with the same rules as the bulk endpoint; a secret is encrypted before it is stored.

It applies the value as `POST /api/settings` does: the marker, list or env file the proxy reads is written, and WAF heuristics are pushed to the running WAF. A secret sent with an empty value is cleared. The answer is `{"status": "success", "message": "Setting updated", "data": {...}}`, with `data.waf` when the value is a WAF heuristic, or `status: "partial"` and `data.failed` naming the proxy files that could not be written. As with the bulk endpoint, a proxy setting takes effect when the proxy reloads (`POST /api/maintenance/reload-config`).

---

## Bulk update settings

```
POST /api/settings
```

The body is a flat object mapping setting names to their new values:

```json
{
  "ssl_bump_enabled": "true",
  "cache_size": "5000",
  "auto_refresh_enabled": "true"
}
```

All updates are applied in a single transaction, and then the proxy's files are written: the toggle markers in `/config` for the toggles in the request, `squid_settings.env` (port, cache sizes, extra SSL ports) on every request, and the list, time and bandwidth files when their settings are in the request. The proxy picks them up on the next reload; the Settings page calls `POST /api/maintenance/reload-config` after a save that changes a proxy setting, and an API client should do the same. The same name and value validation applies as for the single-setting endpoint. Every value is checked before anything is written; a request with refused values answers `400` with all of them in `errors` and the first, in key order, in `detail`:

```json
{
  "status": "error",
  "detail": "auto_refresh_hours: must be a whole number of hours, from 1 to 168",
  "errors": {
    "auto_refresh_hours": "must be a whole number of hours, from 1 to 168",
    "cache_size": "must be a whole number of megabytes, from 1 to 9999999"
  }
}
```

Values that depend on each other are checked together, with the stored value for the half the request does not carry: with `enable_time_restrictions` on, `time_restriction_end` must be later than `time_restriction_start`; with `enable_content_filtering` on, `blocked_file_types` must list at least one extension; with `enable_proxy_auth` on, `proxy_auth_username` and `proxy_auth_password` must both be set once the request is saved. The same check applies to `PUT`, which then names the missing keys in `errors`. Notification URLs must be http or https, without credentials, and not point at this host; at delivery the backend also refuses any address of the networks it is attached to.

The settings nothing reads (`tailscale_*`, `ddns_*`, `auth_method`, `enable_ip_blacklist`, `enable_domain_blacklist`, `enable_waf`, `block_direct_ip`) are skipped, like internally managed keys: the rest of the request is saved, `PUT` answers `400` for them, and a restore lists them as not restored.

A request that carries WAF heuristics (`waf_h_*`) reports what the running WAF did with each in `data.waf`: `{"pushed": ["waf_h_pii"], "failed": [{"key": "waf_h_sequence", "reason": "..."}]}`.

A secret sent with an empty value keeps its stored value, and the response lists it in `data.kept`. To remove a secret, name it in the `clear` query parameter (comma separated): `POST /api/settings?clear=gotify_token,gotify_url`. Only secrets can be cleared this way, and a key cannot be cleared and given a value in the same request (`400`).

```json
{ "status": "success", "message": "Settings updated", "data": { "kept": ["gotify_token"] } }
```

When some proxy configuration files could not be written the answer is still `200`, with `"status": "partial"` and the file names in `data.failed`.

---

## Proxy login

```
POST /api/settings
```

```json
{
  "enable_proxy_auth": "true",
  "proxy_auth_username": "office",
  "proxy_auth_password": "a-long-proxy-password"
}
```

With `enable_proxy_auth` on, every client signs in to the proxy with HTTP Basic (`407 Proxy Authentication Required` without valid credentials), using `proxy_auth_username` and `proxy_auth_password`. They are the proxy's own credentials, not the dashboard login.

| Setting | Value |
|---------|-------|
| `proxy_auth_username` | 1 to 64 characters: letters, digits and `. _ @ + -` (no space, colon or newline). Returned by `GET`. |
| `proxy_auth_password` | 12 characters or more, at most 72 bytes, on one line. A secret: stored encrypted, never returned by `GET` (only `is_set`), removed with `?clear=proxy_auth_password` or a `PUT` with an empty value. |

After a save or a restore that carries any of the three keys, and at backend start, the backend writes `proxy_users.htpasswd` in the config directory: one line with the username and a bcrypt hash of the password, replaced atomically (temporary file and rename), mode `0640`, group `proxy` (gid 13, which the compose files add to the backend with `group_add`), so Squid's helper reads new credentials before the proxy reloads. The proxy's generator sets `root:proxy` on it too, and the backend asks the proxy to reload when the file changes. With login off, or without both credentials, the backend removes the file it wrote. A file it did not write (created by the proxy from `BASIC_AUTH_USERNAME`/`BASIC_AUTH_PASSWORD` passed to the proxy container) is replaced only by stored credentials and never removed. A stored password that cannot be decrypted with the current key leaves the file as it is.

Login cannot be turned on without both credentials, and they cannot be removed while it is on: the request answers `400` with the missing keys in `errors`. If the proxy still finds login on with no user in the password file (a database with login on and no credentials, for example after an upgrade), it refuses every client except localhost with `403` and the block reason `proxy_auth_unset` until credentials are set or login is turned off. It records what it did in `proxy_auth_status.json`, which `GET /api/status` returns as `proxy_auth` and `GET /api/analytics/coverage` as `proxy_login_status`:

```json
{ "proxy_auth": { "state": "no_credentials", "users": 0, "written_at": 1792953504 } }
```

`state` is `off`, `enforced` (`users` lines in the password file) or `no_credentials`. The field is absent (`null` in coverage) until the proxy has recorded it.

---

## Default-deny egress

```
POST /api/settings
```

```json
{ "egress_default_deny": "true" }
```

`egress_default_deny` is a boolean setting, sent as the string `"true"` or `"false"` (default `"false"`). `POST /api/settings` and `PUT /api/settings/egress_default_deny` write or remove the marker file `/config/egress_default_deny`; `POST /api/maintenance/reload-config` then makes the proxy apply it. The setting is also the "Only allowlisted destinations" toggle under Settings > Filtering, which refuses to save it while the allowlist is empty; the API does not refuse.

When `"false"` (the default) local clients may reach any destination that is not blocked. When `"true"` they may reach only the destinations on the default-deny allowlist, LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and IP exceptions; everything else is refused with a Squid 403.

The allowlist destinations themselves are not setting values. Manual entries are managed through `/api/egress-allowlist` (IP/CIDR or domain), and managed CIDR feeds through `/api/egress-providers` (see [Blacklist and exception API](./blacklists.md#egress-providers)).

`egress_provider_refresh_hours` (whole number from `6` to `168`, default `"24"`) sets how often the background worker refreshes enabled egress provider lists. A value outside `6` to `168` is refused with `400` (`must be a whole number from 6 to 168 (hours)`).

---

## Notification limits

WAF blocks and failed sign-ins reach the alert channels through one queue in the backend, which applies these settings to every event. They are read on each event, so a save applies to the next one. The test alert (`POST /api/notifications/test`) is outside them.

| Setting | Default | Values | Effect |
|---|---|---|---|
| `notify_group_window_minutes` | `10` | whole number, 1 to 1440 | Alerts with the same `event_type` and `client_ip` are grouped. The first is sent at once; the others within this many minutes are counted, and one digest follows when the window ends. |
| `notify_max_per_hour` | `20` | whole number, 1 to 1000 | Each channel sends at most this many deliveries in any rolling hour, digests included. Past it the channel holds everything and counts it; once one of its deliveries in the hour is an hour old it sends one notice with the count, which takes that slot, and then sends again. |
| `notify_waf_block` | `"true"` | `"true"`, `"false"` | `"false"`: WAF blocks send nothing. |
| `notify_login_failure` | `"true"` | `"true"`, `"false"` | `"false"`: failed sign-ins send nothing. |
| `notify_min_level` | `info` | `info`, `warning`, `error` | Events below this level send nothing. WAF blocks are `error`, failed sign-ins `warning`; an event with no level counts as `info`. |

A value outside these is refused with `400`. A stored value that is not usable (an older install, a row edited by hand) is read as the default.

A digest is posted like any alert, with `event_type` set to the grouped type plus `_digest`:

```json
{
  "event_type": "waf_block_digest",
  "level": "error",
  "message": "WAF blocked 412 more requests from 203.0.113.5 in the last 10 minutes: SQLI 380, XSS 32",
  "client_ip": "203.0.113.5",
  "count": 412,
  "window_minutes": 10,
  "category_counts": { "SQLI": 380, "XSS": 32 },
  "timestamp": "2026-10-25T12:10:00Z"
}
```

The message names the three most frequent categories and sums the rest as `other`. The held-back notice is `{"event_type": "alerts_held_back", "level": "warning", "count": N, "message": "N alerts held back in the last hour; see Analytics and the Audit log"}`. The backend closes due windows and sends due notices every 5 seconds. It keeps at most 10,000 groups; past that, a new address joins its event type's overflow group, whose digest reads "from other addresses".

The counts are kept in memory. A graceful shutdown sends every pending digest and every held-back notice before the backend exits; a crash loses them. `spm_notifications_held_total{reason, channel}` on `/metrics` counts what was held: `reason="grouped"` with `channel="all"` for each event counted into a digest (grouping happens before an event is split into channels), `reason="cap"` with the channel's name for each delivery that channel held. Both labels are always present, so the series do not change shape.

With `gdpr_mode` on, `client_ip` on `POST /api/internal/alert` is masked before the event enters the notification queue (IPv4 to `/24` as `a.b.c.x`, IPv6 to `/64` as `<prefix>::x`), so formatted messages, raw webhook payloads and digests all carry the masked address and group by network.

---

## Privacy (`gdpr_mode`)

`gdpr_mode` (`"true"` or `"false"`, default `"false"`, Settings > Logs and privacy > Mask client IPs) masks client IP addresses across all API responses (`GET /api/logs`, `GET /api/logs/export`, `/api/ws/logs`, `GET /api/clients/statistics`, `GET /api/clients/{ip}/details`, `GET /api/dashboard/summary`), the MCP server and outbound alert deliveries. IPv4 addresses are masked to `/24` (`192.168.1.x`) and IPv6 addresses to `/64` (`2001:db8:1:2::x`). The SQLite database (`proxy_logs`) and `GET /api/database/export` keep the full unmasked client addresses so network aggregation and classification remain exact when the setting is toggled.

---

## Health

`GET /api/health`, `GET /health` and the readiness probes are described in
[Authentication](./authentication.md#health). They need no authentication.

---

## Database export

```
GET /api/database/export
```

Returns `{"status": "success", "data": {<table>: [rows]}}` for `users`,
`ip_whitelist`, `ip_blacklist`, `domain_blacklist`, `domain_whitelist`,
`list_sources`, `dst_allowlist`, `egress_providers`, `egress_provider_entries`,
`proxy_logs`, `settings` and `audit_log`,
served as the attachment `database_export.json`. Columns named `password`,
`secret` or `token` are replaced with `***REDACTED***`. The alert channel
secrets are rows of `settings`, so they appear in their encrypted form
(`enc::...`). Client addresses in `proxy_logs` are exported in full even when
`gdpr_mode` is on, in which case the top-level response includes
`"contains_unmasked_addresses": true`. Restore cannot read this file; use the
configuration backup.

---

## Database statistics

```
GET /api/database/stats
```

Returns the row count of each of the tables above.

---

## Database optimise

```
POST /api/database/optimize
```

Runs `VACUUM` and `REINDEX` on the SQLite database.

---

## Database size

```
GET /api/database/size
```

Returns `size_bytes` (SQLite page count times page size) and `size_mb`.

---

## Database reset

```
POST /api/database/reset
```

Deletes every row of the tables above except `users` inside one transaction,
settings included; if a table cannot be cleared, the transaction rolls back and
the endpoint answers `500` naming the table. After clearing the tables, it
writes the `database_reset` row to `audit_log` in the same transaction so the
reset is the first row of the new audit log. The default settings are inserted
again at the next backend start. Use with care.

---

## Reload proxy configuration

```
POST /api/maintenance/reload-config
```

Exports the lists, then asks the proxy to regenerate `squid.conf` from the
current lists, marker files and settings files and reload.

**This call blocks.** It writes a trigger file and then waits up to **8 seconds**
for the proxy's watchdog to acknowledge what it did, so a client should allow at
least that. There are three outcomes, and a `200` does not on its own mean the
reload was applied:

| HTTP | `status` | Meaning |
|---|---|---|
| `200` | `success` | The generator ran, squid accepted the config, and it is live |
| `500` | `error` (`code: reload_failed`) | The proxy refused the new config and **kept the previous one**. `data.generator_rc` and `data.reconfigure_rc` say which step failed |
| `500` | `error` (`code: trigger_write_failed`) | The lists were exported, but `/config/.reload-squid` could not be written |
| `200` | `pending` | Nothing acknowledged within the timeout; check that the proxy container is running |

A caller that treats any `200` as success will read `pending` as applied.

---

## Send the lists again

```
POST /api/maintenance/reload-dns
```

Exports every list again, the files Squid reads and the dnsmasq hosts file
(Domain exceptions left out), and writes `/config/.reload-dns`. The dns
container's watchdog sends dnsmasq `SIGHUP` within about 2 seconds, and the
proxy's watchdog reloads Squid when it sees its files change; the answer waits
for neither. The UI offers it as "Send the lists to the DNS sinkhole and the
proxy again" on Blocked domains and "Send the lists again" in Settings,
Maintenance, for a change that has not taken effect.

`data` is counted by the export while it writes the hosts file:

| Field | Meaning |
|---|---|
| `domains` | Domain blacklist entries given to the DNS sinkhole. |
| `left_out` | Entries left out because their name is on Domain exceptions. |

Both count entries, not distinct names: `*.example.com` and `example.com` are
two. Before this, `domains` was the number of rows in the table, entries left
out included.

```json
{ "status": "success", "message": "Lists exported: 640926 domain entries for the DNS sinkhole, 3 left out by the allowed list", "data": { "domains": 640926, "left_out": 3 } }
```

---

## Cache statistics

```
GET /api/cache/statistics
```

Returns the proxy's last collection of Squid's cache statistics. The proxy's watchdog reads Squid's cache manager (the `info` page, and `storedir` for the disk capacity) from localhost once a minute and writes `/config/cache_stats.json`; this endpoint reports that file.

`state` says what the values are:

| `state` | Meaning |
|---|---|
| `current` | Collected within the last three collection intervals (180 s at the default 60 s). |
| `stale` | Collected, but not since then: the values are the last ones and `age_s` says how old. |
| `not_collected` | No file: a proxy that has not collected yet, or one older than this file. Every value is null. |
| `unreadable` | A file this backend cannot read. Every value is null. |

`collected_at` is UTC (`2026-10-25 12:15:28`), `age_s` and `stale_after_s` are seconds. The values are Squid's own, as it printed them; a value Squid did not print is `null`, never 0:

| Field | Squid's line |
|---|---|
| `request_hit_ratio_5min_pct`, `request_hit_ratio_60min_pct` | `Hits as % of all requests` (percent) |
| `byte_hit_ratio_5min_pct`, `byte_hit_ratio_60min_pct` | `Hits as % of bytes sent` (percent, can be negative) |
| `disk_used_kb`, `disk_used_pct` | `Storage Swap size`, `Storage Swap capacity` |
| `disk_capacity_kb` | storedir `Maximum Swap Size` |
| `memory_used_kb`, `memory_used_pct` | `Storage Mem size`, `Storage Mem capacity` |
| `uptime_s` | `UP Time` |
| `store_entries`, `memory_objects`, `disk_objects` | `StoreEntries`, `Hot Object Cache Items`, `on-disk objects` |

Squid takes its first statistics sample one minute after it starts and prints 0.0% until then, so the hit ratios are `null` for the first 60 s of uptime. Until Squid has run for an hour, its 60 minute window covers the time since it started (`uptime_s`). Each collection is one request Squid itself counts, as a miss, in these ratios.

**Deprecated fields.** The fields this endpoint returned before collection worked are still present for one release, as aliases of the values above: `hit_rate` and `byte_hit_rate` (the 5 minute ratios), `cache_size` and `max_cache_size` (`disk_used_kb` and `disk_capacity_kb` as text, `"N/A"` when unknown), `objects_cached` (`store_entries`) and `simulated` (`true` whenever `state` is not `current`). `hits`, `misses` and `requests` were never measured and are `null`. Read the fields above instead; the aliases will be removed in the next contract version.

---

## Clear proxy cache

```
POST /api/maintenance/clear-cache
```

Empties the Squid disk cache. The proxy's watchdog stops Squid, deletes
everything inside the `cache_dir` named in the generated `squid.conf`, recreates
its layout with `squid -z` and starts Squid again, which also empties the memory
cache. Requests in progress are cut off and new ones are refused until Squid is
back. The watchdog refuses a `cache_dir` that does not resolve to
`/var/spool/squid` or a directory under it, and then stops and deletes nothing.

**This call blocks** for up to **45 seconds** while the watchdog acknowledges
what it did:

| HTTP | `status` | Meaning |
|---|---|---|
| `200` | `success` | The disk cache was emptied and Squid is running again. `data.objects_removed` is the number of stored objects deleted |
| `500` | `error` (`code: clear_cache_failed`) | `detail` says what stopped it; `data.step` names the step: `check` (the `cache_dir` was refused, nothing was touched), `stop`, `empty`, `create`, `start` or `error` |
| `200` | `pending` | Nothing acknowledged within the timeout; check that the proxy container is running |

---

## Backup configuration

```
GET /api/maintenance/backup-config
```

Returns, in `data`, the backup envelope: `backup_version`, `app_version`, `exported_at`, every setting as stored (secrets stay encrypted with this install's key) and the five lists (`ip_blacklist`, `ip_whitelist`, `domain_blacklist`, `domain_whitelist`, `dst_allowlist`). The audit log and the users table are not included. The Settings page saves `data` as the backup file.

---

## Restore configuration

```
POST /api/maintenance/restore-config
```

Restores from a backup created by `/api/maintenance/backup-config`.

The body is the backup envelope (or, for an older backup, `{"config": {...}}`). Each setting in the file replaces the stored one; settings that are not in the file are left as they are. List entries are added; entries already present stay, and none are removed. After the transaction the proxy configuration files the settings drive are written, as a Save writes them; ask `POST /api/maintenance/reload-config` to apply them.

List entries are checked with the same rules as the endpoints that add them. An entry that fails is skipped, not fatal, and counted in `skipped_entries`. Settings are checked with the settings API's rules; each one that is not restored is listed in `skipped_settings` with its reason (`default_password_changed`, which every backup contains, is always skipped).

```json
{
  "status": "success",
  "restored_settings": 41,
  "restored_entries": 120,
  "skipped_settings": [{ "key": "default_password_changed", "reason": "managed by the application, not restored from a file" }],
  "skipped_entries": 0,
  "failed_files": [],
  "restored": 161,
  "skipped": 1
}
```

`failed_files` names proxy configuration files that could not be written. `restored` and `skipped` are the older totals.

---

## Check certificate security

```
GET /api/maintenance/check-cert-security
```

Reports whether `/config/ssl_cert.pem` exists and whether `/config/ssl_db`
holds a certificate database. It does not read the certificate.

```json
{ "status": "success", "message": "Certificate security check completed", "data": { "issues": [], "cert_found": true, "db_found": true } }
```

`status` is `"error"`, still with HTTP 200, when `issues` is not empty.

---

## Download CA certificate

```
GET /api/security/download-ca
```

Returns `/config/ssl_cert.pem` as the attachment `secure-proxy-ca.pem`, or
`404` when the proxy has not generated it yet. Clients must trust it while
HTTPS inspection is on.

---

## Rate limits

```
GET /api/security/rate-limits
```

Lists the client addresses with counted Basic authentication attempts in the
current window:

```json
{
  "status": "success",
  "data": [{ "ip": "192.168.1.20", "attempts": 5, "blocked": true }],
  "meta": { "max_attempts": 5, "window_seconds": 300 }
}
```

`blocked` is true when the address has reached `max_attempts`.

```
DELETE /api/security/rate-limits/{ip}
```

Clears the address's count, or answers `404` when it has none.
