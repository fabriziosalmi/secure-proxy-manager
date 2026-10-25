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
    { "setting_name": "cache_size",       "setting_value": "1000"  }
  ]
}
```

Values are strings. The defaults a new database gets are in
`seedDefaultSettings` in `backend-go/internal/database/db.go`.

The alert channel settings are secrets: `webhook_url`, `webhook_bearer_token` (sent as `Authorization: Bearer <token>` with each webhook delivery), `gotify_url`, `gotify_token`, `teams_webhook_url`, `telegram_bot_token`, `telegram_chat_id`, `ntfy_url` and `ntfy_topic` (`crypto.SensitiveKeys` in the backend). They are stored encrypted and are write-only: their row carries `"secret": true`, an empty `setting_value`, `"is_set": true` when a value is stored, and `"decrypt_failed": true` when the stored value cannot be decrypted with the current key (`ENCRYPTION_KEY`, or the key the backend generated in its state directory when that is unset).

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

This endpoint only stores the value. It writes none of the files the proxy and the DNS service read (toggle markers, `squid_settings.env`, list files), so a proxy setting changed here takes effect only after a later `POST /api/settings` that carries it. Use `POST /api/settings` for anything the proxy enforces.

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

Values that depend on each other are checked together, with the stored value for the half the request does not carry: with `enable_time_restrictions` on, `time_restriction_end` must be later than `time_restriction_start`; with `enable_content_filtering` on, `blocked_file_types` must list at least one extension. Notification URLs must be http or https, without credentials, and not point at this host; at delivery the backend also refuses any address of the networks it is attached to.

The settings nothing reads (`tailscale_*`, `ddns_*`, `auth_method`, `enable_ip_blacklist`, `enable_domain_blacklist`, `enable_waf`, `block_direct_ip`) are skipped, like internally managed keys: the rest of the request is saved, `PUT` answers `400` for them, and a restore lists them as not restored.

A request that carries WAF heuristics (`waf_h_*`) reports what the running WAF did with each in `data.waf`: `{"pushed": ["waf_h_pii"], "failed": [{"key": "waf_h_sequence", "reason": "..."}]}`.

A secret sent with an empty value keeps its stored value, and the response lists it in `data.kept`. To remove a secret, name it in the `clear` query parameter (comma separated): `POST /api/settings?clear=gotify_token,gotify_url`. Only secrets can be cleared this way, and a key cannot be cleared and given a value in the same request (`400`).

```json
{ "status": "success", "message": "Settings updated", "data": { "kept": ["gotify_token"] } }
```

When some proxy configuration files could not be written the answer is still `200`, with `"status": "partial"` and the file names in `data.failed`.

---

## Default-deny egress

```
POST /api/settings
```

```json
{ "egress_default_deny": "true" }
```

`egress_default_deny` is a boolean setting, sent as the string `"true"` or `"false"` (default `"false"`). `POST /api/settings` writes or removes the marker file `/config/egress_default_deny`; `POST /api/maintenance/reload-config` then makes the proxy apply it. `PUT /api/settings/egress_default_deny` stores the value without writing the marker. The setting is also the "Only allowlisted destinations" toggle under Settings > Filtering, which refuses to save it while the allowlist is empty; the API does not refuse.

When `"false"` (the default) local clients may reach any destination that is not blocked. When `"true"` they may reach only the destinations on the egress allowlist, LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and Allowed IPs; everything else is refused with a Squid 403.

The allowlist destinations themselves are not setting values. They are managed through the egress-allowlist endpoints (`/api/egress-allowlist`), where each entry is either an IP/CIDR or a domain. See the egress allowlist API for details.

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
`list_sources`, `dst_allowlist`, `proxy_logs`, `settings` and `audit_log`,
served as the attachment `database_export.json`. Columns named `password`,
`secret` or `token` are replaced with `***REDACTED***`. The alert channel
secrets are rows of `settings`, so they appear in their encrypted form
(`enc::...`). Restore cannot read this file; use the configuration backup.

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

Deletes every row of the tables above except `users`, settings included; the
default settings are inserted again at the next backend start. The audit row
for the reset is written first and deleted with the rest. Use with care.

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
| `200` | `pending` | Nothing acknowledged within the timeout; check that the proxy container is running |

A caller that treats any `200` as success will read `pending` as applied.

---

## Reload DNS configuration

```
POST /api/maintenance/reload-dns
```

Exports the lists, including the dnsmasq hosts file (Allowed domains left
out), and writes `/config/.reload-dns`. The dns container's watchdog sends
dnsmasq `SIGHUP` within about 2 seconds; the answer does not wait for it.

```json
{ "status": "success", "message": "DNS blocklist updated with 640929 domains", "data": { "domains": 640929 } }
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
