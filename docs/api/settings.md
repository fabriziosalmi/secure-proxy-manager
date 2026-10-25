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

The alert channel settings are secrets: `webhook_url`, `gotify_url`, `gotify_token`, `teams_webhook_url`, `telegram_bot_token`, `telegram_chat_id`, `ntfy_url` and `ntfy_topic` (`crypto.SensitiveKeys` in the backend). They are stored encrypted and are write-only: their row carries `"secret": true`, an empty `setting_value`, `"is_set": true` when a value is stored, and `"decrypt_failed": true` when the stored value cannot be decrypted with the current key (`ENCRYPTION_KEY`, or the key the backend generated in its state directory when that is unset).

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

The key in the path must consist of alphanumeric characters and underscores only and be no longer than 100 characters. The value is capped at 10 000 characters.

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

All updates are applied in a single transaction. The same name and value validation applies as for the single-setting endpoint. A value that fails validation answers `400` with `detail` starting with the key name, for example `"bandwidth_limit_mbps: must be a positive number"`.

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

`egress_default_deny` is a boolean setting (default `"false"`) toggled like any other value through the bulk or single-setting endpoints. It is also exposed as the "Default-deny egress" toggle on the Settings page, next to SSL inspection.

When `"false"` (the default) behaviour is unchanged: local clients may reach any destination that is not on a blacklist. When `"true"` the proxy denies all outbound egress from local clients except destinations on an explicit allowlist; everything else is refused with a Squid 403.

The allowlist destinations themselves are not setting values. They are managed through the egress-allowlist endpoints (`/api/egress-allowlist`), where each entry is either an IP/CIDR or a domain. See the egress allowlist API for details.

---

## Health

```
GET /health
GET /api/health
```

Returns 200 if the backend is reachable. Authentication is not required.

```json
{ "status": "healthy", "version": "3.4.4" }
```

---

## Database export

```
GET /api/database/export
```

Returns a JSON dump of every exported table. Columns named `password`, `secret`, or `token` are replaced with `***REDACTED***`. The download is served as `Content-Disposition: attachment`.

---

## Database statistics

```
GET /api/database/stats
```

Returns row counts for every exported table along with the file size.

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

Returns the database file size in bytes.

---

## Database reset

```
POST /api/database/reset
```

Truncates every exported table except `users`. Use with care.

---

## Reload proxy configuration

```
POST /api/maintenance/reload-config
```

Asks the proxy to regenerate `squid.conf` from the latest blacklist/whitelist
files and reload.

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

Regenerates the dnsmasq blocklist (with whitelist exclusions) and signals the `dns` container to reload (`SIGHUP`).

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

Clears the Squid disk cache.

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

Reports the strength and validity of the SSL bump certificate.

---

## Download CA certificate

```
GET /api/security/download-ca
```

Returns `/config/ssl_cert.pem`. Install it on client devices to suppress browser warnings when SSL bump is active.

---

## Rate limits

```
GET /api/security/rate-limits
```

Lists IPs currently locked out by the login-failure rate limiter, with the time at which the lockout expires.

```
DELETE /api/security/rate-limits/{ip}
```

Removes the lockout for the given IP.
