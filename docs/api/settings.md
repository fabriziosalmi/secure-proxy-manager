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

Setting values that are stored encrypted at rest (those whose key contains `password`, `secret`, `token`, or `webhook`) are decrypted before being returned.

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

All updates are applied in a single transaction. The same name and value validation applies as for the single-setting endpoint.

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

Asks the proxy to regenerate `squid.conf` from the latest blacklist/whitelist files and reload. Equivalent to `squid -k reconfigure`.

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

Returns Squid cache metrics (hit ratio, memory and disk usage). When the Squid cache manager is unavailable, the response is annotated with `simulated: true` and zeroed values.

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

Downloads a backup containing the current settings, blacklists, and whitelists in JSON form.

---

## Restore configuration

```
POST /api/maintenance/restore-config
```

Restores from a backup created by `/api/maintenance/backup-config`.

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
