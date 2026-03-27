# Settings & Maintenance API

All endpoints require Basic Auth.

---

## Get all settings

```
GET /api/settings
```

Returns all settings as an array.

**Response:**
```json
[
  { "setting_name": "enable_https_filtering", "setting_value": "false" },
  { "setting_name": "cache_size", "setting_value": "2000" }
]
```

---

## Update a setting

```
PUT /api/settings/{setting_name}
```

**Request body:**
```json
{
  "value": "true"
}
```

---

## Health check

```
GET /health
GET /api/health
```

Returns 200 if the backend is reachable. No authentication required.

**Response:**
```json
{
  "status": "healthy"
}
```

---

## Database export

```
GET /api/database/export
```

Exports the database as JSON. Sensitive setting values are redacted. Log entries are limited to the 10,000 most recent.

---

## Database statistics

```
GET /api/database/stats
```

Returns database size and record counts.

---

## Database optimize

```
POST /api/database/optimize
```

Runs `VACUUM` and `ANALYZE` on the SQLite database.

---

## Reload proxy configuration

```
POST /api/maintenance/reload-config
```

Sends `squid -k reconfigure` to the proxy container. Use this after manually editing configuration files.

---

## Cache statistics

```
GET /api/cache/statistics
```

Returns cache metrics. When the Squid cache manager is not accessible, returns `simulated: true` with zeroed values.

**Response:**
```json
{
  "simulated": true,
  "hit_ratio": 0,
  "memory_usage_mb": 0,
  "disk_usage_mb": 0
}
```

---

## Bulk update settings

```
POST /api/settings
```

Update multiple settings in a single request.

**Request body:**
```json
{
  "settings": [
    { "setting_name": "enable_https_filtering", "setting_value": "true" },
    { "setting_name": "cache_size", "setting_value": "5000" }
  ]
}
```

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

Resets the database, clearing all entries. Use with caution.

---

## Reload DNS configuration

```
POST /api/maintenance/reload-dns
```

Reloads the dnsmasq DNS configuration after domain blacklist/whitelist changes.

---

## Clear proxy cache

```
POST /api/maintenance/clear-cache
```

Clears the Squid proxy disk cache.

---

## Backup configuration

```
GET /api/maintenance/backup-config
```

Downloads a backup archive of the current configuration files from `/config/`.

---

## Restore configuration

```
POST /api/maintenance/restore-config
```

Restores configuration from a previously downloaded backup archive.

---

## Check certificate security

```
GET /api/maintenance/check-cert-security
```

Checks the strength and validity of the SSL certificate used for HTTPS filtering.

---

## Download CA certificate

```
GET /api/security/download-ca
```

Downloads the proxy CA certificate (`ssl_cert.pem`). Install this on client devices to avoid browser warnings when HTTPS filtering is enabled.

---

## Rate limits

```
GET /api/security/rate-limits
```

Lists IPs that are currently rate-limited due to repeated failed authentication attempts.

---

## Remove rate limit

```
DELETE /api/security/rate-limits/{ip}
```

Removes the rate limit for a specific IP address, allowing it to attempt authentication again immediately.
