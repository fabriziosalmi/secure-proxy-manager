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
```

Returns 200 if the backend is reachable. No authentication required.

**Response:**
```json
{
  "status": "ok"
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
