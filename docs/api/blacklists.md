# Blacklist & Whitelist API

Base URL: `http://localhost:8011/api` (via UI proxy) or `http://localhost:5001/api` (direct backend).

All endpoints require Basic Auth.

---

## IP Blacklist {#ip-blacklist}

### List entries

```
GET /api/blacklists/ip
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "ip": "203.0.113.5",
      "description": "known malicious",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/blacklists/ip
```

**Request body:**
```json
{
  "ip": "203.0.113.0/24",
  "description": "optional description"
}
```

### Delete entry

```
DELETE /api/blacklists/ip/{id}
```

---

## Domain Blacklist {#domain-blacklist}

### List entries

```
GET /api/blacklists/domains
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "domain": "malicious.com",
      "description": "",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/blacklists/domains
```

**Request body:**
```json
{
  "domain": "*.ads.example.com",
  "description": "optional description"
}
```

### Delete entry

```
DELETE /api/blacklists/domains/{id}
```

---

## Import {#import}

Import multiple entries from a URL or inline content.

```
POST /api/blacklists/import
```

**Request body — from URL:**
```json
{
  "type": "domain",
  "url": "https://example.com/domains.txt"
}
```

**Request body — inline content:**
```json
{
  "type": "ip",
  "content": "192.0.2.1\n198.51.100.0/24\n203.0.113.5"
}
```

`type` must be `"domain"` or `"ip"`.

**Response:**
```json
{
  "status": "success",
  "message": "Import completed",
  "data": {
    "added": 150,
    "skipped": 3,
    "errors": ["Invalid format: not-an-ip"]
  }
}
```

**Supported file formats:**
- Plain text, one entry per line
- JSON array: `["entry1", "entry2"]`
- JSON objects: `[{"domain": "example.com"}]`
- Lines starting with `#` are ignored

::: warning SSRF protection
Import URLs are validated against SSRF rules. Private IP ranges, loopback, and link-local addresses are rejected.
:::

---

## Geo Import

Import IP ranges for one or more countries.

```
POST /api/blacklists/import-geo
```

**Request body:**
```json
{
  "countries": ["RU", "CN", "KP"]
}
```

---

## IP Whitelist {#ip-whitelist}

Whitelisted destination IPs bypass the direct-IP block rule in Squid.

### List entries

```
GET /api/ip-whitelist
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "ip": "192.168.1.50",
      "description": "Home NAS",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/ip-whitelist
```

**Request body:**
```json
{
  "ip": "192.168.1.0/24",
  "description": "LAN subnet"
}
```

### Delete entry

```
DELETE /api/ip-whitelist/{id}
```
