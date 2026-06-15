# Blacklist and Whitelist API

Base URLs:

- Through the `web` reverse proxy (recommended): `https://localhost:8443/api`
- Directly to the backend (localhost only): `http://127.0.0.1:5001/api`

All endpoints require authentication (Basic or JWT). All response bodies follow the envelope `{"status": "success" | "error", "data": ..., "detail": ...}`.

---

## IP blacklist {#ip-blacklist}

### List entries

```
GET /api/ip-blacklist
```

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
POST /api/ip-blacklist
```

```json
{
  "ip": "203.0.113.0/24",
  "description": "optional description"
}
```

`ip` accepts a single address or a CIDR range. Wildcards are not supported for IPs.

### Delete entry

```
DELETE /api/ip-blacklist/{id}
```

### Bulk delete

```
POST /api/ip-blacklist/bulk-delete
```

```json
{ "ids": [1, 2, 3] }
```

### Clear all

```
DELETE /api/ip-blacklist/clear-all
```

### Import (per-type)

```
POST /api/ip-blacklist/import
```

Same body as the unified `/api/blacklists/import` endpoint, with `type` defaulted to `"ip"`.

---

## Domain blacklist {#domain-blacklist}

### List entries

```
GET /api/domain-blacklist
```

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "domain": "malicious.example",
      "description": "",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/domain-blacklist
```

```json
{
  "domain": "*.ads.example.com",
  "description": "optional description"
}
```

`domain` accepts an exact FQDN or a wildcard subdomain pattern (`*.example.com`).

### Delete entry

```
DELETE /api/domain-blacklist/{id}
```

### Bulk delete

```
POST /api/domain-blacklist/bulk-delete
```

```json
{ "ids": [1, 2, 3] }
```

### Clear all

```
DELETE /api/domain-blacklist/clear-all
```

### Import (per-type)

```
POST /api/domain-blacklist/import
```

Same body as the unified `/api/blacklists/import` endpoint, with `type` defaulted to `"domain"`.

---

## Unified import {#import}

Import multiple entries from a URL or inline content.

```
POST /api/blacklists/import
```

**From URL:**

```json
{
  "type": "domain",
  "url": "https://example.com/domains.txt"
}
```

**Inline content:**

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
  "data": {
    "added": 150,
    "skipped": 3,
    "errors": ["Invalid format: not-an-ip"]
  }
}
```

**Supported file formats:**

- Plain text, one entry per line.
- JSON array — `["entry1", "entry2"]`.
- JSON objects — `[{"domain": "example.com"}]`.
- Lines beginning with `#` are ignored.

::: warning SSRF protection
Import URLs are validated. Hosts that resolve to loopback, private, link-local, multicast, or other special-purpose ranges are rejected, and the resolved IP is pinned to prevent DNS rebinding mid-download. The download is capped at 200 MB.
:::

---

## Geo import {#geo-import}

```
POST /api/blacklists/import-geo
```

```json
{ "countries": ["RU", "CN", "KP"] }
```

Country IP ranges are fetched from `herrbischoff/country-ip-blocks` (IPv4) and added to the IP blacklist.

---

## IP whitelist {#ip-whitelist}

Whitelisted destination IPs bypass the direct-IP block rule in Squid.

### List entries

```
GET /api/ip-whitelist
```

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

---

## Domain whitelist {#domain-whitelist}

Whitelisted domains are excluded from the dnsmasq sinkhole, so they resolve normally even when present in the domain blacklist.

### List entries

```
GET /api/domain-whitelist
```

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "domain": "github.com",
      "type": "fqdn",
      "description": "Essential — code hosting",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/domain-whitelist
```

```json
{
  "domain": "github.com",
  "description": "Essential — code hosting"
}
```

### Delete entry

```
DELETE /api/domain-whitelist/{id}
```

---

## Egress allowlist {#egress-allowlist}

The egress allowlist is the deny-by-default complement to the blacklists. It is consulted only when default-deny egress is enabled (the `egress_default_deny` setting, default `false`). While that setting is off — the default — behaviour is unchanged: clients may reach any destination not on a blacklist, and this allowlist has no effect. When it is on, the proxy denies all outbound egress from local clients except destinations on this allowlist; everything else is refused with a Squid 403.

The `egress_default_deny` toggle is set via the bulk settings endpoint (`POST /api/settings`, flat `{name: value}` body), not through this group.

Each entry is either an IP/CIDR (matched by Squid `dst`) or a domain (matched by Squid `dstdomain`). The type is auto-classified on add: a value parseable as an IP or CIDR is stored as type `cidr`, otherwise it is treated as a `domain`.

### List entries

```
GET /api/egress-allowlist
```

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "entry": "acme-v02.api.example",
      "type": "domain",
      "description": "ACME server",
      "added_date": "2026-03-01T12:00:00"
    }
  ]
}
```

### Add entry

```
POST /api/egress-allowlist
```

```json
{
  "entry": "203.0.113.0/24",
  "description": "optional description"
}
```

`entry` accepts an IP, a CIDR range, or a domain; the type is auto-classified to `cidr` or `domain`.

**Success:**

```json
{
  "status": "success",
  "message": "Entry added to egress allowlist"
}
```

A 400 is returned with `"entry must be an IP, CIDR, or domain"` when `entry` is empty, whitespace, or otherwise invalid, and with `"entry already in allowlist"` on a duplicate.

### Delete entry

```
DELETE /api/egress-allowlist/{id}
```

### Bulk delete

```
POST /api/egress-allowlist/bulk-delete
```

```json
{ "ids": [1, 2, 3] }
```

### Clear all

```
DELETE /api/egress-allowlist/clear-all
```
