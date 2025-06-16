# Blacklist Import Examples

This document provides examples for importing blacklists using the Secure Proxy Manager API.

## Domain Blacklist Import

### From Plain Text URL (Recommended)

The user's example file format works perfectly:

```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/blacklist.txt"}'
```

**Example blacklist.txt file:**
```
0123movies.10s.live
0123movies.com
0123movies.is
0123movies.net
0123movies.org
0123movies.st
0123movies4u.com
0123movieshd.com
# This is a comment and will be ignored
*.malicious-ads.com
```

### Direct Content Import

```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{
    "content": "example.com\n*.badsite.org\nmalicious.net\n# Comment line"
  }'
```

### JSON Format Import

```bash
curl -X POST http://localhost:8011/api/domain-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{
    "content": "[\"example.com\", \"badsite.org\", \"*.malicious.com\"]"
  }'
```

## IP Blacklist Import

### From Plain Text URL

```bash
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/ip-blacklist.txt"}'
```

**Example ip-blacklist.txt file:**
```
192.168.1.100
10.0.0.5
172.16.0.1
203.0.113.0/24
# CIDR notation is supported
198.51.100.0/24
```

### Direct Content Import

```bash
curl -X POST http://localhost:8011/api/ip-blacklist/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{
    "content": "192.168.1.100\n10.0.0.5\n172.16.0.0/24"
  }'
```

## Alternative: Generic Import Endpoint

You can also use the generic endpoint with a type parameter:

### Domain Import
```bash
curl -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/blacklist.txt", "type": "domain"}'
```

### IP Import
```bash
curl -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n admin:admin | base64)" \
  -d '{"url": "https://example.com/blacklist.txt", "type": "ip"}'
```

## Response Format

All endpoints return a JSON response:

```json
{
  "status": "success",
  "message": "Import completed: 8 entries imported",
  "imported_count": 8,
  "error_count": 0,
  "errors": []
}
```

If there are errors:

```json
{
  "status": "success",
  "message": "Import completed: 6 entries imported, 2 errors",
  "imported_count": 6,
  "error_count": 2,
  "errors": [
    "Invalid domain format: not-a-valid-domain",
    "Invalid IP format: 999.999.999.999"
  ]
}
```

## Supported Formats

- **Plain Text**: One entry per line (most common format)
- **JSON Array**: `["entry1", "entry2", "entry3"]`
- **JSON Objects**: `[{"domain": "example.com", "description": "Blocked"}]`
- **Comments**: Lines starting with `#` are ignored
- **CIDR Notation**: Supported for IP addresses (e.g., `192.168.1.0/24`)
- **Wildcards**: Supported for domains (e.g., `*.example.com`)

## Notes

- Duplicate entries are automatically skipped
- Invalid entries are logged but don't stop the import process
- The system automatically updates the proxy configuration after import
- Large files are supported (tested with lists containing thousands of entries)
