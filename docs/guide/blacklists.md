# Blacklists and Whitelists

## Domain Blacklist

Blocks HTTP and HTTPS requests to matching domains. Supports:

- Exact match: `malicious.com`
- Wildcard subdomain: `*.ads.example.com`

Manage via: **Web UI → Blacklists → Domains** or the [API](/api/blacklists#domain-blacklist).

## IP Blacklist

Blocks requests originating from matching IP addresses or CIDR ranges.

- Single IP: `203.0.113.5`
- CIDR range: `198.51.100.0/24`

Manage via: **Web UI → Blacklists → IPs** or the [API](/api/blacklists#ip-blacklist).

## IP Whitelist

Whitelisted destination IPs bypass the direct-IP block rule. Use this for trusted LAN devices accessed by IP address (NAS, printers, IoT devices).

- Single IP: `192.168.1.50`
- CIDR range: `192.168.1.0/24`

::: tip
The IP whitelist allows traffic **to** specific destination IPs. It does not affect the source IP blacklist.
:::

Manage via: **Web UI → Blacklists → Whitelist** or the [API](/api/blacklists#ip-whitelist).

## Importing Blocklists

### Popular Lists (one-click)

In the web UI, go to **Blacklists** and click **Popular Lists** to import pre-configured feeds:

**Domains:**
- StevenBlack (ad/malware hosts consolidated list)
- MalwareDomainList
- Phishing Army

**IPs:**
- Firehol Level 1 (active threats)
- Spamhaus DROP (malware/botnet ASNs)
- Emerging Threats (C&C and compromised hosts)

### Import from URL

```bash
AUTH="Authorization: Basic $(echo -n YOUR_USER:YOUR_PASS | base64)"

# Domain blocklist from URL
curl -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"type": "domain", "url": "https://example.com/domains.txt"}'

# IP blocklist from URL
curl -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"type": "ip", "url": "https://example.com/ips.txt"}'
```

### Import inline content

```bash
curl -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"type": "domain", "content": "badsite.com\n*.ads.example\nmalicious.net"}'
```

### Supported formats

- Plain text — one entry per line (most common)
- JSON array — `["entry1", "entry2"]`
- JSON objects — `[{"domain": "example.com"}]`
- Lines starting with `#` are ignored

### Geo-based IP blocking

```bash
curl -X POST http://localhost:8011/api/blacklists/import-geo \
  -H "Content-Type: application/json" \
  -H "$AUTH" \
  -d '{"countries": ["RU", "CN"]}'
```

## Scheduling automatic updates

The built-in scheduler does not yet support automatic feed refresh. Use a host cron job:

```cron
0 3 * * * curl -s -X POST http://localhost:8011/api/blacklists/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n USER:PASS | base64)" \
  -d '{"type": "domain", "url": "https://hosts.oisd.nl/"}'
```
