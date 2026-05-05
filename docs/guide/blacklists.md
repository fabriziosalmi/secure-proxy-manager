# Blacklists and Whitelists

Secure Proxy Manager keeps four lists, each with its own role in the request path:

| List | Layer | Effect |
|---|---|---|
| Domain blacklist | Squid + dnsmasq | Domain is rejected by Squid; dnsmasq sinkholes it to `0.0.0.0` |
| IP blacklist | Squid | Squid rejects connections to the matching destination IP or CIDR range |
| IP whitelist | Squid | Whitelisted destination IPs bypass the direct-IP block rule |
| Domain whitelist | dnsmasq | Domains are excluded from the dnsmasq sinkhole, so they resolve normally even if blacklisted |

## Domain blacklist

Blocks HTTP and HTTPS requests to matching destinations.

- Exact match: `malicious.example`
- Wildcard subdomain: `*.ads.example.com`

Manage via **Web UI → Blacklists → Domains** or the [API](/api/blacklists#domain-blacklist).

## IP blacklist

Blocks requests targeting the matching destination IP.

- Single IP: `203.0.113.5`
- CIDR range: `198.51.100.0/24`

Manage via **Web UI → Blacklists → IPs** or the [API](/api/blacklists#ip-blacklist).

## IP whitelist

Whitelisted destination IPs bypass the direct-IP block rule. Use this for trusted LAN devices reached by IP (NAS, printers, IoT devices).

- Single IP: `192.168.1.50`
- CIDR range: `192.168.1.0/24`

::: tip
The IP whitelist applies to **destination** IPs. It does not affect blocking of source IPs.
:::

Manage via **Web UI → Blacklists → Whitelist** or the [API](/api/blacklists#ip-whitelist).

## Domain whitelist

Whitelisted domains are removed from the dnsmasq blocklist, so they resolve normally even if they are also present in the domain blacklist. Use this for essential services (GitHub, Docker registries, package mirrors) before importing large blocklists that may include them.

Manage via **Web UI → Blacklists → Domain Whitelist** or the [API](/api/blacklists#domain-whitelist).

## Importing blocklists

### Curated public lists (one click)

In the web UI, open **Blacklists → Popular lists** to import any of the following:

**IP lists.**

- Firehol Level 1
- Spamhaus DROP and EDROP
- Emerging Threats (compromised hosts and C2)
- CINS Army
- Stamparm Ipsum (level 3+)
- Blocklist.de (last 48 hours)
- Talos Intelligence

**Domain lists.**

- Aggregated Blacklist (`fabriziosalmi/blacklists`, ~2.9 M entries)
- StevenBlack Unified hosts
- URLhaus malware domains (abuse.ch)
- Phishing Army
- OISD Big
- HaGeZi Multi Pro
- NoTracking
- DanPollock hosts

The exact list, URLs, and descriptions are defined in `ui/src/pages/Blacklists.tsx` and may evolve between releases.

### Import from URL

```bash
AUTH="Authorization: Basic $(printf '%s' "$USER:$PASS" | base64)"

# Domain blocklist from URL
curl -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "url": "https://example.com/domains.txt"}'

# IP blocklist from URL
curl -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "ip", "url": "https://example.com/ips.txt"}'
```

Per-type endpoints are also accepted: `POST /api/ip-blacklist/import` and `POST /api/domain-blacklist/import`.

### Import inline content

```bash
curl -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "content": "badsite.example\n*.ads.example\nmalicious.example"}'
```

### Supported formats

- Plain text — one entry per line.
- JSON array — `["entry1", "entry2"]`.
- JSON objects — `[{"domain": "example.com"}]`.
- Lines beginning with `#` are ignored.

### Geo-based IP blocking

```bash
curl -X POST https://localhost:8443/api/blacklists/import-geo \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"countries": ["RU", "CN"]}'
```

Country IP ranges are pulled from `herrbischoff/country-ip-blocks` (IPv4) and merged into the IP blacklist.

## Automatic refresh

A background worker re-imports a fixed pair of public lists when auto-refresh is enabled in **Settings → Auto-refresh**:

- `auto_refresh_enabled`: `true` to enable.
- `auto_refresh_hours`: re-fetch interval in hours (default `24`).

The defaults imported on each cycle are:

- IP: Firehol Level 1, Stamparm Ipsum (level 1).
- Domain: StevenBlack Unified hosts, URLhaus.

To schedule additional custom feeds, run a host cron job that calls the import endpoint:

```bash
0 3 * * * curl -s -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" \
  -u USER:PASS \
  -d '{"type": "domain", "url": "https://big.oisd.nl/domainswild"}'
```
