# Blacklist and Whitelist API

Base URLs:

- Through the `web` reverse proxy (recommended): `https://localhost:8443/api`
- Directly to the backend (localhost only): `http://127.0.0.1:5001/api`

All endpoints require authentication (Basic or JWT). All response bodies follow the envelope `{"status": "success" | "error", "data": ..., "detail": ...}`.

---

## IP blacklist {#ip-blacklist}

### List entries

```
GET /api/ip-blacklist?limit=50&offset=0&search=203.0
```

`limit` is 1 to 1000 (default 100); `search` matches the entry and its description. Newest first.

```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "ip": "203.0.113.5",
      "description": "known malicious",
      "added_date": "2026-03-01 12:00:00",
      "source_id": 4,
      "source_kind": "url",
      "source": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
      "source_label": "Firehol Level 1"
    }
  ],
  "meta": { "total": 50772, "limit": 50, "offset": 0 }
}
```

`added_date` is UTC. `source_kind` is `url`, `manual`, `geo`, `paste` or `restore` (see [Sources](#sources)); it, `source` and `source_label` are `null` for an entry added before sources were recorded. The same fields are on every list endpoint below. Read the count from `meta.total`: the top-level `total`, `limit` and `offset` beside it are deprecated.

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

A refusal is a `400` whose `detail` names the value and the list as the page does: `"300.1.1.1" is not an IP address or network`, `"203.0.113.9" is already on Blocked IPs`. The domain lists and the allowed lists answer the same way (`is not a domain name: labels of letters, digits and hyphens separated by dots`, `is already on Allowed domains`).

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

### Import (per-type, retired)

```
POST /api/ip-blacklist/import
```

Answers `410 Gone`: use `POST /api/blacklists/import` with `type: "ip"`.

---

## Domain blacklist {#domain-blacklist}

### List entries

```
GET /api/domain-blacklist
```

Same shape as the IP list, with `domain` in place of `ip`.

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

`domain` accepts an exact name. A `*.` or `.` prefix is accepted too, but an entry blocks one exact name either way: `*.example.com` and `.example.com` block `example.com` itself (the exporter and the proxy drop the `*.` and the leading dot), not its subdomains. While the list holds `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries (default 1,000,000) a new one is refused with `413`.
A URL is reduced to its hostname (a port is dropped). Anything else is refused with `400`: only letters, digits, hyphens, underscores and dots are allowed, with labels of 1-63 characters and no more than 253 in all. In particular, whitespace, tabs, newlines and colons are refused, because entries are written one per line into the proxy and DNS files.

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

### Import (per-type, retired)

```
POST /api/domain-blacklist/import
```

Answers `410 Gone`: use `POST /api/blacklists/import` with `type: "domain"`.

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
  "url": "https://example.com/domains.txt",
  "name": "Example list"
}
```

The entries are recorded under the URL as their source; importing the same URL again adds to that source. The optional `name` (at most 100 characters) labels it, as the Popular lists in the UI do.

**Inline content:**

```json
{
  "type": "ip",
  "content": "192.0.2.1\n198.51.100.0/24\n203.0.113.5"
}
```

`type` must be `"domain"` or `"ip"`. Inline content is recorded as a new pasted-list source each time. An import that would take the domain blacklist past `SPM_DNS_BLOCKLIST_MAX_DOMAINS` is refused whole with `413`.

**Response:**

```json
{
  "status": "success",
  "message": "Successfully imported 150 entries (3 skipped/invalid)",
  "data": {
    "added": 150,
    "skipped": 3,
    "bogon_skipped": 0
  }
}
```

`skipped` counts entries already listed or not valid; `bogon_skipped` counts the private and LAN ranges among them, which the IP blacklist refuses.

**Supported file formats:**

- Plain text, one entry per line.
- Hosts files: the last field of a line is the entry.
- A domain written as a URL is reduced to its host name.
- Blank lines and lines beginning with `#` or `;` are ignored.

::: warning SSRF protection
Import URLs are validated. Hosts that resolve to loopback, private, link-local, multicast, or other special-purpose ranges are rejected with `403`, and the resolved IP is pinned to prevent DNS rebinding mid-download. The download is capped at 32 MB.
:::

---

## Geo import {#geo-import}

```
POST /api/blacklists/import-geo
```

```json
{ "countries": ["RU", "CN", "KP"] }
```

Each country's IPv4 blocks are fetched from ipdeny.com, or from `herrbischoff/country-ip-blocks` when ipdeny does not answer (from `GEOIP_URL` when it is set), and added to the IP blacklist under one source per country (`source_kind: "geo"`, `source: "RU"`). At most 50 countries per request.

---

## Sources {#sources}

Every list entry records the source that added it, and an entry keeps the source that added it first.

| `kind` | `source` | Recorded for |
|---|---|---|
| `url` | the URL (`label`: the list's name, when given) | an import from a URL, a Popular list, the auto-refresh of that URL |
| `manual` | empty | entries added one at a time |
| `geo` | the country code | a geo import |
| `paste` | empty | each inline import, one source per request |
| `restore` | empty | each configuration restore, one source per list |

### List the sources of a list

```
GET /api/ip-blacklist/sources
GET /api/domain-blacklist/sources
GET /api/ip-whitelist/sources
GET /api/domain-whitelist/sources
```

```json
{
  "status": "success",
  "data": [
    {
      "id": 4,
      "kind": "url",
      "source": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
      "label": "Firehol Level 1",
      "entries": 4521,
      "first_added": "2026-10-25 08:00:00",
      "last_added": "2026-10-25 08:02:00"
    },
    {
      "id": null,
      "kind": "unrecorded",
      "source": "",
      "label": "",
      "entries": 50772,
      "first_added": "2026-10-20 07:00:00",
      "last_added": "2026-10-24 09:00:00"
    }
  ],
  "meta": { "total": 2, "limit": 2, "offset": 0 }
}
```

The counts and dates are those of the entries. Most recently added first; the entries whose source was not recorded (`id: null`) last. A source with no entries left is not listed.

### Remove a source

```
DELETE /api/ip-blacklist/sources/{id}
DELETE /api/ip-blacklist/sources/unrecorded
```

Removes, in one transaction, the entries the source added (or every entry whose source was not recorded), then exports the lists so Squid and dnsmasq stop enforcing them. The same route exists under each of the four lists; an id that belongs to another list answers `404`.

```json
{ "status": "success", "message": "Removed 4521 entries", "data": { "removed": 4521 } }
```

### Export a list

```
GET /api/ip-blacklist/export
```

Every entry of the list, one per line, as `text/plain`, in the order added. The same route exists under each of the four lists.

---

## Enforcement {#enforcement}

```
GET /api/blacklists/enforcement
```

```json
{
  "status": "success",
  "data": {
    "dns_blocklist_limit": 1000000,
    "domain_blacklist_entries": 640929,
    "domain_blacklist_on_allowed": 3,
    "squid_domain_acl": { "names": 473936, "limit": 250000, "held": false, "written_at": 1792900000 },
    "squid_ip_blacklist": { "entries": 50772, "networks": 32215, "dropped": 0, "written_at": 1792900000 },
    "squid_ip_whitelist": null
  }
}
```

- `dns_blocklist_limit`: `SPM_DNS_BLOCKLIST_MAX_DOMAINS`.
- `domain_blacklist_on_allowed`: blacklisted domains whose enforced name (lower case, `*.` and a leading dot dropped) is on the domain whitelist, left out of what dnsmasq and Squid receive.
- `squid_domain_acl`: the proxy's record of Squid's own copy of the domain blacklist: the names after dropping `*.` and duplicates, `SPM_SQUID_DOMAIN_ACL_MAX`, and whether Squid holds them.
- `squid_ip_blacklist`, `squid_ip_whitelist`: the proxy's record of each IP list after merging overlapping and adjacent entries: the lines it had, the networks Squid loads, and the lines that were not an address or CIDR.

A record the proxy has not written (an older proxy, or one that has not started) is `null`.

---

## IP whitelist {#ip-whitelist}

Whitelisted destination IPs get past the direct-IP block rule and the final deny in Squid. Squid checks the IP and domain blacklists first, so a whitelisted address that is also blacklisted stays blocked. A change is exported at once.

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
      "added_date": "2026-03-01 12:00:00",
      "source_kind": "manual"
    }
  ],
  "meta": { "total": 1, "limit": 100, "offset": 0 }
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

### Import a pasted list {#allowed-import}

```
POST /api/ip-whitelist/import
POST /api/domain-whitelist/import
```

```json
{ "content": "192.168.1.50\n# a comment\n10.0.0.0/24" }
```

One entry per line, at most 1 MiB; blank lines and lines starting with `#` are ignored. Each line is checked as the single add checks it, and the new entries are recorded under one source of kind `paste`, so the paste can be removed as a whole ([Remove a source](#sources)). An entry already on the list keeps the source that added it first.

```json
{
  "status": "success",
  "data": {
    "added": 2,
    "skipped": 0,
    "refused": 1,
    "refusals": [{ "entry": ".x.example", "reason": "\".x.example\" is not an exact name: write x.example. An allowed name takes that same name off Blocked domains, however it is written there, and covers no name under it" }]
  }
}
```

`skipped` counts the lines already listed or repeated in the paste; `refusals` lists the first 20 refused lines with their reasons, `refused` counts them all.

### Delete entry

```
DELETE /api/ip-whitelist/{id}
```

---

## Domain whitelist {#domain-whitelist}

A blacklisted domain whose enforced name is on the whitelist is left out of what the backend exports, so dnsmasq resolves it normally and Squid does not refuse it: `example.com` here takes out `example.com`, `*.example.com` and `.example.com`, in any case. It covers no subdomain, so a leading dot and wildcards are refused. A change is exported at once.

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
      "description": "Essential: code hosting",
      "added_date": "2026-03-01 12:00:00",
      "source_kind": "manual"
    }
  ],
  "meta": { "total": 1, "limit": 100, "offset": 0 }
}
```

### Add entry

```
POST /api/domain-whitelist
```

```json
{
  "domain": "github.com",
  "description": "Essential: code hosting"
}
```

`domain` is stored in lower case. `.github.com` and `*.github.com` are refused with the name to write (`".github.com" is not an exact name: write github.com. ...`), since an allowed name covers no name under it. A pasted list goes to [`POST /api/domain-whitelist/import`](#allowed-import).

### Delete entry

```
DELETE /api/domain-whitelist/{id}
```

---

## Egress allowlist {#egress-allowlist}

The egress allowlist is the deny-by-default complement to the blacklists. It is consulted only when default-deny egress is enabled (the `egress_default_deny` setting, default `false`). While that setting is off (the default), behaviour is unchanged: clients may reach any destination not on a blacklist, and this allowlist has no effect. When it is on, the proxy denies all outbound egress from local clients except destinations on this allowlist; everything else is refused with a Squid 403.

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
      "added_date": "2026-03-01 12:00:00"
    }
  ],
  "meta": { "total": 1, "limit": 100, "offset": 0 }
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
