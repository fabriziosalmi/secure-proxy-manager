# Blacklist and Whitelist API

Base URLs:

- Through the `web` service (recommended): `https://localhost:8443/api`
- Directly to the backend, from the host only: `http://127.0.0.1:5001/api`

All endpoints require authentication (Basic or JWT). Successful responses are
`{"status": "success", ...}`; errors are `{"status": "error", "detail": "..."}`.

The UI calls the four lists Blocked IPs (`ip-blacklist`), Blocked domains
(`domain-blacklist`), Allowed IPs (`ip-whitelist`) and Allowed domains
(`domain-whitelist`). Every change to a list requests an export of the files
Squid and dnsmasq read, and writes an audit log row.

---

## Common operations

### List entries

```
GET /api/ip-blacklist?limit=50&offset=0&search=203.0
```

`limit` is 1 to 1000 (default 100); `search` matches the entry and its
description. Newest first. The same parameters work on every list, including
the egress allowlist.

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

`added_date` is UTC. `source_kind` is `url`, `manual`, `geo`, `paste` or
`restore` (see [Sources](#sources)); it, `source` and `source_label` are
`null` for an entry added before sources were recorded. The four lists carry
these fields; the egress allowlist does not. Read the count from
`meta.total`: the top-level `total`, `limit` and `offset` beside it are
deprecated.

### Delete one entry

```
DELETE /api/ip-blacklist/{id}
```

`404` when no entry has that ID. The same route exists on every list.

### Bulk delete and clear (blocked lists and egress allowlist)

```
POST /api/ip-blacklist/bulk-delete
```

```json
{ "ids": [1, 2, 3] }
```

At least one ID. The answer is `{"status": "success", "data": {"deleted": 3}}`.

```
DELETE /api/ip-blacklist/clear-all
```

Deletes every entry and answers `Cleared N entries`. Both routes exist on
`ip-blacklist`, `domain-blacklist` and `egress-allowlist`; the two allowed
lists have neither.

---

## IP blacklist {#ip-blacklist}

```
POST /api/ip-blacklist
```

```json
{
  "ip": "203.0.113.0/24",
  "description": "optional description"
}
```

`ip` is a single address or a CIDR range (at most 50 characters); wildcards are
not supported. Private, loopback, link-local, CGNAT, multicast and unspecified
ranges are refused with `400`, and so is an entry already on the list.
`description` is at most 500 characters on every list.

A refusal's `detail` names the value and the list in the page's words:
`"300.1.1.1" is not an IP address or network`, `"203.0.113.9" is already on
Blocked IPs`. The domain lists answer the same way (`"..." is not a domain
name: labels of letters, digits and hyphens separated by dots`,
`"..." is already on Blocked domains`).

### Import (per-type, retired)

```
POST /api/ip-blacklist/import
```

Answers `410 Gone`: use `POST /api/blacklists/import` with `type: "ip"`.

---

## Domain blacklist {#domain-blacklist}

```
POST /api/domain-blacklist
```

```json
{
  "domain": "ads.example.com",
  "description": "optional description"
}
```

`domain` is an exact name, lower-cased on add. A leading `*.` or `.` is
accepted, but an entry blocks one exact name either way: Squid's copy of the
list and the dnsmasq export both drop the prefix and compare in lower case, so
`*.example.com` and `.example.com` block `example.com` itself, not its
subdomains. A URL is
reduced to its host name (a port is dropped). Anything else is refused with
`400`: only letters, digits, hyphens, underscores and dots, labels of 1 to 63
characters, at most 253 in all. Whitespace, tabs, newlines and colons are
refused because entries are written one per line into the proxy and DNS files.
While the list holds `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries (default
1,000,000) a new one is refused with `413`.

### Import (per-type, retired)

```
POST /api/domain-blacklist/import
```

Answers `410 Gone`: use `POST /api/blacklists/import` with `type: "domain"`.

---

## Unified import {#import}

```
POST /api/blacklists/import
```

**From a URL:**

```json
{
  "type": "domain",
  "url": "https://example.com/domains.txt",
  "name": "Example list"
}
```

The entries are recorded under the URL as their source; importing the same URL
again adds to that source. The optional `name` (at most 100 characters) labels
it, as the Popular lists in the UI do.

**Pasted content:**

```json
{
  "type": "ip",
  "content": "192.0.2.1\n198.51.100.0/24\n203.0.113.5"
}
```

`type` must be `"domain"` or `"ip"`, and one of `url` and `content` is
required. Pasted content is recorded as a new pasted-list source each time. An
import that would take the domain blacklist past
`SPM_DNS_BLOCKLIST_MAX_DOMAINS` is refused whole with `413`.

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

`skipped` counts entries already listed or not valid; `bogon_skipped` counts
the private and other non-routable ranges among them, which the IP blacklist
refuses.

**Formats:**

- One entry per line.
- Hosts files: the last field of a line is the entry.
- A domain written as a URL is reduced to its host name.
- Blank lines and lines starting with `#` or `;` are ignored.

::: warning SSRF protection
Before a URL is fetched its host is resolved; when any address is private,
loopback, link-local, multicast, unspecified, in `0.0.0.0/8` or in CGNAT, the
import is refused with `403`. A URL that is not `http` or `https`, or a host
that does not resolve, is refused with `400`. The client checks the addresses
again when it connects and on each of at most five redirects. The download is
limited to 32 MB; three attempts are made before it fails with `400`.
:::

---

## Geo import {#geo-import}

```
POST /api/blacklists/import-geo
```

```json
{ "countries": ["RU", "CN", "KP"] }
```

One to 50 two-letter country codes. Each country's IPv4 blocks are fetched
from `https://www.ipdeny.com/ipblocks/data/countries/<cc>.zone`, or from
`herrbischoff/country-ip-blocks` on GitHub when ipdeny does not answer, and
added to the IP blacklist under one source per country (`source_kind: "geo"`,
`source: "RU"`). Private and other non-routable ranges in a feed are skipped.
When the backend has `GEOIP_URL` set, `<GEOIP_URL>?cc=<cc>` is fetched
instead of both.

```json
{
  "status": "success",
  "message": "Imported 9184 IP blocks for 2 of 2 countries",
  "data": { "imported": 9184, "countries_imported": 2, "countries_requested": 2 }
}
```

When some countries fail, `status` is `"partial"` and `data.errors` names them;
when every country fails and nothing was imported, the answer is `502`.

---

## Sources {#sources}

Every entry of the four lists records the source that added it, and keeps the
source that added it first.

| `kind` | `source` | Recorded for |
|---|---|---|
| `url` | the URL (`label`: the list's name, when given) | an import from a URL, a Popular list, the automatic refresh of that URL |
| `manual` | empty | entries added one at a time |
| `geo` | the country code | a geo import |
| `paste` | empty | each pasted import, one source per request |
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

The counts and dates are those of the entries. Most recently added first; the
entries whose source was not recorded (`id: null`) last. A source with no
entries left is not listed.

### Remove a source

```
DELETE /api/ip-blacklist/sources/{id}
DELETE /api/ip-blacklist/sources/unrecorded
```

Removes, in one transaction, the entries the source added (or every entry
whose source was not recorded), then requests an export so Squid and dnsmasq
stop enforcing them. The same route exists under each of the four lists; an
ID that belongs to another list answers `404`.

```json
{ "status": "success", "message": "Removed 4521 entries", "data": { "removed": 4521 } }
```

### Export a list

```
GET /api/ip-blacklist/export
```

Every entry of the list, one per line, as `text/plain`, in the order added,
served as the attachment `<list>-<date>.txt`. The same route exists under each
of the four lists.

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
- `domain_blacklist_on_allowed`: blocked domains whose enforced name (lower
  case, `*.` and a leading dot dropped) is on the domain whitelist, left out
  of what dnsmasq and Squid receive.
- `squid_domain_acl`: the proxy's record of Squid's own copy of the domain
  blacklist: the names after dropping prefixes and duplicates,
  `SPM_SQUID_DOMAIN_ACL_MAX`, and whether Squid holds them.
- `squid_ip_blacklist`, `squid_ip_whitelist`: the proxy's record of each IP
  list after merging overlapping and adjacent entries: the lines it had, the
  networks Squid loads, and the lines that were not an address or CIDR.

A record the proxy has not written (an older proxy, or one that has not
started) is `null`.

---

## IP whitelist {#ip-whitelist}

Allowed destination addresses get past the direct-IP block rule and the final
deny in Squid. Squid checks the blocked lists first, so an allowed address
that is also blocked stays blocked.

```
POST /api/ip-whitelist
```

```json
{
  "ip": "192.168.1.0/24",
  "description": "LAN subnet"
}
```

Any valid address or CIDR range is accepted, private ones included.

### Import a pasted list {#allowed-import}

```
POST /api/ip-whitelist/import
POST /api/domain-whitelist/import
```

```json
{ "content": "192.168.1.50\n# a comment\n10.0.0.0/24" }
```

`content` is required, at most 1 MiB, one entry per line; blank lines and
lines starting with `#` are ignored. Each line is checked as the single add
checks it, and the new entries are recorded under one source of kind `paste`,
so the paste can be removed as a whole ([Remove a source](#sources)). An entry
already on the list keeps the source that added it first.

```json
{
  "status": "success",
  "message": "Added 2 entries to Allowed IPs (0 already listed, 1 refused)",
  "data": {
    "added": 2,
    "skipped": 0,
    "refused": 1,
    "refusals": [{ "entry": "300.1.1.1", "reason": "\"300.1.1.1\" is not an IP address or network" }]
  }
}
```

`skipped` counts the lines already listed or repeated in the paste; `refused`
counts the refused lines and `refusals` lists the first 20 with their reasons.
`POST /api/blacklists/import` feeds only the two blocked lists.

---

## Domain whitelist {#domain-whitelist}

A blocked domain whose enforced name is on the whitelist is left out of what
the backend exports, so dnsmasq resolves it normally and Squid does not refuse
it: `example.com` here takes out a blocked `example.com`, `*.example.com` and
`.example.com`, in any case. It covers no name under it.

```
POST /api/domain-whitelist
```

```json
{
  "domain": "github.com",
  "description": "Essential: code hosting"
}
```

The name is stored in lower case. A leading `.` or `*.` is refused with `400`
and the name to write (`".github.com" is not an exact name: write github.com.
...`), because an allowed name covers no name under it. Other wildcards and
patterns (`*`, `?`, `[`, `(`, `|`, `\`) and any name that is not a valid host
name are refused with `400` too. A pasted list goes to
[`POST /api/domain-whitelist/import`](#allowed-import).

---

## Egress allowlist {#egress-allowlist}

The egress allowlist is consulted only while default-deny egress is on (the
`egress_default_deny` setting, default `"false"`, changed through
`POST /api/settings` and applied with `POST /api/maintenance/reload-config`;
see [Settings](./settings.md#default-deny-egress)). While it is on, local
clients reach only these destinations, LAN destinations (`10.0.0.0/8`,
`192.168.0.0/16`) and Allowed IPs; everything else is refused with a Squid
403.

Each entry is an address or CIDR (matched by a Squid `dst` ACL) or a domain
(matched by a Squid `dstdomain` ACL). The type is set on add: a value that
parses as an address or CIDR is stored as `cidr`, anything else as `domain`.

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

`entry` (at most 253 characters) is lower-cased. A domain must contain a dot.
A domain entry matches that exact name; `.example.com` covers the domain and
every name under it.

**Success:**

```json
{
  "status": "success",
  "message": "Entry added to egress allowlist"
}
```

**Refusals (`400`):**

| `detail` | Cause |
|---|---|
| `invalid entry` | Empty, or contains a space |
| `entry must be an IP, CIDR, or domain` | Not an address or CIDR, and not a valid domain with a dot |
| `write .example.com, with a leading dot, ...` | A domain written `*.example.com` |
| `entry already in allowlist` | A duplicate |
