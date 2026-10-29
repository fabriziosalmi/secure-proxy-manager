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
| `preset` | the preset's id (`label`: `Common services: <name>`) | a preset added with [`POST /api/{list}/presets/{id}`](#presets), one source per list and preset |

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

## Presets {#presets}

Named groups of domains the backend keeps for two lists: the common services a
network usually needs on the domain whitelist (`github`, `google`,
`microsoft`, `ai-services`, `docker`, `cdn-js`, `cloudflare`), and the public
DNS-over-HTTPS resolvers on the domain blacklist (`doh`).

```
GET /api/domain-whitelist/presets
GET /api/domain-blacklist/presets
```

```json
{
  "status": "success",
  "data": [
    { "id": "docker", "name": "Docker", "domains": ["docker.com", "hub.docker.com", "registry.docker.io", "auth.docker.io", "production.cloudflare.docker.com"], "listed": ["hub.docker.com"] }
  ]
}
```

`listed` is the preset's domains the list already holds, whatever source added
them.

```
POST /api/domain-whitelist/presets/{id}
POST /api/domain-blacklist/presets/{id}
```

Adds, in one transaction, the domains of the preset the list does not hold yet,
under the preset's source (`kind` `preset`), and requests one export, which
reloads the DNS sinkhole as well. A domain already listed keeps the source that
added it. The answer is `{"preset", "name", "added": [domains], "already": n}`;
the audit log records one `add_preset_<list>` event with the same counts. An
unknown id is `404`; a preset that would take the domain blacklist past its
limit is `413`.

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

---

## Egress provider lists {#egress-providers}

Managed IPv4 and IPv6 CIDR destination lists for default-deny egress. Built-in
catalog providers (`kind: "catalog"`) are fetched from
`lord-alfred/ipranges` at the newest commit of `main` at each download (the
commit is returned in `last_commit`); custom URL
providers (`kind: "url"`) are fetched from operator-configured HTTP or HTTPS
CIDR feeds.

Enabled provider prefixes are stored in `egress_provider_entries` and exported
together with manual CIDR entries into `/config/dst_allow_ip.txt` as a
deduplicated union without altering the manual `dst_allowlist` table.

### List providers

```
GET /api/egress-providers
```

Returns all 13 catalog entries (`amazon`, `cloudflare`, `digitalocean`,
`facebook`, `github`, `google`, `linode`, `microsoft`, `oracle`, `telegram`,
`twitter`, `vultr`, `all`) in catalog order, followed by any custom URL
providers in creation order.

```json
{
  "status": "success",
  "data": [
    {
      "id": 0,
      "kind": "catalog",
      "name": "amazon",
      "url": "",
      "source": "ip-ranges.amazonaws.com",
      "enabled": false,
      "shared_network": true,
      "v4_count": 0,
      "v6_count": 0,
      "ipv4_covered": 0,
      "ipv6_64_covered": 0,
      "last_refresh": "",
      "last_commit": "",
      "last_error": "",
      "held": null
    },
    {
      "id": 1,
      "kind": "catalog",
      "name": "telegram",
      "url": "",
      "source": "core.telegram.org/resources/cidr.txt",
      "enabled": true,
      "shared_network": false,
      "v4_count": 7,
      "v6_count": 4,
      "ipv4_covered": 11008,
      "ipv6_64_covered": 4295229440,
      "last_refresh": "2026-10-26T22:05:12Z",
      "last_commit": "bbd1c91eab7e21b1e700049b2a115b9a55a10a18",
      "last_error": "",
      "held": null,
      "created": "2026-10-26 22:05:12"
    }
  ]
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `id` | number | Row ID in `egress_providers` (`0` for a catalog provider that has never been enabled or refreshed) |
| `kind` | `"catalog"` \| `"url"` | Built-in catalog provider or custom URL feed |
| `name` | string | Catalog name or custom URL label |
| `url` | string | Feed URL for `kind: "url"`, empty for catalog providers |
| `source` | string | Upstream origin description for catalog providers |
| `enabled` | boolean | Whether the provider's prefixes are included in `dst_allow_ip.txt` |
| `shared_network` | boolean | Whether third-party sites and workloads run on the provider's IP ranges (`confirm_shared: true` required to enable) |
| `v4_count` | number | Validated IPv4 CIDR prefixes stored for this provider |
| `v6_count` | number | Validated IPv6 CIDR prefixes stored for this provider |
| `ipv4_covered` | number | Total distinct IPv4 addresses covered after merging overlapping prefixes |
| `ipv6_64_covered` | number | Total distinct IPv6 `/64` blocks covered after merging overlapping prefixes |
| `last_refresh` | string | RFC 3339 UTC timestamp of the last successful refresh |
| `last_commit` | string | Upstream Git commit SHA for catalog providers, or SHA-256 hex digest of the body for URL providers |
| `last_error` | string | Error message from the most recent failed refresh (`""` when the last refresh succeeded) |
| `held` | object \| `null` | Candidate update held because covered addresses grew by more than 25% or a previously empty address family appeared from zero (`commit`, `v4_count`, `v6_count`, `ipv4_covered`, `ipv6_64_covered`, `growth_pct`, `reason`, `held_at`) |

### Enable or disable a provider

```
PUT /api/egress-providers/{name}
```

```json
{
  "enabled": true,
  "confirm_shared": true
}
```

- Enabling a provider with `shared_network: true` without `"confirm_shared": true`
  is refused with `400`.
- When a provider is enabled for the first time with `0` stored entries, the
  backend fetches and validates its feed immediately. If the initial fetch
  fails, the provider remains enabled and the `200` response includes
  `"refresh_error": "<reason>"` alongside `"data"`.
- Disabling (`"enabled": false`) keeps the stored prefixes for future re-use,
  excludes them from `/config/dst_allow_ip.txt`, and triggers an export.

### Add a custom URL provider

```
POST /api/egress-providers/url
```

```json
{
  "label": "partner-cidr-feed",
  "url": "https://feeds.example.com/allowlist.txt"
}
```

- `label` is 1 to 100 characters and must not collide with a catalog provider
  name (`400` otherwise) or an existing URL provider (`409`).
- `url` must be an `http` or `https` URL that does not resolve to a loopback,
  private, link-local, or other SSRF-disallowed address (`400` otherwise), and
  must not duplicate an existing URL (`409`).
- The feed is fetched and validated immediately (`502` if the initial fetch or
  validation fails).

### Delete a custom URL provider

```
DELETE /api/egress-providers/url/{id}
```

Deletes the custom URL provider and its stored prefixes in one transaction,
then exports `/config/dst_allow_ip.txt`. Answers `404` when no URL provider has
that ID.

### Refresh a provider now

```
POST /api/egress-providers/{name}/refresh
```

Fetches and validates the provider's feed immediately:

- `200` with `{"status": "success", "data": {...}, "held": false}` when the new
  list is applied (or unchanged at the same commit/hash).
- `200` with `{"status": "success", "data": {...}, "held": true}` when the
  candidate update is held for manual confirmation (`data.held` holds the
  candidate summary).
- `422` when the upstream fetch fails or any line in the feed violates the
  validation rules (invalid CIDR, IPv4 wider than `/8`, IPv6 wider than `/16`,
  non-public range, or more than 50,000 entries); the previous good entries stay
  untouched and `last_error` records the failure.

### Apply a held update

```
POST /api/egress-providers/{name}/apply-held
```

Promotes the held candidate (`held`) to the active prefix list for `{name}`,
clears `held` and `last_error`, writes an `egress_provider_held_applied` audit
row, exports `/config/dst_allow_ip.txt`, and returns the updated provider state.
Answers `400` when `{name}` has no held update.

### Audit actions

Provider operations write the following `action` values to `audit_log` with the
provider name as `target` and JSON `details`:

| Action | `details` fields |
|---|---|
| `egress_provider_enabled` | `kind`, `shared_network` (on `PUT /api/egress-providers/{name}`); `kind`, `url` (redacted, on `POST /api/egress-providers/url`) |
| `egress_provider_disabled` | `kind` (on `PUT /api/egress-providers/{name}`); `kind`, `url` (redacted), `deleted` (on `DELETE /api/egress-providers/url/{id}`) |
| `egress_provider_refreshed` | `commit`, `v4_before`, `v4_after`, `v6_before`, `v6_after`, `ipv4_covered_before`, `ipv4_covered_after` |
| `egress_provider_refresh_failed` | `kind`, `reason` |
| `egress_provider_held` | `commit`, `growth_pct`, `reason`, `v4_before`, `v4_after`, `v6_before`, `v6_after`, `ipv4_covered_before`, `ipv4_covered_after`, `ipv6_64_covered_before`, `ipv6_64_covered_after` |
| `egress_provider_held_applied` | `commit`, `growth_pct`, `v4_before`, `v4_after`, `v6_before`, `v6_after`, `ipv4_covered_before`, `ipv4_covered_after` |
