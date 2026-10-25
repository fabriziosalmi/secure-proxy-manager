# Blacklists and Whitelists

Secure Proxy Manager keeps four lists, each with its own role in the request path. The **Blacklists** page has a tab for each (Blocked IPs, Blocked domains, Allowed IPs, Allowed domains); the tab is in the address (`/blacklists?tab=blocked-domains`), so a link opens it.

| List | Enforced by | Effect |
|---|---|---|
| Domain blacklist | dnsmasq, and Squid while the list is small enough | dnsmasq answers `0.0.0.0` and `::` for every entry; Squid also refuses the name itself while the list has at most `SPM_SQUID_DOMAIN_ACL_MAX` names (default 250,000) |
| IP blacklist | Squid | Squid refuses requests to a matching destination IP or CIDR range |
| IP whitelist | Squid | Matching destinations get past the direct-IP rule and the final deny; the blacklists are checked first, so it does not override them |
| Domain whitelist | the export | A name on it takes the same name off the domain blacklist (written `name`, `*.name` or `.name` there) before dnsmasq and Squid receive it |

Each tab has an **Enforcement** section that says what enforces the list from recorded state: the proxy writes what it loaded (`/config/domain_acl_status.json` for the domains, `/config/ip_blacklist_acl_status.json` and `/config/ip_whitelist_acl_status.json` for the networks Squid loads after merging overlapping entries), and the page says "Not reported" when a record is missing.

## Domain blacklist

Blocks HTTP and HTTPS requests to matching destinations.

- A name blocks that exact host, not its subdomains: `malicious.example` blocks `malicious.example`, and `ads.malicious.example` stays reachable unless it is listed too.
- An entry written `*.ads.example.com` or `.ads.example.com` is accepted and blocks `ads.example.com` itself, in dnsmasq and in Squid alike: the exporter and the proxy both drop the `*.` and the leading dot, and compare names in lower case. It does not cover subdomains.

The list is limited to `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries; see [Size limit](#size-limit).

Manage via **Web UI → Blacklists → Blocked domains** or the [API](/api/blacklists#domain-blacklist).

## IP blacklist

Blocks requests to the matching destination IP.

- Single IP: `203.0.113.5`
- CIDR range: `198.51.100.0/24`

Private, loopback, link-local, CGNAT and other non-routable ranges are refused: blocking them would cut off the proxy's own clients. Before Squid loads the list, the proxy merges overlapping and adjacent entries into the fewest networks that cover the same addresses.

Manage via **Web UI → Blacklists → Blocked IPs** or the [API](/api/blacklists#ip-blacklist).

## IP whitelist

Whitelisted destination IPs get past the direct-IP block rule and the final deny. Use this for trusted LAN devices reached by IP (NAS, printers, IoT devices).

- Single IP: `192.168.1.50`
- CIDR range: `192.168.1.0/24`

::: tip
The IP whitelist applies to **destination** IPs. Squid checks the IP and domain blacklists before it, so an address on both the IP blacklist and the IP whitelist stays blocked.
:::

Manage via **Web UI → Blacklists → Allowed IPs** or the [API](/api/blacklists#ip-whitelist).

## Domain whitelist

A name on the domain whitelist is left out of the domain blacklist the backend exports, so neither dnsmasq nor Squid receives it. Use this for essential services (GitHub, Docker registries, package mirrors) before importing large blocklists that may include them. The match is on the name the blacklist entry enforces: `github.com` here takes out a blacklist entry `github.com`, `*.github.com` or `.github.com` (each blocks `github.com` itself), in any case, and not `api.github.com`. A leading dot and wildcards are refused here, because an allowed name covers no subdomain.

Manage via **Web UI → Blacklists → Allowed domains** or the [API](/api/blacklists#domain-whitelist).

## Where the entries came from

Every entry records the source that added it:

| Source | Recorded for |
|---|---|
| The URL, with the list's name for a Popular list | an import from a URL, a Popular list, the automatic refresh of that URL |
| Manual | an entry added on its own |
| Pasted list | each list pasted into the import form, one source per paste |
| GeoIP: CC | a country's address blocks |
| Restore | each configuration restore, one source per list |

An entry belongs to the source that added it first: importing a list that repeats an entry already present does not move it. The **Where the entries came from** section of each tab lists the sources with the entries each added and when, and **Remove batch** removes exactly those entries, after a confirmation that names how many go; the lists are then exported again, so Squid and dnsmasq stop enforcing them. Entries added before this release show "Source not recorded" and can be removed together the same way.

**Export** downloads the whole list, one entry per line.

## Destination allowlist (default-deny egress)

The blacklists above are deny-lists: clients may reach any destination that is not explicitly blocked. The destination allowlist inverts that for outbound egress. When enabled, the proxy denies all egress from local clients **except** destinations on the allowlist, and refuses everything else with a Squid `403`.

This is the deny-by-default complement to the domain and IP blacklists and the direct-IP block rule. Use it for a strict "allow-only-these-destinations" outbound policy: for example, to let an app behind the proxy reach only an approved CA/ACME server, package mirror, or internal API and nothing else.

::: warning
Default-deny egress is **off by default**. While it is off, behaviour is unchanged: clients reach any destination that is not blacklisted. Turning it on with an empty allowlist blocks all outbound egress from local clients.
:::

### Enable default-deny egress

Toggle **Default-deny egress** on the **Settings** page (next to SSL inspection), or set it through the bulk settings API:

```bash
curl -X POST https://localhost:8443/api/settings \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"egress_default_deny": true}'
```

The setting is `egress_default_deny` and defaults to `false`.

### Manage allowed destinations

Add destinations on the **Egress Allowlist** page (add, delete, search, paginate), or via the API. Each entry is one of:

- IP or CIDR: `203.0.113.10`, `198.51.100.0/24`, matched on the destination IP (a Squid `dst` ACL, so a name that resolves into the network matches too).
- Domain: `acme-v02.api.letsencrypt.org`, matched on the destination domain (a Squid `dstdomain` ACL). An exact name allows that host only: `example.com` does not cover `www.example.com`. A leading dot, `.example.com`, allows the domain and every name under it. `*.example.com` is refused, because `dstdomain` would read it as a literal name that matches nothing.

The type is classified automatically on add: a value that parses as an IP or CIDR is stored as `cidr`, otherwise it is treated as a `domain`. A local client is allowed if the destination matches the IP allowlist **or** the domain allowlist. The deny comes after the rules that allow LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and the addresses on Allowed IPs, so those stay reachable: with default deny on and an empty allowlist, clients reach only those.

```bash
# Add a destination (auto-classified as cidr or domain)
curl -X POST https://localhost:8443/api/egress-allowlist \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"entry": "acme-v02.api.letsencrypt.org", "description": "ACME"}'

# List entries
curl https://localhost:8443/api/egress-allowlist -H "$AUTH"

# Delete one entry by ID
curl -X DELETE https://localhost:8443/api/egress-allowlist/42 -H "$AUTH"
```

`POST /api/egress-allowlist/bulk-delete` removes entries by a list of IDs, and `DELETE /api/egress-allowlist/clear-all` removes them all. The `egress_default_deny` toggle is set through the bulk settings endpoint, not this group.

::: tip
Whitelists and blacklists still apply when default-deny egress is on. A destination must be on the allowlist **and** must not be blacklisted to be reachable.
:::

## Importing blocklists

### Curated public lists (one click)

In the web UI, open **Blacklists → Popular lists** (on the Blocked IPs and Blocked domains tabs) to import any of the following. The entries are recorded under the list's URL and name, so the list can be removed as a whole later.

**IP lists.**

- Firehol Level 1
- Spamhaus DROP and EDROP
- Emerging Threats (compromised hosts and C2)
- CINS Army
- Stamparm Ipsum (level 3+)
- Blocklist.de (last 48 hours)

**Domain lists.**

- StevenBlack Unified hosts
- URLhaus malware domains (abuse.ch, through the [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) mirror: abuse.ch requires an Auth-Key for direct downloads)
- Phishing Army
- OISD Big
- HaGeZi Multi Pro (the listed names; subdomains are not covered)
- DanPollock hosts

### Size limit

The domain blacklist holds at most `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries
(default 1,000,000). dnsmasq keeps every blocked name in memory: measured at
about 195 MiB per million domains, unchanged across reloads, against the dns
container's 256 MiB limit. An import that would exceed the limit is refused
whole, with the reason; the auto-refresh stops adding at the limit and logs it.
To hold more, raise `SPM_DNS_BLOCKLIST_MAX_DOMAINS` on the backend and the dns
service's memory limit together, roughly 200 MiB per additional million.

The aggregated `fabriziosalmi/blacklists` list (5.5 million domains on
2026-10-24) is not offered as a one-click import for this reason: at the
default limits it got dnsmasq killed for lack of memory, and without DNS the
proxy resolves nothing.

The exact list, URLs, and descriptions are defined in `ui/src/components/blacklists/popularLists.ts` and may evolve between releases. The page shows the limit, and says when the list is full.

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

An optional `"name"` labels the source, as the Popular lists do. The retired per-type endpoints `POST /api/ip-blacklist/import` and `POST /api/domain-blacklist/import` answer `410 Gone` naming this one.

### Import inline content

```bash
curl -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "content": "badsite.example\n*.ads.example\nmalicious.example"}'
```

### Supported formats

- Plain text: one entry per line.
- Hosts files: the last field of a line is the entry (`0.0.0.0 ads.example` imports `ads.example`).
- A domain written as a URL is reduced to its host name.
- Blank lines and lines beginning with `#` or `;` are ignored; an entry already listed, or not valid, is skipped and counted.

### Geo-based IP blocking

```bash
curl -X POST https://localhost:8443/api/blacklists/import-geo \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"countries": ["RU", "CN"]}'
```

Each country's IPv4 blocks are fetched from ipdeny.com, or from `herrbischoff/country-ip-blocks` when ipdeny does not answer (or from `GEOIP_URL` when it is set), and added to the IP blacklist under one source per country.

## Automatic refresh

A background worker re-imports a fixed pair of public lists when auto-refresh is enabled in **Settings → Filtering → Refresh the built-in feeds**:

- `auto_refresh_enabled`: `true` to enable.
- `auto_refresh_hours`: re-fetch interval in hours (default `24`).

The defaults imported on each cycle are:

- IP: Firehol Level 1, Stamparm Ipsum (level 1).
- Domain: StevenBlack Unified hosts, URLhaus (malware-filter mirror).

To schedule additional custom feeds, run a host cron job that calls the import endpoint:

```bash
0 3 * * * curl -s -X POST https://localhost:8443/api/blacklists/import \
  -H "Content-Type: application/json" \
  -u USER:PASS \
  -d '{"type": "domain", "url": "https://big.oisd.nl/domainswild"}'
```
