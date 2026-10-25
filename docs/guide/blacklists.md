# Blacklists and Whitelists

Secure Proxy Manager keeps four lists, each with its own role in the request
path. The **Blacklists** page has a tab for each (Blocked IPs, Blocked domains,
Allowed IPs, Allowed domains); the tab is in the address
(`/blacklists?tab=blocked-domains`), so a link opens it. The fifth list, the
egress allowlist, has its own page.

| List | Enforced by | Effect |
|---|---|---|
| Blocked domains | dnsmasq, and Squid while the list is small enough | dnsmasq answers `0.0.0.0` and `::` for every entry; Squid also refuses the name itself while the list has at most `SPM_SQUID_DOMAIN_ACL_MAX` names (default 250,000) |
| Blocked IPs | Squid | Requests to a matching destination address or range are refused |
| Allowed IPs | Squid | Matching destinations get past the direct-IP rule and the final deny; the blocked lists are checked first, so it does not override them |
| Allowed domains | the export | A name on it takes the same name off the blocked domains (written `name`, `*.name` or `.name` there, in any case) before dnsmasq and Squid receive them |

Each tab has an **Enforcement** section that reports what the proxy recorded
when it loaded the list (`/config/domain_acl_status.json` for the domains,
`/config/ip_blacklist_acl_status.json` and `/config/ip_whitelist_acl_status.json`
for the networks Squid loads after merging overlapping entries). It says "Not
reported" when a record is missing.

The examples below use the API through the UI's address. The certificate is
self-signed unless you mounted your own, hence `-k`:

```bash
SPM=https://localhost:8443
AUTH="Authorization: Basic $(printf '%s' 'admin:your_password' | base64)"
```

## Blocked domains

- A name blocks that exact host, not its subdomains: `malicious.example` blocks
  `malicious.example`, and `ads.malicious.example` stays reachable unless it is
  listed too.
- An entry written `*.ads.example.com` or `.ads.example.com` is accepted and
  blocks `ads.example.com` itself, in dnsmasq and in Squid alike: both drop the
  `*.` and the leading dot and compare names in lower case. It does not cover
  subdomains.
- A URL is reduced to its host name. An entry added on its own is stored in
  lower case; an import keeps the feed's case, which is enforced in lower
  case all the same.

The list is limited to `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries; see
[Size limit](#size-limit). Manage it on **Blacklists > Blocked domains** or
through the [API](/api/blacklists#domain-blacklist).

## Blocked IPs

Destination addresses and ranges:

- Single address: `203.0.113.5`
- CIDR range: `198.51.100.0/24`

Private, loopback, link-local, CGNAT (`100.64.0.0/10`), multicast and
unspecified ranges are refused. Before Squid loads the list, the proxy merges
overlapping and adjacent entries into the fewest networks that cover the same
addresses.

Manage it on **Blacklists > Blocked IPs** or through the
[API](/api/blacklists#ip-blacklist).

## Allowed IPs

Allowed destination addresses get past the direct-IP block rule and the final
deny. Use it for devices reached by address (NAS, printers). LAN destinations
in `10.0.0.0/8` and `192.168.0.0/16` are already allowed.

- Single address: `192.168.1.50`
- CIDR range: `172.20.0.0/16`

::: tip
Allowed IPs are **destinations**, not clients. Squid checks the blocked lists
before it, so an address on both Blocked IPs and Allowed IPs stays blocked. To
admit an extra client, use `GUI_IP_WHITELIST` in `.env`.
:::

Manage it on **Blacklists > Allowed IPs** or through the
[API](/api/blacklists#ip-whitelist); a pasted list goes to
`POST /api/ip-whitelist/import` and is recorded as one source.

## Allowed domains

A name on this list is left out of the blocked domains the backend exports, so
neither dnsmasq nor Squid receives it. Use it for essential services (code
hosting, registries, package mirrors) before importing large lists that may
include them. The match is on the name a blocked entry enforces: `github.com`
here takes out a blocked entry written `github.com`, `*.github.com` or
`.github.com`, in any case (each of them blocks `github.com` itself), and not
`api.github.com`. An allowed name covers no name under it, so a leading dot or
`*.` is refused with the name to write instead, and other wildcards and
regular expressions are refused too. Names are stored in lower case.

Manage it on **Blacklists > Allowed domains** or through the
[API](/api/blacklists#domain-whitelist); a pasted list goes to
`POST /api/domain-whitelist/import` and is recorded as one source.

## Where the entries came from

Every entry of the four lists records the source that added it:

| Source | Recorded for |
|---|---|
| The URL, with the list's name for a Popular list | an import from a URL, a Popular list, the automatic refresh of that URL |
| Manual | an entry added on its own |
| Pasted list | each list pasted into the add form, one source per paste, on all four lists |
| GeoIP: CC | a country's address blocks |
| Restore | each configuration restore, one source per list |

An entry belongs to the source that added it first: importing a list that
repeats an entry already present does not move it. The **Where the entries
came from** section of each tab lists the sources with the number of entries
each added and when, and **Remove batch** removes exactly those entries after a
confirmation that says how many go; the lists are then exported again, so Squid
and dnsmasq stop enforcing them. Entries added before sources were recorded
show "Source not recorded" and can be removed together the same way.

**Export** downloads the whole list, one entry per line.

## Destination allowlist (default-deny egress)

The lists above are deny-lists: clients reach any destination that is not
blocked. The egress allowlist inverts that. When default-deny egress is on, a
local client reaches only the destinations on the allowlist, LAN destinations
(`10.0.0.0/8`, `192.168.0.0/16`) and Allowed IPs; anything else gets a Squid
`403`.

Use it for a strict outbound policy, for example to let a device behind the
proxy reach only an ACME server, a package mirror and an internal API.

::: warning
Default-deny egress is **off by default**. Turning it on with an empty
allowlist leaves clients only LAN destinations and Allowed IPs; the Settings
page refuses to save it in that state, the API does not.
:::

### Enable default-deny egress

Turn on **Settings > Filtering > Only allowlisted destinations**. Through the
API, save the setting and then reload the proxy, as the Settings page does:

```bash
curl -k -X POST $SPM/api/settings \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"egress_default_deny": "true"}'
curl -k -X POST $SPM/api/maintenance/reload-config -H "$AUTH"
```

Setting values are strings. `PUT /api/settings/egress_default_deny` stores the
value but does not write the file the proxy reads (`/config/egress_default_deny`);
use `POST /api/settings`.

### Manage allowed destinations

Add destinations on the **Egress allowlist** page (add, delete, search, 50 a
page) or through the API. Each entry is one of:

- An address or CIDR: `203.0.113.10`, `198.51.100.0/24`, matched on the
  destination address (a Squid `dst` ACL, so a name that resolves into the
  range matches too).
- A domain: `acme-v02.api.letsencrypt.org`, matched on the destination name (a
  Squid `dstdomain` ACL). An exact name allows that host only: `example.com`
  does not cover `www.example.com`. A leading dot, `.example.com`, allows the
  domain and every name under it. `*.example.com` is refused, because
  `dstdomain` would read it as a literal name that matches nothing. A domain
  must contain a dot.

The type is set on add: a value that parses as an address or CIDR is stored as
`cidr`, anything else as `domain`. An entry is reachable if it matches the
address list **or** the domain list.

```bash
# Add a destination
curl -k -X POST $SPM/api/egress-allowlist \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"entry": "acme-v02.api.letsencrypt.org", "description": "ACME"}'

# List entries
curl -k $SPM/api/egress-allowlist -H "$AUTH"

# Delete one entry by ID
curl -k -X DELETE $SPM/api/egress-allowlist/42 -H "$AUTH"
```

`POST /api/egress-allowlist/bulk-delete` removes entries by a list of IDs, and
`DELETE /api/egress-allowlist/clear-all` removes them all.

::: tip
The blocked lists still apply when default-deny egress is on: they are
checked first, so a destination must be on the allowlist **and** not blocked.
:::

## Importing lists

### Popular lists

On the Blocked IPs and Blocked domains tabs, **Popular lists** imports any of
these with one click. The entries are recorded under the list's URL and name,
so the list can be removed as a whole later.

**IP lists:** Firehol Level 1, Spamhaus DROP, Spamhaus EDROP, Emerging Threats,
CINS Army, Stamparm Ipsum (level 3 and above), Blocklist.de All.

**Domain lists:** StevenBlack Unified, URLhaus Malware (through the
[malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) mirror),
Phishing Army, OISD Big, HaGeZi Multi Pro (the listed names; subdomains are not
covered), DanPollock Hosts.

The names, URLs and descriptions are in
`ui/src/components/blacklists/popularLists.ts`.

### Size limit

The domain blacklist holds at most `SPM_DNS_BLOCKLIST_MAX_DOMAINS` entries
(default 1,000,000). dnsmasq keeps every blocked name in memory. Measured on
2026-10-25 with the dns image of this repository and the shipped limits
(256 MiB, 0.5 CPU): 1,000,000 names of 31 characters (2,000,000 hosts lines,
`0.0.0.0` and `::`) took dnsmasq to 226 MiB resident, unchanged after two
reloads (`SIGHUP`). Longer names take more.

An add or an import that would go past the limit is refused, the import whole,
with the reason; the automatic refresh stops adding at the limit and logs it.
To hold more, raise `SPM_DNS_BLOCKLIST_MAX_DOMAINS` on the backend and the
`dns` service's memory limit together. The Blocked domains tab shows the limit
and says when the list is full.

### Import from a URL

```bash
# Domains
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "url": "https://example.com/domains.txt"}'

# IPs
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "ip", "url": "https://example.com/ips.txt"}'
```

An optional `"name"` labels the source, as the Popular lists do. The download
is limited to 32 MB, and a URL whose host resolves to a private or internal
address is refused. The retired per-type endpoints
`POST /api/ip-blacklist/import` and `POST /api/domain-blacklist/import` answer
`410 Gone`.

### Import pasted content

```bash
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "content": "badsite.example\n*.ads.example\nmalicious.example"}'
```

### Supported formats

- One entry per line.
- Hosts files: the last field of a line is the entry (`0.0.0.0 ads.example`
  imports `ads.example`).
- A domain written as a URL is reduced to its host name.
- Blank lines and lines starting with `#` or `;` are ignored. An entry already
  listed, or not valid, is skipped and counted; for IPs, private and other
  non-routable ranges are skipped and counted separately.

### Country blocks

```bash
curl -k -X POST $SPM/api/blacklists/import-geo \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"countries": ["RU", "CN"]}'
```

Each country's IPv4 blocks are fetched from ipdeny.com, or from
`herrbischoff/country-ip-blocks` on GitHub when ipdeny does not answer, and
added to Blocked IPs under one source per country. At most 50 countries per
request. When the backend has `GEOIP_URL` set, `<GEOIP_URL>?cc=<code>` is
fetched instead of both.

## Automatic refresh

With **Settings > Filtering > Refresh the built-in feeds** on, a background
worker re-imports four fixed lists every `auto_refresh_hours` hours (default
24, from 1 to 168):

- IP: Firehol Level 1, Stamparm Ipsum (level 1).
- Domain: StevenBlack Unified hosts, URLhaus (malware-filter mirror).

The settings are `auto_refresh_enabled` and `auto_refresh_hours`. To refresh
other feeds on a schedule, call the import endpoint from cron on the host:

```bash
0 3 * * * curl -sk -X POST https://localhost:8443/api/blacklists/import -u admin:your_password -H "Content-Type: application/json" -d '{"type": "domain", "url": "https://big.oisd.nl/domainswild"}'
```
