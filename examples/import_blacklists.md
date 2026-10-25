# Importing lists through the API

All imports go through `POST /api/blacklists/import` (and
`POST /api/blacklists/import-geo` for countries). The per-type endpoints
`POST /api/domain-blacklist/import` and `POST /api/ip-blacklist/import` are
retired and answer `410 Gone`.

The examples use the UI's HTTPS port. The certificate is self-signed unless you
mounted your own, hence `-k`; plain HTTP on port 8011 redirects and does not
reach the API.

```bash
SPM=https://localhost:8443
AUTH="Authorization: Basic $(printf '%s' 'admin:your_password' | base64)"
```

## Domains

### From a URL

```bash
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "url": "https://example.com/blacklist.txt", "name": "Example list"}'
```

`name` is optional; it labels the source on the Blocked domains tab. The URL's
host must resolve to a public address, and the download is limited to 32 MB.

A file such as:

```
# comment lines are ignored
0123movies.example
0.0.0.0 ads.example
https://tracker.example/path
*.malicious-ads.example
```

imports `0123movies.example`, `ads.example` (the last field of a hosts line),
`tracker.example` (a URL is reduced to its host) and `*.malicious-ads.example`,
which blocks `malicious-ads.example` itself, not its subdomains.

### Pasted content

```bash
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "domain", "content": "example.com\nbadsite.example\n# a comment"}'
```

## IP addresses and ranges

```bash
curl -k -X POST $SPM/api/blacklists/import \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"type": "ip", "content": "203.0.113.7\n198.51.100.0/24\n192.168.1.100"}'
```

Single addresses and CIDR ranges are accepted. Private, loopback, link-local,
CGNAT and other non-routable ranges are refused: `192.168.1.100` above is
skipped and counted in `bogon_skipped`.

## Response

For the IP example above, on an empty list:

```json
{
  "status": "success",
  "message": "Successfully imported 2 entries (1 skipped/invalid) ...",
  "data": { "added": 2, "skipped": 1, "bogon_skipped": 1 }
}
```

`skipped` counts entries already listed or not valid, including the
non-routable ranges that `bogon_skipped` counts; when `bogon_skipped` is not
zero, `message` adds a sentence saying how many private ranges were dropped.
Read the numbers from `data`, not from `message`.

## Formats

- One entry per line; for a hosts file, the last field of the line.
- Blank lines and lines starting with `#` or `;` are ignored.
- JSON arrays are not parsed: send one entry per line.
- Domains: letters, digits, hyphens, underscores and dots; an optional leading
  `*.` is accepted and dropped by the exporters.

## Countries

```bash
curl -k -X POST $SPM/api/blacklists/import-geo \
  -H "Content-Type: application/json" -H "$AUTH" \
  -d '{"countries": ["RU", "CN"]}'
```

## Notes

- An entry already on the list is skipped; a feed that repeats an entry adds it
  once.
- An invalid line is skipped and counted; it does not stop the import.
- After an import that added entries, the backend exports the lists, and the
  proxy and dnsmasq pick them up within a few seconds.
- An import that would take the domain blacklist past
  `SPM_DNS_BLOCKLIST_MAX_DOMAINS` (default 1,000,000) is refused whole with
  `413`.

More detail: [Blacklist and Whitelist API](../docs/api/blacklists.md#import).
