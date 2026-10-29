# What is Secure Proxy Manager?

Secure Proxy Manager is a self-hosted forward proxy built on
[Squid](http://www.squid-cache.org/), with a web UI and a REST API for
managing what clients may reach, inspecting requests with a WAF and reading
the access log. It runs as a Docker Compose stack on your own host.

It is meant for homelab operators and small networks that want one auditable
egress point without a commercial appliance.

## Core capabilities

- **Forward proxy.** Clients send HTTP and HTTPS through Squid on port 3128.
  HTTPS is a `CONNECT` tunnel unless SSL bump is turned on.
- **Blocked domains.** Exact names. An entry written `*.example.com` or
  `.example.com` blocks `example.com` itself, not its subdomains. dnsmasq sinkholes every entry, and
  Squid also denies the names while the list is small enough.
- **Blocked IPs.** Single addresses or CIDR ranges of destinations. Private,
  loopback and other non-routable ranges are refused.
- **IP exceptions.** Destination addresses exempt from the direct-IP rule. The
  blocked lists are checked first, so this list does not override them.
- **Domain exceptions.** Exact names. Each takes the same name off the blocked
  domains, however it is written there (`name`, `*.name`, `.name`, any case),
  before they reach dnsmasq and Squid.
- **Default-deny allowlist.** Off by default. When Settings > Filtering > Only
  allowlisted destinations is on, clients reach only the entries on this list,
  LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) and IP exceptions.
- **WAF.** A Go ICAP service with 172 request rules in 21 categories, 5
  response rules in 2 categories and six behavioural heuristics (entropy,
  beaconing, personal data, destination sharding, protocol ghosting, sequence
  validation). Responses are checked for reflected XSS, secret leaks, personal
  data and executable content types.
- **Logs.** The access log with server-side filters and CSV export, and a live
  feed over WebSocket.
- **Imports.** From a URL, pasted text, a curated list under Popular lists, or
  a country's address blocks. Each entry records the source that added it.

## What it is not

- Not a firewall: it filters what clients send through port 3128, and nothing
  else. A client that is not configured to use the proxy is not filtered.
- Not a transparent proxy: there is no intercept port.
- Not a reverse proxy for inbound traffic.
- Not a multi-node service: it runs on one host (see
  [Architecture: limits](./architecture.md#limits)).

## Resources

The shipped `docker-compose.yml` sets these memory limits: `proxy` 512 MiB,
`waf` 256 MiB, `dns` 256 MiB, `backend` 128 MiB, `web` 128 MiB. Squid's disk
cache defaults to 2000 MB (Settings > Proxy engine > Disk cache). You need
Docker with the Compose v2 plugin (`docker compose`).

## Network ports

| Host port | Service | Notes |
|---|---|---|
| `80`, `8011` | `web` (HTTP) | Redirect to `https://<host>:8443`; `/health`, `/wpad.dat` and ACME challenge paths are answered directly |
| `443`, `8443` | `web` (HTTPS) | The UI and `/api/` |
| `3128` | `proxy` | Configure clients to use this |
| `127.0.0.1:5001` | `backend` | Localhost only, not reachable from the network |

The WAF (ICAP on `1344`, management and metrics on `8080`) and dnsmasq (`53`)
are on the internal Docker network and publish no port on the host.
