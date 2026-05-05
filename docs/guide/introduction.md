# What is Secure Proxy Manager?

Secure Proxy Manager is a self-hosted, containerised forward proxy built on top of [Squid](http://www.squid-cache.org/). It provides a web UI for managing traffic filtering rules, monitoring access logs in real time, and enforcing security policies on HTTP and HTTPS traffic.

It is intended for homelab operators and small networks that need a manageable, auditable forward proxy without a commercial appliance.

## Core capabilities

- **Forward proxy.** HTTP and HTTPS (with optional SSL bump) traffic filtering through Squid.
- **Blacklists.** Domain blocking with exact match or wildcard subdomain (`*.example.com`); IP blocking with single addresses or CIDR ranges.
- **IP whitelist.** Trusted destination IPs that bypass the direct-IP block rule.
- **Domain whitelist.** Domains excluded from the dnsmasq DNS sinkhole.
- **WAF.** A Go ICAP server that inspects request payloads with 175 regex rules across 23 categories and 7 behavioural heuristics (entropy, beaconing, PII, sharding, ghosting, morphing, sequence). Limited response inspection (reflected XSS, secret leak, PII) is also performed.
- **Real-time logs.** WebSocket-based live log stream with search, filters, and statistics.
- **Dashboard.** Traffic timeline, security score, blocked counts, top domains and clients.
- **Blocklist import.** Import from URL or inline content. One-click import of curated public lists (Firehol, Spamhaus, StevenBlack, URLhaus, Phishing Army, and others).

## What it is not

- Not a full NGFW, IDS, or IPS.
- Not a deep-packet-inspection appliance.
- Not designed for high-throughput enterprise edge deployments.

## Minimum requirements

| Resource | Minimum |
|---|---|
| CPU | 1 core |
| RAM | 1 GB |
| Disk | 5 GB |
| Docker | 20.10.0+ |
| Docker Compose | 2.0.0+ |

## Network ports

The `web` service exposes both HTTP and HTTPS on the host. The backend API is bound to `127.0.0.1` only and is reached through the `web` reverse proxy.

| Host port | Service | Notes |
|---|---|---|
| `80` | Web UI (HTTP) | Redirects to HTTPS; serves ACME challenges |
| `443` | Web UI (HTTPS) | Primary entry point |
| `8011` | Web UI (HTTP, alt) | Backwards compatibility |
| `8443` | Web UI (HTTPS, alt) | Backwards compatibility |
| `3128` | Squid proxy | Configure clients to use this |
| `127.0.0.1:5001` | Backend API | Localhost only — not reachable from the network |

The WAF (ICAP, port `1344`) and DNS (dnsmasq, port `53`) services run on an internal Docker network and are not exposed on the host.
