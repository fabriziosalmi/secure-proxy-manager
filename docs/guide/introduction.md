# What is Secure Proxy Manager?

Secure Proxy Manager is a self-hosted, containerized web proxy management system built on top of [Squid](http://www.squid-cache.org/). It provides a modern web UI for managing traffic filtering rules, monitoring access logs in real time, and enforcing security policies on HTTP/HTTPS traffic.

It is designed for homelab operators, homelabbers, and small businesses who need a manageable, auditable forward proxy without a commercial solution.

## Core capabilities

- **Forward proxy** — HTTP and HTTPS (with optional SSL bump) traffic filtering via Squid
- **Blacklists** — domain and IP blocking with wildcard, CIDR, and regex support
- **IP whitelist** — trusted destination IPs that bypass the direct-IP block rule
- **WAF** — Python ICAP server that inspects request payloads for common attack patterns
- **Real-time logs** — WebSocket-based live log stream with search and stats
- **Dashboard** — 24h traffic chart, security score, blocked count, recent sessions
- **Blocklist import** — URL or inline import; one-click popular list import (Spamhaus, Firehol, Pi-hole, Phishing Army)
- **PDF report** — analytics summary downloadable from the dashboard

## What it is not

- Not a full NGFW or IDS/IPS
- Not a DPI appliance
- Not designed for high-throughput enterprise edge deployments (10Gbps+)
- WAF response inspection (`RESPMOD`) is currently a stub — only request inspection is active

## Minimum requirements

| Resource | Minimum |
|---|---|
| CPU | 1 core |
| RAM | 1 GB |
| Disk | 5 GB |
| Docker | 20.10.0+ |
| Docker Compose | 2.0.0+ |

## Network ports

| Port | Service | Notes |
|---|---|---|
| `8011` | Web UI | HTTP, served by Flask proxy |
| `3128` | Squid proxy | Configure clients to use this |
| `5001` | Backend API | Bound to `127.0.0.1` only by default |
