---
layout: home

hero:
  name: "Secure Proxy Manager"
  text: "Containerised proxy management for homelabs and small networks"
  tagline: A Squid forward proxy with a Go backend, React UI, and Go ICAP WAF — deployed in minutes with Docker Compose.
  image:
    src: /hero-icon.svg
    alt: Secure Proxy Manager
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/reference
    - theme: alt
      text: GitHub
      link: https://github.com/fabriziosalmi/secure-proxy-manager

features:
  - title: Traffic filtering
    details: Domain and IP blocking with CIDR and wildcard subdomain support. One-click import of curated public blocklists. Geo-based IP blocking by country code.
  - title: IP whitelist
    details: Whitelist trusted destination IPs to bypass the direct-IP block rule. Useful for LAN devices accessed by IP address.
  - title: ICAP WAF
    details: Go-based ICAP server inspects HTTP requests with 175 regex rules across 23 categories plus 7 behavioural heuristics. Anomaly scoring with a configurable block threshold.
  - title: Real-time logs
    details: Live log streaming over WebSocket with one-time token authentication. Filter, search, and aggregate access events.
  - title: Hardened by default
    details: HTTP Basic plus JWT authentication, login rate limiting, SSRF guard on import URLs, CORS allowlist, bcrypt password hashing, backend API bound to localhost only.
  - title: Self-hosted
    details: Runs entirely on your hardware via Docker Compose. SQLite database, no cloud dependency. Configurable via environment variables and the web UI.
---
