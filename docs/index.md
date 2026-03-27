---
layout: home

hero:
  name: "Secure Proxy Manager"
  text: "Containerized proxy management for homelabs and small networks"
  tagline: Squid proxy engine with FastAPI backend, React UI, and ICAP WAF — deployed in minutes with Docker Compose.
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
  - title: Traffic Filtering
    details: Domain and IP blacklisting with CIDR and wildcard support. One-click import of popular blocklists (Spamhaus, Firehol, Pi-hole, Phishing Army). Geo-based IP blocking.
  - title: IP Whitelist
    details: Whitelist trusted destination IPs to bypass the direct-IP block. Useful for LAN NAS, printers, and other devices accessed by IP address.
  - title: ICAP WAF
    details: Go-based ICAP server inspects all HTTP requests using 171 regex rules across 21 categories plus 7 behavioral heuristics (entropy, beaconing, PII, sharding, ghosting, morphing, sequence). Anomaly scoring with configurable threshold.
  - title: Real-time Logs
    details: Live log streaming via WebSocket with one-time token authentication. Filter by IP, domain, or status. Search, stats, and CSV-ready table.
  - title: Security Hardening
    details: Rate-limited authentication, SSRF protection on import URLs, CORS restriction, bcrypt password hashing, localhost-only backend API binding.
  - title: Self-hosted
    details: Runs entirely on your hardware via Docker Compose. No cloud dependency. SQLite database. Configurable via environment variables and web UI.
---
