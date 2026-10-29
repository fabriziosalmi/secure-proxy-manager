---
layout: home

hero:
  name: "Secure Proxy Manager"
  text: "Self-hosted forward proxy with a WAF and a DNS sinkhole"
  tagline: Squid, a Go ICAP WAF, dnsmasq, a Go API and a React UI in one Docker Compose stack, for one controllable egress point on your own network.
  image:
    src: /hero-icon.svg
    alt: Secure Proxy Manager
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: Tested like an attacker
      link: /#tested-like-an-attacker
    - theme: alt
      text: API Reference
      link: /api/reference
    - theme: alt
      text: GitHub
      link: https://github.com/fabriziosalmi/secure-proxy-manager

features:
  - title: Egress control
    details: Blocked IPs and domains and their exceptions (single addresses, CIDR ranges, exact names), imports from a URL, pasted text, curated lists or a country's address blocks, and an optional default-deny allowlist.
  - title: WAF over ICAP
    details: 172 request rules in 21 categories, 5 response rules in 2, six behavioural heuristics and anomaly scoring, with runtime toggles per category. Fails closed by default.
  - title: DNS sinkhole
    details: "dnsmasq answers 0.0.0.0 and :: for every blocked domain. SafeSearch and YouTube restricted mode are DNS overrides you can switch on."
  - title: MCP server
    details: An optional Model Context Protocol server (spm-mcp on PyPI) exposes traffic queries as tools; the tools that change the proxy are off unless you enable them.
  - title: Logs and analytics
    details: Access logs with server-side filters and CSV export, a live feed over WebSocket, per-client views, and an audit log of every list change.
  - title: Signed images
    details: Release images for amd64 and arm64 on GHCR and Docker Hub, signed with cosign. The GHCR images carry an SBOM and build provenance.
---

## See it block

![Malicious requests blocked by the proxy + WAF, benign traffic allowed](/demo/adversarial-demo.svg)

Malicious requests get **403**'d at the proxy by the WAF; benign traffic passes.

## Tested like an attacker

`make adversarial` builds an isolated sandbox of the real images, attacks it
and tears it down. CI runs it on every pull request and push to `main`, and
daily; any failing plane fails the run:

- **Block matrix**: 28 malicious cases (19 request categories and the 2
  response categories) must be blocked and 11 benign cases must pass, through
  the real proxy and WAF.
- **API attacker**: 18 cases of missing, forged and tampered credentials, login
  SQL injection and a login burst against the backend.
- **Latency**: a k6 run through the proxy and the WAF must keep p95 under
  800 ms and errors under 5%.
- **Config matrix**: disabling a WAF category lets that attack through and
  re-enabling it blocks it again.
- **Resilience**: with the WAF stopped the proxy does not answer 200; after a
  restart it blocks again.

Details are in
[tests/adversarial/README.md](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/tests/adversarial/README.md).

## Manage it from an MCP client

```bash
SPM_URL=http://localhost:5001 SPM_USERNAME=admin SPM_PASSWORD=... uvx spm-mcp
```

Read-only by default; set `SPM_MCP_READONLY=false` to also register the tools
that block domains, toggle WAF categories, add egress entries and reload the
proxy.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

The installer installs Docker if it is missing, writes a `.env` with random
credentials, pulls the release images and starts the stack. Then point a client
at `<host>:3128` and open `https://<host>`. See
[Getting Started](/guide/getting-started).
