---
layout: home

hero:
  name: "Secure Proxy Manager"
  text: "Self-hosted Secure Web Gateway"
  tagline: One controllable egress point for your network — Squid forward proxy + a real WAF (ICAP) + DNS sinkhole + a modern UI, in a single Docker Compose stack. The self-hosted counterpart to cloud SWGs, with no traffic leaving your network.
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
  - title: Forward-proxy egress control
    details: One controllable egress point. Block domains and IPs (CIDR + wildcard), one-click import of curated blocklists, geo-based blocking, and an optional default-deny egress allowlist.
  - title: Real WAF over ICAP
    details: A Go ICAP service inspects requests/responses — ~170 rules across 21 categories + behavioural heuristics, anomaly scoring. False negatives gated to 0 by an adversarial suite on every commit.
  - title: DNS sinkhole
    details: dnsmasq sinkholes blacklisted / malware / ad domains at the network layer, before a connection is ever made. SafeSearch and YouTube-restricted enforcement included.
  - title: MCP-native
    details: Ships an optional Model Context Protocol server — inspect and drive the gateway from Claude or any agent in natural language ("what's reaching AI APIs?", "block evil.example").
  - title: Real-time logs & analytics
    details: Live log streaming over WebSocket, filter/search/aggregate, top-domains, shadow-IT, per-client views — and a correlation event-id linking a blocked request to its WAF event end-to-end.
  - title: Hardened, signed, self-hosted
    details: Basic + JWT auth, login rate-limit, SSRF guards, bcrypt, backend bound to localhost. Cosign-signed multi-arch images on GHCR + Docker Hub. Runs entirely on your hardware, SQLite, no cloud.
---

## See it block

![Malicious requests blocked by the proxy + WAF, benign traffic allowed](/demo/adversarial-demo.svg)

Malicious requests get **403**'d at the proxy by the WAF; benign traffic passes.

## How it compares

| Capability | Pi-hole / AdGuard | Nginx Proxy Manager | Cloud SWG (Zscaler…) | **Secure Proxy Manager** |
|---|:---:|:---:|:---:|:---:|
| DNS sinkhole | ✅ | — | ✅ | ✅ |
| Forward proxy (egress control) | — | — | ✅ | ✅ |
| HTTP request/body inspection (WAF) | — | — | ✅ | ✅ |
| Default-deny egress allowlist | — | — | ✅ | ✅ |
| Reverse proxy / ingress | — | ✅ | — | — |
| Self-hosted — traffic stays local | ✅ | ✅ | — | ✅ |
| Free / no per-seat cost | ✅ | ✅ | — | ✅ |

SPM is the **self-hosted outbound** counterpart to a cloud Secure Web Gateway —
WAF inspection + DNS sinkholing + egress control, on your own metal.

## Tested like an attacker

An **adversarial e2e harness** (`make adversarial`, gated in CI) drives real
attack traffic *through* the running proxy + WAF and fails the build on any
regression — five planes:

- **block-matrix** — SQLi / XSS / RCE / SSRF / … across 21 categories → **false negatives = 0**, benign → **false positives = 0**.
- **API attacker** — auth-bypass, forged/tampered JWTs, login SQLi, rate-limit → no bypass.
- **bench/latency** — p95 + ICAP overhead, regression-gated.
- **config-matrix** — flip a setting → prove the data plane changes.
- **resilience** — kill the WAF → the proxy **fails closed**, then self-heals.

## Manage it from an agent (MCP)

```bash
SPM_URL=http://localhost:5001 SPM_USERNAME=admin SPM_PASSWORD=… uvx spm-mcp
```

Exposes the management API as MCP tools so an assistant/agent can query traffic,
manage block/allow lists, toggle WAF categories, and reload config.

## 30-second start

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/secure-proxy-manager/main/deploy/install.sh | sudo bash
```

The installer checks Docker, generates random admin credentials, pulls the
signed images, and starts the stack. Then point a client at the proxy on
`:3128` and open the dashboard. See the [Getting Started](/guide/getting-started)
guide.
