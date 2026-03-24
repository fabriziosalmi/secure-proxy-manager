# Integration Architecture — 3-Layer LLM Security Stack

## Overview

Three independent projects that together form a complete edge-to-LLM security pipeline:

| Layer | Project | Role | Tech |
|-------|---------|------|------|
| L1 — Edge Ingress | [edge99/SecBeat](https://github.com/fabriziosalmi/traefik-simple-cdn) | TLS, WAF, DDoS, bot detection | Rust, K3s, eBPF |
| L2 — Network Egress | [secure-proxy-manager](https://github.com/fabriziosalmi/secure-proxy-manager) | Egress filtering, domain whitelist, IP blocking | Squid, Python |
| L3 — Application | [llmproxy](https://github.com/fabriziosalmi/llmproxy) | LLM security gateway, injection detection, cost routing | Python, FastAPI |

## Request Flow

```
Internet
  │
  ▼
SecBeat (L1 — Ingress)
  ├── eBPF: kernel-level DDoS filtering (pre-TLS)
  ├── TLS termination + JA3/JA4 fingerprinting
  ├── WAF: 166 OWASP rules (SQLi, XSS, path traversal, cmd injection)
  ├── 231k malicious domain blocklist (TI-Engine)
  ├── Behavioral correlation (cross-edge gossip, 3-node consensus)
  ├── HTTP/3 QUIC support
  └── HMAC-signed inter-node communication
  │
  ▼
llmproxy (L3 — Application)
  ├── ASGI firewall (byte-level + encoding detection)
  ├── SecurityShield (injection scoring, PII masking, trajectory analysis)
  ├── Lexical injection detection (60 patterns, 8 categories, multilingual)
  ├── Cross-session threat intelligence (ThreatLedger)
  ├── 5-ring plugin pipeline (18 marketplace plugins)
  ├── Cost-aware routing + budget enforcement
  ├── HMAC response attestation
  ├── Immutable audit ledger (SHA256 hash chain)
  ├── GDPR compliance (erasure, DSAR, retention)
  └── Supply chain .pth detection (6-layer defense)
  │
  ▼ (outbound via L2)
secure-proxy-manager (L2 — Egress)
  ├── Domain whitelist (only LLM provider APIs allowed)
  ├── Direct IP blocking (no raw IP exfiltration)
  ├── HTTPS inspection (MITM for encrypted payloads)
  ├── File type blocking (.tar, .zip, .gz — no bulk exfil)
  ├── IMDS blocking (169.254.169.254 — no cloud cred theft)
  └── Full connection audit log
  │
  ▼
LLM Providers (OpenAI, Anthropic, Google, etc.)
```

## Integration Points (APIs already exist)

### SecBeat → llmproxy (ingress enrichment)
- **Mechanism**: HTTP headers injected by SecBeat, read by llmproxy
- **Data flow**:
  - `X-Edge99-Threat-Score`: WAF + behavioral score (0-100)
  - `X-Edge99-JA3`: TLS fingerprint hash
  - `X-Edge99-Country`: GeoIP country code
  - `X-Edge99-Bot-Score`: Bot probability
- **llmproxy action**: Enrich `PluginContext.metadata` for plugin decisions
- **TODO**: llmproxy plugin to read and weight edge-level threat data

### llmproxy → SecBeat (threat escalation)
- **Mechanism**: POST to SecBeat admin API
- **Endpoint**: `/_cluster/blacklist` (exists in SecBeat)
- **Trigger**: ThreatLedger IP score exceeds threshold
- **Effect**: IP banned at eBPF level across all 5 global edges
- **TODO**: Webhook in llmproxy that fires on ThreatLedger threshold

### llmproxy → secure-proxy-manager (exfil containment)
- **Mechanism**: POST to Squid proxy API
- **Endpoints**:
  - `/api/ip-blacklist` — block IP destination
  - `/api/domain-blacklist` — block domain destination
- **Trigger**: Detected exfiltration attempt or compromised dependency
- **Effect**: Outbound connection to target blocked at network level
- **TODO**: Webhook in llmproxy for outbound threat events

### SecBeat → secure-proxy-manager (TI propagation)
- **Mechanism**: Import API
- **Endpoint**: `/api/domain-blacklist/import` (exists in secure-proxy)
- **Data**: 231k malicious domain list from TI-Engine
- **TODO**: Cron job or gossip hook to sync TI data to egress filter

### secure-proxy-manager → llmproxy (network anomaly alert)
- **Mechanism**: Webhook (not yet implemented in secure-proxy)
- **Trigger**: Blocked outbound connection from llmproxy container
- **Effect**: ThreatLedger records event, alerts operator
- **TODO**: Add webhook support to secure-proxy-manager

## Docker Compose (Combined Stack)

```yaml
# Conceptual — not yet tested as combined stack
version: "3.9"

services:
  # L1: Edge ingress (SecBeat)
  secbeat:
    image: ghcr.io/fabriziosalmi/secbeat:latest
    ports:
      - "443:443"
      - "8443:8443"  # HTTP/3 QUIC
    environment:
      - BACKEND_URL=http://llmproxy:8090

  # L3: Application (LLM proxy)
  llmproxy:
    build: ./llmproxy
    ports:
      - "8090:8090"
    environment:
      - HTTP_PROXY=http://squid-proxy:3128
      - HTTPS_PROXY=http://squid-proxy:3128
      - NO_PROXY=localhost,127.0.0.1,secbeat
    volumes:
      - llmproxy-data:/app/data
      - ./config.yaml:/app/config.yaml:ro

  # L2: Network egress (Squid)
  squid-proxy:
    image: ghcr.io/fabriziosalmi/secure-proxy-manager:latest
    ports:
      - "3128:3128"
    environment:
      - BLOCK_DIRECT_IP=true
      - ENABLE_DOMAIN_BLACKLIST=true
      - ENABLE_HTTPS_FILTERING=true

networks:
  default:
    driver: bridge
```

## Attack Coverage Matrix

| Attack Vector | SecBeat (L1) | llmproxy (L3) | secure-proxy (L2) | Combined |
|---|:---:|:---:|:---:|:---:|
| DDoS / volumetric | ✅ eBPF | ❌ | ❌ | ✅ |
| SQLi / XSS | ✅ WAF | ❌ | ❌ | ✅ |
| Bot / scraper | ✅ JA3/JA4 | ❌ | ❌ | ✅ |
| Prompt injection | ⚠️ Generic WAF | ✅ Specialized | ❌ | ✅✅ |
| Multi-turn jailbreak | ❌ | ✅ Trajectory | ❌ | ✅ |
| PII leakage | ❌ | ✅ Presidio+regex | ❌ | ✅ |
| System prompt extraction | ❌ | ✅ Canary detector | ❌ | ✅ |
| Supply chain .pth | ❌ | ✅ 6-layer detect | ❌ | ✅ |
| Credential exfil to domain | ❌ | ⚠️ Detect only | ✅ Block | ✅✅ |
| Credential exfil to IP | ❌ | ⚠️ Detect only | ✅ Block | ✅✅ |
| Cloud IMDS theft | ❌ | ❌ | ✅ Block | ✅ |
| Bulk data exfil (.tar) | ❌ | ❌ | ✅ Block | ✅ |
| Budget exhaustion | ❌ | ✅ Guard+downgrade | ❌ | ✅ |
| Response tampering | ❌ | ✅ HMAC | ❌ | ✅ |
| Audit tampering | ❌ | ✅ Hash chain | ❌ | ✅ |
| GDPR violation | ❌ | ✅ Erasure+DSAR | ❌ | ✅ |

## Session Plan

**Dedicated integration session required.** Tasks:

1. **Client fingerprinting**: Ensure SecBeat → llmproxy header propagation doesn't leak client identity to LLM providers. Use internal headers only, strip before outbound.
2. **Threat escalation webhook**: llmproxy ThreatLedger → SecBeat `/_cluster/blacklist` POST on threshold breach.
3. **Egress containment webhook**: llmproxy → secure-proxy `/api/ip-blacklist` on detected exfil.
4. **Edge enrichment plugin**: llmproxy marketplace plugin that reads `X-Edge99-*` headers and adjusts threat scoring.
5. **Combined Docker Compose**: Single-command deployment of all 3 layers.
6. **E2E test**: Full attack simulation through all 3 layers.
7. **TI sync**: SecBeat 231k domain list → secure-proxy egress blocklist.

**Requirements**: Both codebases open, all 3 services running, Tailscale mesh for secure inter-node communication.

## Competitive Position

No LLM proxy competitor has this stack:
- **LiteLLM**: Compromised (supply chain attack 2026-03-24). 100+ deps, no WAF, no egress filter, no audit chain.
- **Portkey**: Application-only. No edge security, no network filtering, no supply chain protection.
- **Helicone**: Observability-focused. No security pipeline, no egress control, no GDPR.
- **This stack**: 3-layer defense from eBPF kernel to LLM API, 11 deps, 687 tests, 7/7 CI, MIT licensed.
