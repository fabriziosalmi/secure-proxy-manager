# Feature Roadmap — 100 Ideas Reviewed

## Summary

| Status | Count | Percentage |
|--------|-------|------------|
| 🟢 Done | **42** | 42% |
| 🔵 Do Next | **17** | 17% |
| ⚪ Backlog | 14 | 14% |
| ❌ Rejected | **27** | 27% |

**42 of 100 "innovative" ideas were already implemented.** The remaining 17 "Do Next" items represent ~35 hours of development for maximum impact.

## Priority "Do Next" List (sorted by impact)

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | Setup Wizard (first-login) | 3-4h | 🔥🔥🔥 |
| 2 | Multi-Arch ARM64 (Raspberry Pi) | 4-5h | 🔥🔥🔥 |
| 3 | Security Packs (WAF categories) | 4-5h | 🔥🔥🔥 |
| 4 | Client Setup Export (PAC + per-OS) | 3h | 🔥🔥🔥 |
| 5 | Kiosk Mode (whitelist-only) | 2-3h | 🔥🔥 |
| 6 | DevOps Preset | 1h | 🔥🔥 |
| 7 | DoH Blocker toggle | 2h | 🔥🔥 |
| 8 | GDPR IP masking | 2h | 🔥🔥 |
| 9 | Update Notifier | 1-2h | 🔥🔥 |
| 10 | Regex Playground | 3h | 🔥🔥 |
| 11 | WPAD Auto-Discovery | 2h | 🔥 |
| 12 | Pi-hole/AdGuard detect | 3h | 🔥 |
| 13 | ntfy.sh notifications | 30min | 🔥 |
| 14 | Let's Encrypt | 3-4h | 🔥 |
| 15 | One-Click Cloud Deploy | 2-3h | 🔥 |
| 16 | Squid CVE Alert | 2h | 🔥 |
| 17 | API Documentation | 1-3h | 🔥 |

---

# Feature Roadmap — Curated from 100 Ideas

> Gemini generated 100 feature ideas. We reviewed each one with brutal honesty.
> This file tracks only the ones that **actually make sense** for our stack and users.
> Rated by real-world impact, not hype.

---

## Status Legend
- 🟢 **Done** — already implemented
- 🔵 **Do Next** — high value, feasible now
- ⚪ **Backlog** — good idea, not urgent
- ❌ **Rejected** — doesn't fit our stack/audience

---

## Batch 1: UI & User Experience

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 1 | Web Dashboard | 🟢 Done | 5 pages, charts, real-time WebSocket |
| 2 | Visual Policy Builder | ❌ Rejected | Drag-drop ACL builder is over-engineered for homelab. Presets solve this better |
| 3 | Setup Wizard | 🔵 **Do Next** | First-login wizard: "What are you protecting?" → IoT, family, SMB → auto-configure |
| 4 | Dark Mode | 🟢 Done | Default theme since v1.0 |
| 5 | Log Viewer Searchable | 🟢 Done | Full-text search + live stream + pagination |
| 6 | Config Editor | ⚪ Backlog | Custom WAF rules textarea exists but no syntax highlighting. Monaco editor is overkill |
| 7 | Panic Mode | ❌ Rejected | One accidental click blocks entire network. `docker stop` is safer and faster |
| 8 | Mobile-Friendly | 🟢 Done | Hamburger menu, responsive layout since v2.0 |
| 9 | Multi-lingua | ❌ Rejected | i18n adds massive complexity. Target audience reads English |
| 10 | Custom Branding | ⚪ Backlog | "Company Name" field in settings. Low priority |

## Batch 2: Security & WAF

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 11 | ICAP WAF in Go | 🟢 Done | 166 regex + 7 heuristic + 3 ML-lite checks |
| 12 | Security Packs (toggleable rule groups) | 🔵 **Do Next** | Group WAF rules into packs: SQLi, XSS, DLP, C2, Crypto. Toggle per-category from UI |
| 13 | SSL-Bump Auto-Config | 🟢 Done | CA cert download button in Settings |
| 14 | C2 Feed Auto-Update | ⚪ Backlog | Backend has `blacklist_auto_refresh` worker but not configurable from UI. Add refresh interval + source management |
| 15 | DoH Blocker | 🔵 **Do Next** | Toggle that blocks DNS-over-HTTPS providers (dns.google, cloudflare-dns.com, doh.opendns.com). Prevents IoT/malware from bypassing dnsmasq |
| 16 | ClamAV Integration | ❌ Rejected | +200MB container, high RAM. WAF already detects ELF/PE/ZIP magic bytes. Not worth the resource cost for homelab |
| 17 | Anti-Mining | 🟢 Done | Stratum, xmrig, cpuminer, mining pool rules in WAF |
| 18 | Tor Exit Blocker | ⚪ Backlog | Add torproject.org bulk exit list to Popular Lists. Trivial but niche |
| 19 | Geo-Block UI | 🟢 Done | Country selector with one-click import |
| 20 | SSH Tunnel Detection | 🟢 Done | "Protocol Ghosting" heuristic detects SSH/binary in HTTP body |

---

## Implementation Plan: Top Priority Items

### 1. Setup Wizard (first-login onboarding)

**Why**: A new user installs, opens the UI, sees 30+ toggles and has no idea what to do. A wizard transforms this into 3 clicks.

**How**:
- Detect first login (no `wizard_completed` setting in DB)
- Show modal overlay with 3 steps:
  1. **"What's your setup?"** → Homelab / Family / Small Business / Advanced
  2. **"What devices use this proxy?"** → PCs, Smart TVs, IoT, Phones, Servers
  3. **"How strict?"** → Relaxed / Balanced / Strict
- Map answers to preset (Basic/Family/Standard/Paranoid) + device-specific blocklists
- Apply settings + mark wizard as completed
- User can re-run from Settings anytime

**Effort**: 3-4h

### 2. WAF Security Packs (toggleable rule categories)

**Why**: 166 rules are invisible to the user. They should see "SQLi Protection: ON" not regex soup.

**How**:
- Backend: WAF Go engine already has categories (SQL_INJECTION, XSS_ATTACKS, etc.)
- Add API endpoint `GET /api/waf/categories` → list categories with rule counts + enabled status
- Add API endpoint `POST /api/waf/categories/{name}/toggle` → enable/disable a category
- Frontend: Grid of category cards in Settings → DNS & WAF section, each with toggle + rule count
- Categories: SQLi (12 rules), XSS (8), Command Injection (6), Path Traversal (5), SSRF (4), Cloud Secrets (15), Sensitive Files (12), Web Shells (8), Crypto Mining (4), Data Exfil (6), Protocol Anomaly (8), DLP (10), Java/Deser (4), DNS Tunneling (3)

**Effort**: 4-5h (2h backend, 2h frontend)

### 3. DoH Blocker Toggle

**Why**: DNS-over-HTTPS lets devices bypass dnsmasq entirely. Smart TVs, IoT, and malware use DoH to phone home despite our DNS blackhole.

**How**:
- Maintain a list of known DoH provider domains:
  ```
  dns.google, dns.google.com, cloudflare-dns.com,
  mozilla.cloudflare-dns.com, doh.opendns.com,
  dns.quad9.net, doh.cleanbrowsing.org,
  dns.adguard.com, doh.appliedprivacy.net
  ```
- Toggle in Settings → adds these to domain blacklist + dnsmasq blocklist
- Also block well-known DoH IPs (8.8.8.8:443, 1.1.1.1:443) via Squid ACL
- Visual indicator on Dashboard when DoH blocking is active

**Effort**: 2h

## Batch 3: Integrations (Modern Self-Hosted)

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 21 | Tailscale/Wireguard gateway | 🟢 Done | Sidecar in compose, toggle in Settings |
| 22 | Notifications (Telegram/Discord) | 🟢 Done | Multi-provider: Telegram, Gotify, Teams, Discord, Custom webhook |
| 23 | Pi-hole/AdGuard auto-detect | 🔵 **Do Next** | Scan LAN for Pi-hole/AdGuard, offer to use as upstream DNS instead of dnsmasq. Respects existing setups |
| 24 | Auto-update Feeds | 🟢 Done (partial) | Worker exists. Need UI for refresh interval config |
| 25 | Home Assistant sensors | ❌ Rejected | Too niche. Our REST API is already consumable by HA via `rest` sensor |
| 26 | Cloud Backup (S3/WebDAV) | ⚪ Backlog | JSON export exists. Cloud adds credential complexity. External cron `curl` works |
| 27 | Let's Encrypt | 🔵 **Do Next** | Self-signed works but browsers complain. ACME for public-facing SMB deployments |
| 28 | Arr-Suite template | ⚪ Backlog | A "Media Server" preset whitelisting *arr domains. No native integration needed |
| 29 | Docker Socket Monitoring | ⚪ Backlog | Map container IP → name in logs. Privacy concern — opt-in only |
| 30 | Easy Client Export | 🔵 **Do Next** | "Setup my device" button → PAC file + per-OS instructions (Win/Mac/Linux/iOS/Android) |

### 4. Pi-hole / AdGuard Auto-Detect

**Why**: Users with existing Pi-hole/AdGuard won't uninstall them. We should cooperate, not compete. Auto-detect + offer to use as upstream DNS = zero friction adoption.

**How**:
- On first boot (or from Settings), scan common LAN IPs for:
  - Pi-hole API: `GET http://<ip>/admin/api.php?summary` (returns JSON if Pi-hole)
  - AdGuard Home API: `GET http://<ip>/control/status` (returns JSON if AdGuard)
  - Common IPs to scan: gateway (.1), .2-.10, .53, .100, .200
- If found:
  - Show toast/banner: "Found Pi-hole at 192.168.1.2 — Use as DNS?"
  - User confirms → set as upstream DNS for dnsmasq (or replace dnsmasq entirely)
  - Show in Settings: "DNS Provider: Pi-hole @ 192.168.1.2" with test + change button
- If not found:
  - Use built-in dnsmasq (current behavior, no change)
- Settings toggle: "Auto-detect DNS provider on LAN" (opt-in, default off for privacy)

**Effort**: 3h

## Batch 4: Performance & Core

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 31 | Multi-Arch Docker (ARM64) | 🔵 **Do Next** | Raspberry Pi is THE homelab device. `docker buildx` with QEMU for linux/amd64 + linux/arm64 |
| 32 | Low-RAM profile (512MB) | 🟢 Done | Stack total ~100MB (Go 20MB + WAF 15MB + dnsmasq 5MB + Squid 50MB) |
| 33 | OS Update Caching | ⚪ Backlog | Squid refresh patterns for APT/RPM/Windows Update. A "Cache Server" preset |
| 34 | Log Rotation | 🟢 Done | Go worker with configurable TTL |
| 35 | Healthchecks | 🟢 Done | All containers + Dashboard status |
| 36 | Multi-WAN Load Balancing | ❌ Rejected | Kernel-level routing, not proxy-level. Use pfSense/OPNsense |
| 37 | Fast-Config Reload | 🟢 Done | `squid -k reconfigure` via API, zero downtime |
| 38 | Minimal Alpine Base | 🟢 Done | 16MB Go binary on Alpine 3.20 |
| 39 | Parallel ICAP | 🟢 Done | Native Go goroutines per request |
| 40 | Kernel Tuning | ❌ Rejected | Requires `--privileged`, breaks container security |

## Batch 5: Compliance & Reporting

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 41 | PDF Report scheduled | 🟢 Done (partial) | Export button exists. Auto-schedule via cron + webhook would be nice |
| 42 | GDPR IP masking | 🔵 **Do Next** | Toggle to anonymize last octet in logs/analytics/exports. Essential for EU compliance |
| 43 | Top 100 Domains | 🟢 Done | Domain Cloud + `/api/analytics/top-domains` |
| 44 | Exfiltration volume alert | ⚪ Backlog | Per-IP byte tracking over time windows. WAF entropy helps but volume needs persistent state |
| 45 | Audit Trail | 🟢 Done | `/api/audit/log` tracks all admin actions |
| 46 | Bandwidth Quota per IP | ❌ Rejected | Monthly accounting + enforcement too complex for proxy-level. Use router QoS |
| 47 | Time-based Access | 🟢 Done | Toggle with start/end time in Settings |
| 48 | Shadow IT Detection | 🟢 Done | 35+ SaaS services auto-detected and categorized |
| 49 | Security Score | 🟢 Done | 0-100 score with recommendations on Dashboard |
| 50 | LDAP/AD Auth | ⚪ Backlog | Squid supports `basic_ldap_auth` but config is complex. v3 feature |

## Batch 6: Smart Features

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 51 | Auto-Learning Mode | ⚪ Backlog | Needs ML pipeline. Safe URL cache is a primitive version. v3 |
| 52 | Device Discovery | ❌ Rejected | ARP scan from Docker sees only container IPs. Needs LAN agent — out of scope |
| 53 | Honey-Domain Generator | ❌ Rejected | Fake traffic pollutes our own logs more than it confuses attackers |
| 54 | UA Randomizer | 🟢 Done | Protocol hardening strips/normalizes outbound User-Agent |
| 55 | WPAD Auto-Discovery | 🔵 **Do Next** | Serve `wpad.dat` on HTTP so browsers auto-configure proxy. Pairs with Client Export |
| 56 | ntfy.sh notifications | 🔵 **Do Next** | Ultra-light, self-hosted push. Add as provider alongside Telegram/Gotify. ~30min |
| 57 | Grafana/Prometheus | ⚪ Backlog | Go backend could expose `/metrics`. But adds Grafana container. REST API already scrapeable |
| 58 | Log Sanitizer | 🟢 Done (partial) | GDPR masking covers this use case |
| 59 | gRPC Inspection | ❌ Rejected | HTTP/2 binary — Squid can't inspect, needs Envoy. Different product |
| 60 | Rule Simulator (what-if) | 🔵 **Do Next** | Test regex against last 24h traffic logs. This is the "Regex Playground" from Sprint 3 |

### WPAD Auto-Discovery

**Why**: Instead of manually configuring proxy on every device, WPAD lets browsers auto-detect and auto-configure. Combined with Client Export, this is zero-touch onboarding.

**How**:
- Nginx serves `http://wpad.<domain>/wpad.dat` on port 80
- The PAC file content: `function FindProxyForURL(url, host) { return "PROXY <proxy-ip>:3128; DIRECT"; }`
- Settings field: "WPAD Domain" (e.g., `wpad.local`)
- dnsmasq adds: `address=/wpad.local/<proxy-ip>`
- Browsers with "Auto-detect proxy" enabled → find and use it automatically

**Effort**: 2h

### Regex Playground (Rule Simulator)

**Why**: Before deploying a new WAF rule, test it against real traffic. "Would this regex have blocked anything yesterday?" prevents false positives in production.

**How**:
- New API endpoint: `POST /api/waf/test-rule` with `{regex: "...", hours: 24}`
- Backend reads WAF JSONL traffic log, applies regex to stored URLs/bodies
- Returns: matches found, sample URLs, would-block count
- Frontend: textarea for regex + "Test" button + results table
- Could live in Threat Intel page or as a modal from Settings WAF section

**Effort**: 3h

### GDPR IP Anonymization

**Why**: EU law requires data minimization. Logging full client IPs when not needed for security is a compliance risk. A toggle to mask the last octet makes us GDPR-friendly out of the box.

**How**:
- Settings toggle: "GDPR Mode — Anonymize Client IPs"
- When enabled, the Go backend masks IPs before writing to DB:
  - `192.168.100.7` → `192.168.100.x`
  - Applied to: proxy_logs table, analytics queries, PDF export, WebSocket stream
- NOT applied to: blacklist/whitelist entries (those are intentional)
- The WAF ICAP still sees full IPs for blocking — only the logging/display is masked
- Reversible: turning off shows full IPs for new entries (old masked entries stay masked)

**Effort**: 2h

### Multi-Arch Docker Build

**Why**: Raspberry Pi 4/5 is the #1 homelab device. Without ARM64 images, half the self-hosted community can't use us.

**How**:
- GitHub Actions workflow with `docker buildx`:
  ```yaml
  platforms: linux/amd64,linux/arm64
  ```
- All 4 images need cross-compilation:
  - `web` (nginx): already multi-arch
  - `backend-go`: `GOARCH=arm64` cross-compile (trivial, Go handles this natively)
  - `waf-go`: same as backend
  - `proxy` (Squid): Ubuntu base supports arm64
  - `dns` (dnsmasq): Alpine supports arm64
- Push to Docker Hub / GHCR with manifest list
- Test on actual Pi or QEMU emulation in CI

**Effort**: 4-5h (mostly CI pipeline)

### 5. Let's Encrypt Integration (renumbered)

**Why**: Self-signed certs trigger browser warnings. SMB users with a domain want real HTTPS without manual cert management.

**How**:
- Add optional ACME client (acme.sh or certbot) to web container
- Settings toggle: "Let's Encrypt" with domain + email fields
- On enable: run ACME challenge via HTTP-01 (port 80 must be reachable)
- Auto-renew via cron inside container
- Fallback: keep self-signed if ACME fails

**Effort**: 3-4h

### 5. Client Setup Export (PAC + instructions)

**Why**: After installing the proxy, users struggle to configure their devices. A "Setup my device" page with copy-paste instructions and auto-generated PAC file removes this friction.

**How**:
- New page or modal: "Connect Your Devices"
- Auto-generate PAC file: `function FindProxyForURL() { return "PROXY host:3128"; }`
- Per-OS tabs with copy-paste instructions:
  - **Windows**: Settings → Proxy → Manual → host:3128
  - **macOS**: System Preferences → Network → Proxies → host:3128
  - **Linux**: `export http_proxy=http://host:3128`
  - **iOS**: WiFi → Configure Proxy → Manual → host:3128
  - **Android**: WiFi → Modify → Advanced → Proxy → Manual → host:3128
- Download buttons: PAC file, CA cert, shell script
- QR code for mobile (encode proxy URL)

**Effort**: 3h

## Batch 7: Ecosystem & Community

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 61 | Plugin System | ❌ Rejected | Security and plugins are antithetical in a WAF. Custom regex rules ARE the plugin system |
| 62 | Blacklist Marketplace | 🟢 Done (partial) | Popular Lists with 16+ sources. A community GitHub repo with curated lists could extend this |
| 63 | Community Wiki | ⚪ Backlog | GitHub Wiki or docs/. README is already comprehensive |
| 64 | One-Click Cloud Deploy | 🔵 **Do Next** | cloud-init script for Hetzner/DO/Linode. Docker compose already works — just need a bootstrap script |
| 65 | GitHub Discussions | 🟢 **Done** | Activated! Community hub for questions and feature requests |
| 66 | Bug Bounty | ⚪ Backlog | SECURITY.md with responsible disclosure + credits |
| 67 | Video Tutorial | ⚪ Backlog | Marketing content, not code. When product is stable |
| 68 | Public CI/CD | 🟢 Done | GitHub Actions. Multi-arch build is the missing piece |
| 69 | MIT License | 🟢 Done | Already MIT — most permissive |
| 70 | Public Roadmap | 🟢 Done | This file (GEMINI.md) IS the roadmap |

## Batch 8: Vertical Use Cases

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 71 | Non-Profit Safe profile | 🟢 Done | "Family" preset covers this |
| 72 | Privacy Paranoiac profile | 🟢 Done | "Paranoid" preset + 2.9M domain blocklist |
| 73 | DevOps profile | 🔵 **Do Next** | Whitelist Docker Hub, GitHub, PyPI, npm, crates.io. "Allow only dev tools" mode |
| 74 | Kiosk Mode | 🔵 **Do Next** | Block everything except whitelisted domains. "Whitelist-only" toggle |
| 75 | IoT Isolation | 🟢 Done (partial) | Geo-block + DNS blackhole. Per-device policy needs router integration |
| 76 | CrowdSec | ⚪ Backlog | Adds container + external API. Popular Lists covers 90% of the value |
| 77 | IPv6 full support | ⚪ Backlog | Squid and WAF support it, but testing is complex. Few homelabs use internal IPv6 |
| 78 | Security Headers | 🟢 Done | HSTS, CSP, X-Frame-Options, X-Content-Type-Options injected |
| 79 | MIME-Type Filter | 🟢 Done | Content Filtering toggle with configurable extensions |
| 80 | WebSocket Support | 🟢 Done | Squid CONNECT + Nginx upgrade. Live Stream uses WSS |

### DevOps Preset

**Why**: A developer's proxy should whitelist dev tools, not block npm install. A preset that auto-whitelists essential dev domains removes friction for developer homelabs.

**How**:
- New preset in Presets.tsx: "DevOps" with Server icon
- Auto-adds to domain whitelist:
  ```
  github.com, *.github.com, *.githubusercontent.com,
  registry.npmjs.org, pypi.org, files.pythonhosted.org,
  registry.hub.docker.com, *.docker.io, *.docker.com,
  crates.io, static.crates.io,
  repo.maven.apache.org, dl.google.com,
  packages.microsoft.com, apt.releases.hashicorp.com
  ```
- WAF threshold: 10 (moderate — devs hit more exotic URLs)
- Content filtering: OFF (devs download executables)
- All heuristics: ON (devs should still be protected from C2)

**Effort**: 1h (just a new preset config)

### Kiosk Mode (Whitelist-Only)

**Why**: A library, school, or public terminal needs to allow ONLY specific domains. Everything else is blocked by default.

**How**:
- Settings toggle: "Kiosk Mode (Whitelist-Only)"
- When enabled: Squid ACL order changes — `deny all` first, then `allow domain_whitelist`
- The Domain Whitelist becomes the primary access list
- Dashboard shows "KIOSK MODE" badge as warning
- Pre-populated suggestions: "Add Google, Wikipedia, educational sites?"

**Effort**: 2-3h (Squid ACL reorder + UI toggle)

### One-Click Cloud Deploy

**Why**: A self-hoster on Hetzner/DO wants to run one command and have everything working. No SSH, no Docker knowledge.

**How**:
- `deploy/cloud-init.sh` — a curl-pipe-sh script:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/.../deploy.sh | bash
  ```
- Script does: install Docker, clone repo, generate .env with random password, docker compose up
- For Hetzner: a cloud-init YAML that runs on first boot
- For DigitalOcean: a 1-Click App template (Marketplace submission)
- README badge: "Deploy on Hetzner" / "Deploy on DigitalOcean"

**Effort**: 2-3h

## Batch 9: Maintainability & Stability

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 81 | Syslog/GELF export | ⚪ Backlog | Go syslog is trivial but ELK users already use `docker logs` → Filebeat |
| 82 | Auto-diagnose iptables | ❌ Rejected | Requires `--privileged` + host networking |
| 83 | Config Snapshot/Rollback | 🟢 Done | JSON backup + restore API. UI "previous versions" is backlog |
| 84 | Docker Compose download | ❌ Rejected | Compose is in Git. Generating from UI causes version confusion |
| 85 | Works Offline | 🟢 Done | Local SQLite, local dnsmasq, local WAF. Zero external deps |
| 86 | Load Test | 🟢 Done | E2E stress test + full benchmark script |
| 87 | Squid CVE Alert | 🔵 **Do Next** | Check Squid version vs known CVEs. Show warning badge in Dashboard |
| 88 | API Documentation | 🔵 **Do Next** | OpenAPI spec or `/api/docs` endpoint. Essential for integrations |
| 89 | CLI Tool (spm) | ⚪ Backlog | UI + curl + E2E covers everything. Dedicated CLI is overkill now |
| 90 | Update Notifier | 🔵 **Do Next** | Check GitHub releases API, show "v2.3.0 available" badge in sidebar |

## Batch 10: God Mode

| # | Idea | Status | Notes |
|---|------|--------|-------|
| 91 | AI Chatbot (Ollama) | ❌ Rejected | +4GB RAM for a proxy. WAF explainability is enough |
| 92 | Terraform Export | ❌ Rejected | Ultra-niche. Terraform users can write docker_container themselves |
| 93 | Cloud Bandwidth Costs | ❌ Rejected | Requires pricing API per cloud provider. Too fragile |
| 94 | Crypto-jacking Detection | 🟢 Done | WAF rules for stratum/xmrig/pools + beaconing heuristic |
| 95 | Hardware LED/Buzzer | ❌ Rejected | Fun but useless. Telegram/ntfy notifications do the same |
| 96 | SOCKS5 Support | ⚪ Backlog | Squid supports it but config is separate. Niche |
| 97 | Internal IP Reputation | 🟢 Done (partial) | Top Clients analytics + dest sharding heuristic |
| 98 | Mobile Traffic Profile | ❌ Rejected | CA cert install is documentable in Client Export. No special "profile" needed |
| 99 | GitOps Config Backup | ⚪ Backlog | Auto-commit to Git repo. Nice but adds Git complexity in container |
| 100 | Ghost Mode | ❌ Rejected | Hiding proxy from internal scanners — if it's your network, hiding makes no sense |

### Squid CVE Alert

**Why**: Running a proxy with known vulnerabilities is worse than running no proxy. A simple version check against a CVE list tells the admin "update now."

**How**:
- Go backend checks Squid version via `squid -v` on startup
- Maintains a small embedded map of `version → [CVE-IDs]`
- Dashboard shows amber badge: "Squid 5.9 — 2 known CVEs" with links
- Settings section shows detailed CVE list with severity

**Effort**: 2h

### Update Notifier

**Why**: Users don't check GitHub for updates. A small badge "v2.3.0 available" in the sidebar motivates upgrades.

**How**:
- Go backend checks `https://api.github.com/repos/fabriziosalmi/secure-proxy-manager/releases/latest` every 6h
- Compares with current version
- If newer: returns `update_available: "v2.3.0"` in health endpoint
- Sidebar shows small badge next to version: "2.0.0-go ⬆ 2.3.0"
- Click → opens GitHub release page

**Effort**: 1-2h

### API Documentation

**Why**: Anyone wanting to integrate (Home Assistant, scripts, monitoring) needs to know the endpoints.

**How**:
- Option A: Hand-written OpenAPI 3.0 YAML in `docs/openapi.yaml` — tedious but precise
- Option B: Auto-generate from Go chi routes with comments — less maintenance
- Option C: Simple `/api/docs` endpoint that returns a JSON listing of all routes
- Start with C (1h), upgrade to A later

**Effort**: 1-3h depending on approach

---

## Rejected Ideas (with reasoning)

| Idea | Why Not |
|------|---------|
| Visual Policy Builder | Drag-drop is cool in demos, terrible in practice. Text config + presets are faster |
| Panic Mode | Accidental click = entire family/office offline. `docker stop` exists |
| Multi-lingua | Our users read English. i18n doubles maintenance burden for every string |
| ClamAV | 200MB+ RAM for virus scanning that WAF already handles at the protocol level |
| Custom Branding | Nice-to-have but zero security value. Maybe v3 |
| Home Assistant | Too niche. REST API already consumable by HA sensors |
| Bandwidth Quota | Monthly per-IP accounting too complex for proxy-level. Use router QoS |
| Device Discovery | ARP scan from Docker only sees container IPs. Needs LAN agent |
| Honey-Domains | Fake traffic pollutes our own analytics |
| gRPC Inspection | HTTP/2 binary stream, Squid can't inspect. Needs Envoy — different product |
| Plugin System | Security tool + arbitrary code execution = oxymoron. Custom regex rules are the extension mechanism |
| Auto-diagnose iptables | Requires --privileged and host networking |
| Docker Compose download | Compose is in Git. Generating from UI causes version confusion |
| AI Chatbot (Ollama) | +4GB RAM for a proxy is absurd. WAF explainability covers the use case |
| Terraform Export | Ultra-niche. Terraform users write docker_container themselves |
| Cloud Bandwidth Costs | Requires pricing API per cloud provider. Too fragile to maintain |
| Hardware LED/Buzzer | Telegram/ntfy notifications accomplish the same without hardware |
| Mobile Traffic Profile | CA cert install is documentable in Client Export |
| Ghost Mode | Hiding your own proxy from your own network makes no sense |
