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
