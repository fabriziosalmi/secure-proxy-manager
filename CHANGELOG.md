# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.2] - 2026-04-07

### Added

- **Glass morphism UI**: Full design system overhaul — `backdrop-blur` glass surfaces, animated number counters (rAF with ease-out cubic), staggered card entrance animations, progress bar glow effects with color-matched `box-shadow`, frosted ⌘K search modal, ambient login glow, custom 4px themed scrollbars, and gradient typography across all pages
- **Sidebar active pill indicator**: Animated sliding bar with `transition-all duration-300` that follows the active nav item
- **Status panel redesign**: Sidebar footer rebuilt with concentric pulse ring indicator, hierarchical status text, version/runtime/update row, and deprioritized sign-out
- **`useAnimatedNumber` hook**: `requestAnimationFrame`-based counter interpolation with ease-out cubic, used on Dashboard, ThreatIntel, and Logs pages
- **Extra SSL/HTTPS Ports setting**: New `extra_ssl_ports` setting in Settings → Proxy Configuration for HTTPS CONNECT on non-standard ports (e.g. Proxmox 8006, Grafana 3000); validated and injected into Squid `SSL_ports` ACL at startup
- **Chart tooltip glass style**: All Recharts tooltips upgraded with `backdrop-filter: blur(12px)`, translucent borders, and `tabular-nums`
- **Page transitions**: `fade-in-up` entrance animation on route change via `key={location.pathname}` in Layout
- **Button micro-interactions**: `active:scale(0.97)` press effect and `translateX(2px)` row hover across all interactive elements

### Fixed

- **DNS crash-loop**: Fixed double `--conf-file` flag in entrypoint (second silently overwrote the first, dropping base config including `listen-address`, `bind-interfaces`, and `conf-dir` for blocklists). Now merges base + runtime into single `/tmp/dnsmasq.conf`
- **DNS memory exhaustion**: Increased container memory limit from 64M to 256M for large blocklists (600K+ domains); reduced `cache-size` from 100K to 10K to prevent memory pressure alongside address-based blocklists
- **DNS healthcheck timing**: Relaxed from `start_period: 3s, timeout: 2s, retries: 3` to `start_period: 15s, timeout: 5s, retries: 6` for reliable cold-start with large blocklists
- **Web container crash**: `mkdir /etc/nginx/ssl` failed on read-only filesystem; added tmpfs mounts for `/etc/nginx/ssl`, `/etc/nginx/conf.d`, `/var/www/certbot`
- **Web container permissions**: `chown("/var/cache/nginx/client_temp")` failed due to `cap_drop: ALL`; added `CHOWN`, `SETUID`, `SETGID`, `NET_BIND_SERVICE` capabilities required by nginx master process
- **Proxy healthcheck**: Replaced external `curl http://example.com` probe (DNS + network dependent, unreliable) with local `squidclient mgr:info` with `curl gstatic.com/generate_204` fallback; increased `start_period` to 30s and `retries` to 5

## [3.2.1] - 2026-04-07

### Fixed

- Settings save failure caused by key mismatches, stale closures, and missing Zod schema validation across frontend and backend
- Proxy GUI inaccessible when browser configured to use the proxy (port 8443 missing from SSL_ports, LAN destinations blocked by direct IP rules)
- Docker healthchecks failing due to missing tools in containers (replaced squidclient/wget with curl)
- SSRF to Docker internal containers via proxy ACL allowing 172.16.0.0/12 destinations (removed, restricted to 10.0.0.0/8 and 192.168.0.0/16)

### Security

- ReDoS protection: regex length capped at 1024 characters with client-side and server-side validation
- Country code injection blocked with strict two-letter alpha validation on geo-import
- crypto/rand failure now panics instead of falling back to a predictable math/rand token
- IP address validation uses net.ParseIP instead of trusting raw header values
- Custom WAF rules reject null bytes and enforce 512-character limit
- Clipboard API errors handled properly (non-HTTPS contexts)
- Unbounded analytics queries capped (file extensions, user agents, shadow IT)
- Docker compose: no-new-privileges, read-only root filesystem, cap_drop ALL, log rotation on all services
- Nginx rate limiting (20 req/s API, 5 req/min login), TLS cipher suite restricted to ECDHE-only

### Added

- Login failure alerting: failed authentication attempts broadcast via WebSocket and notification pipeline (webhook, Gotify, Telegram, ntfy)

### Performance

- SQLite: MaxOpenConns increased from 1 to 4 for concurrent WAL readers; PRAGMA cache_size 50 MB, mmap_size 512 MB, temp_store in memory; ANALYZE on startup
- SQLite indexes added on proxy_logs(unix_timestamp), proxy_logs(destination), audit_log(timestamp)
- WAF heuristic engine: consolidated five mutex lock/unlock cycles per request into one; capped client state map at 10K entries
- WAF rule matching: early threshold exit skips remaining tiers once score is met
- WAF DGA detection cached per domain (10K entries, 10-minute TTL)
- Shannon entropy calculation uses fixed-size array instead of map allocation
- WAF tar-pit delay moved to background goroutine (was blocking ICAP handler for 10 seconds)
- WAF ipBlockTracker capped at 10K IPs with amortized eviction (was O(n) full-map scan per block)
- WAF backend notification uses pooled HTTP client (was allocating a new client per call)
- Nginx: gzip compression on text types, HTTP/2, SSL session cache 50 MB, static asset caching with immutable headers
- DNS resolver: cache-size increased from 10K to 100K entries; negative caching enabled; TTL clamping 300s-3600s
- Squid: persistent connections, pipeline prefetch, aggressive refresh patterns for static assets, ICAP preview size 1K to 4K
- Frontend: Vite manual chunk splitting (react, recharts, tanstack-query); log filter memoized with useMemo

## [3.2.0] - 2026-04-04

### Security Hardening (18 improvements)

#### Critical Fixes
- **Plaintext password eliminated**: bcrypt is now the primary auth method; plaintext env-var fallback only used during first boot before DB seed completes
- **Sensitive tokens encrypted at rest**: Webhook URLs, Gotify/Telegram/ntfy tokens stored with AES-256-GCM in the database (new `internal/crypto` package)
- **JWT blacklist persisted**: Revoked tokens survive container restarts via new `jwt_blacklist` SQLite table with TTL-based cleanup
- **AdminPasswordHash loaded from DB**: Previously missing — the bcrypt hash is now loaded at startup so auth uses it correctly

#### New Security Infrastructure
- **Global rate limiting**: Token bucket per-IP middleware (20 req/s sustained, 60 burst) on all endpoints, not just login
- **Circuit breaker**: WAF service calls protected against cascading failures (3 failures → open 30s → half-open probe)
- **Notification retry**: Failed webhook/Telegram/Gotify/ntfy deliveries retry 3x with exponential backoff (1s, 2s, 4s)
- **WebSocket origin validation**: `CheckOrigin` now validates against CORS allowlist instead of accepting all origins
- **CSP tightened**: Removed `unsafe-eval` from script-src, `*` from connect-src → `script-src 'self'; connect-src 'self' ws: wss:`
- **Self-signed cert reduced**: Validity 10 years → 1 year for better security hygiene

#### Performance & Reliability
- **3 new SQLite indexes**: `idx_proxy_logs_ts_ip`, `idx_proxy_logs_ts_dest`, `idx_proxy_logs_status` — accelerates analytics queries on large DBs
- **Query LIMIT clauses**: UserAgents (50), FileExtensions (50000) prevent unbounded result sets
- **Worker graceful shutdown**: All 4 background workers now accept `context.Context` and stop cleanly on SIGTERM
- **pprof endpoint**: `/debug/pprof/*` routes (auth-protected) for production CPU/memory profiling

#### CI/CD Improvements
- **Backend unit tests in CI**: New job with race detector and 60% coverage threshold
- **gosec security scanning**: Automated vulnerability scanning for both backend-go and waf-go
- **npm audit**: Frontend dependency audit (high severity) in CI pipeline

### Added
- `backend-go/internal/crypto/` — AES-256-GCM encryption package with tests
- `backend-go/internal/middleware/ratelimit.go` — Per-IP token bucket rate limiter
- `backend-go/internal/middleware/circuitbreaker.go` — Circuit breaker (closed/open/half-open)
- `PLAN.md` — Comprehensive project analysis and action plan

### Changed
- `auth.go` — bcrypt-first password verification, JWT blacklist uses SHA-256 hashed keys
- `main.go` — Worker context propagation, pprof routes, WS origin check, DB hash loading
- `settings.go` — Transparent encrypt-on-write / decrypt-on-read for sensitive settings
- `security.go` — Notification retry with backoff, encrypted settings decryption
- `analytics.go` — Circuit breaker on WAF calls, LIMIT on queries
- `ci.yml` — 3 new jobs (backend tests, gosec, npm audit)
- `docker-entrypoint.sh` — Cert validity 3650 → 365 days
- `nginx.conf.template` — CSP aligned with backend middleware

## [3.0.0] - 2026-03-28

### Added — 17 New Features
- **Setup Wizard**: 3-step first-login onboarding (environment → devices → strictness)
- **6 Presets**: Basic, Family, Standard, Paranoid, DevOps, Kiosk
- **Security Packs**: 21 toggleable WAF categories via API
- **Client Setup Export**: PAC file + per-OS instructions (Win/Mac/Linux/iOS/Android)
- **Kiosk Mode**: Whitelist-only preset for public terminals
- **DoH Blocker**: Blocks 14 DNS-over-HTTPS providers
- **GDPR IP Masking**: Anonymize last IP octet in logs
- **Update Notifier**: Checks GitHub releases every 6h, badge in sidebar
- **Regex Playground**: Test WAF rules against real traffic before deploying
- **WPAD Auto-Discovery**: Browsers auto-detect proxy via wpad.dat
- **Pi-hole/AdGuard Detect**: Scans LAN for existing DNS providers
- **ntfy.sh Notifications**: Self-hosted push notification provider
- **Let's Encrypt**: Auto-HTTPS with certbot (optional, fallback to self-signed)
- **One-Click Cloud Deploy**: install.sh + cloud-init.yaml for any VPS
- **Squid CVE Alert**: Detects known vulnerabilities in Squid version
- **API Documentation**: GET /api/docs — 60+ endpoints with descriptions
- **Multi-Arch ARM64**: GitHub Actions builds for linux/amd64 + linux/arm64

### Changed
- Go backend is now the default (no overlay needed)
- Removed legacy Python backend directory
- CI updated: Go build + WAF tests replace Python lint
- Docker Compose simplified: `docker compose up -d` uses Go backend
- Memory limit 768M → 128M (Go uses ~20MB)
- HTTPS on ports 443/8443, HTTP redirect on 80/8011

### Security
- All Dependabot vulnerabilities resolved
- Proper IP validation (rejects 999.999.999.999)
- Domain validation per RFC 1035
- TypeScript typed interfaces (replaced Record<string,string>)
- Settings compact toggle grid (consistent UI)

## [2.2.1] - 2026-03-28

### Fixed
- Removed legacy Python backend (3,545 lines deleted)
- Go backend as default in docker-compose.yml
- Record<string,string> → typed interfaces
- IP validation: octets 0-255, CIDR 0-32
- Domain validation: RFC 1035
- Memory limit 768M → 128M

## [2.0.0] - 2026-03-27

### Added
- Complete Go backend port (3,551 LOC, 16MB binary)
- 27 security audit fixes across 5 rounds
- 104-check E2E test suite
- HTTPS with self-signed TLS auto-generated
- Logout button, change password form
- Compact Settings UI with toggle grids

### Changed
- Python/FastAPI replaced by Go (chi, zerolog, modernc/sqlite)
- Backend memory: 150MB → 20MB
- P50 latency: 180ms → 107ms

## [1.8.0] - 2026-03-27

### Added
- Version badge (v1.8.0) in sidebar footer
- Web (nginx) container healthcheck
- Intelligence & Analytics API endpoints documented in README

### Fixed
- **50+ DB connection leaks** across all 9 backend routers (try/finally)
- All bare `except` clauses now log errors properly
- Large blacklist import: streaming download + batch insert (2.6M domains supported)
- Backend memory limit 512M → 768M for large imports
- Search box moved from fixed overlay to sidebar (no more button overlap)
- Blacklist naming: "Fabrizio Salmi" → "Aggregated Blacklist (Ads+Trackers+Malware)"

### Security
- SQL injection fix in database_routes.py (parameterized table names)
- JWT secret stable across container restarts
- Credentials stripped from debug logs
- Database indexes on source_ip, status, timestamp
- Unbounded query limits clamped
- 0 Dependabot vulnerabilities

### Improved
- Zero TypeScript `any` types in entire codebase
- All API responses properly typed with interfaces

## [1.7.1] - 2026-03-27

### Added
- **Threat Intel Dashboard**: Shadow IT detector (35+ SaaS services categorized), file type distribution, service type breakdown, domain cloud
- **Global Search (⌘K)**: Search across logs, blacklists, pages from anywhere
- **Keyboard Shortcuts**: 1-5 for page navigation, Escape to close modals
- **Asset Tags**: Click any IP to assign a human-readable name
- **Cache Efficiency Gauge**: Squid cache hit rate on Dashboard
- 4 analytics API endpoints: shadow-it, file-extensions, user-agents, top-domains
- **Protocol Hardening**: Method whitelisting, Via/XFF stripping, HSTS injection, max header size
- **Reset Counters**: Clear WAF stats, dashboard, and logs independently
- Auto-refresh blocklists after import
- LAN bypass for proxy self-access

### Fixed
- WebSocket Live Stream works through proxy (CONNECT to LAN)
- Method blocking ACL position in Squid config
- Volume permissions via gosu entrypoint

## [1.4.0] - 2026-03-26

### Added
- WAF expanded to 171 rules across 21 categories (was 78/11) with 10 new categories: CLOUD_SECRETS, SENSITIVE_FILES, WEBSHELL_C2, CRYPTO_TUNNEL, DATA_EXFIL, POST_EXPLOIT, JAVA_DESER, PROTOCOL_ANOMALY, FINANCIAL_DATA, RANSOMWARE
- WAF traffic intelligence: Shannon entropy calculator, per-request feature extraction, JSONL profiling (training data for future ML anomaly detection)
- WAF /stats endpoint with real-time metrics: req/min, avg entropy, high entropy count, top destinations, top blocked categories
- Backend /api/waf/stats proxy endpoint for UI integration
- Dashboard "WAF Intelligence" card showing live WAF metrics
- RESPMOD body inspection for reflected XSS and secret leaks in responses
- BENCHMARKS.md with reproducible security and performance test results

### Changed
- WAF Go codebase modularized into 5 files: main.go, rules.go, entropy.go, stats.go, normalize.go
- React Query migration: all 4 pages (Dashboard, Blacklists, Logs, Settings) now use @tanstack/react-query
- Auth tokens moved from sessionStorage to localStorage (survives new tabs)

### Fixed
- CSP policy: added unsafe-eval (Recharts), ws:/wss: (WebSocket connections)
- crypto.randomUUID fallback for non-secure HTTP contexts
- Recharts ResponsiveContainer minWidth/minHeight to prevent -1 dimension warnings
- Read-only database error on index creation during startup

### Security
- Fixed 7 dependency vulnerabilities: PyJWT 2.9->2.12.1, python-multipart 0.0.20->0.0.22, requests 2.32.4->2.33.0, picomatch (npm audit fix)
- WAF benchmark: 100% attack detection (23/23), 0% false positives (5/5)

## [1.3.0] - 2026-03-26

### Added
- WAF request body inspection: Go ICAP server now scans POST/PUT payloads (up to 1MB) for SQL injection, XSS, command injection, and other attack patterns
- WAF HTTP health endpoint on port 8080 with Docker healthcheck integration
- Backend modular architecture: main.py split into config, auth, database, models, websocket, and 8 API routers
- Automatic log retention background task (configurable via `log_retention_days` setting, default 30 days)
- Database index on `proxy_logs(timestamp)` for faster queries
- CI pipeline: added `lint-backend` (ruff) and `docker-build` verification jobs
- React Query (`@tanstack/react-query`) provider for future data fetching improvements

### Fixed
- DB schema mismatch: `proxy_logs` table now correctly declares `source_ip` and `unix_timestamp` columns matching actual INSERT usage
- Removed per-log-line `ALTER TABLE` hack that ran on every log entry parsed
- Password no longer re-hashed with bcrypt on every container restart (only when password actually changes)
- Removed duplicate `LoginRequest` model and legacy `/api/login` endpoint (dead code)
- Exception handlers restored to `except Exception` for catch-all safety (previous narrowing to `RuntimeError, ValueError, OSError` missed critical exception types)

### Changed
- WAF credentials: removed hardcoded `admin/admin` fallback; missing env vars now skip notification with a log warning
- Auth token storage migrated from `sessionStorage` to `localStorage` (tokens survive new browser tabs)
- Proxy `startup.sh` consolidated from 456 to 200 lines: deduplicated IP blocking rules into single `ensure_ip_blocking_rules()` function
- Proxy service now depends on WAF healthcheck (`service_healthy`) instead of simple service start
- WAF env vars (`BASIC_AUTH_USERNAME`, `BASIC_AUTH_PASSWORD`) passed through docker-compose

### Security
- WAF now inspects both URL and request body, closing a gap where POST-based attacks were invisible
- Removed insecure credential defaults from WAF notification system

## [1.2.0] - 2026-03-25

### Added
- High-performance Go ICAP WAF server replacing the legacy Python implementation, eliminating GIL bottlenecks and solving memory leak issues
- Strict client-side Zod validation in the React Settings page preventing malformed configurations
- Idempotency-Key header support for configuration mutation endpoints (`/api/settings`, `/api/maintenance/reload-config`, `/api/maintenance/clear-cache`) to prevent duplicate operations

### Changed
- Replaced broad `except Exception as e` blocks in backend Python scripts with specific exception handling (e.g. `sqlite3.Error`, `requests.exceptions.RequestException`, `OSError`)
- Migrated backend unit tests from Flask conventions to `fastapi.testclient.TestClient`

## [0.14.2] - 2026-03-25

### Added
- Playwright end-to-end test suite: 59 tests across auth, API, and all UI pages; runs in Docker via `docker-compose.test.yml`
- Bulk Add panel in Blacklists: paste multiple IPs or domains (one per line) via textarea, processed by `/api/blacklists/import`
- Proxy address copy banner on the Dashboard showing `host:3128` with a one-click copy button
- Configurable WebSocket backend port via `VITE_WS_BACKEND_PORT` build env or `window.__WS_BACKEND_PORT__` runtime override (default: 5001)

### Changed
- UI proxy layer replaced with Nginx serving compiled React static assets; JWT stored in `sessionStorage`, sent as `Authorization: Bearer` on all API calls
- Settings backup calls `GET /api/database/export`; removed the non-functional restore-config handler
- Backend API port 5001 now binds on all interfaces (required for browser WebSocket connections from LAN); firewall recommendation documented in `.env.example`
- `PROXY_CONTAINER_NAME` default corrected to `secure-proxy-manager-proxy` to match `container_name` in `docker-compose.yml`
- Removed `FLASK_ENV` environment variable (unused after UI proxy refactor)
- `.env.example` ships with empty credentials; services refuse to start if `BASIC_AUTH_USERNAME`/`BASIC_AUTH_PASSWORD` are unset or set to `admin`

### Fixed
- Blacklist entries not appearing after add: `useApi` hook returns the unwrapped array; component was double-unwrapping via `.data` property
- 401 interceptor reloading the page on wrong-password during login (should only reload on session expiry)
- GeoIP import URL and User-Agent header
- Geo-block multi-country support (TypeScript build error)
- Malwaredomains.com URL replaced with URLhaus (upstream offline)
- Import timeouts raised for large blocklist URLs

## [0.14.1] - 2026-03-25

### Added
- IP whitelist UI and backend CRUD (`/api/ip-whitelist`): IPs and CIDR networks that bypass Squid's direct-IP block rule
- Popular Lists one-click import for IP and domain blocklists (Firehol Level 1, Spamhaus DROP, Emerging Threats, StevenBlack, URLhaus, Phishing Army)
- Real-time log summary stat cards on the Logs page (total, success, blocked, error counts)
- VitePress documentation site deployed to GitHub Pages
- API end-to-end test suite (`tests/e2e_test.py`) configurable via env vars for CI

### Changed
- Squid `http_access allow ip_whitelist` rule now precedes `http_access deny direct_ip_*`
- `init.sh` warns on empty or `admin` credentials and exits before starting services

### Fixed
- Historical logs not persisting after page navigation
- Dashboard stat fields aligned to actual API response keys
- Blacklists page field names aligned to API response (`ip`, `added_date`)
- Settings page initialization converts the API array format to a key/value map
- Sidebar health indicator polls `/health` for real connected/disconnected state
- SQLi parameter binding, SSRF protection on import URLs, WAF memory leak, thread pool DoS protection, Squid de-escalated from root

## [0.14.0] - 2026-03-25

### Changed
- Complete backend rewrite from Flask to FastAPI with Uvicorn and SQLite WAL mode
- Frontend rewritten from Bootstrap/Jinja2 to React 18 + Vite + TypeScript + Tailwind CSS
- UI proxy layer (Flask) now only serves static React assets and reverse-proxies API/WebSocket traffic
- README project structure, API paths, env vars, and acknowledgements updated to match actual code

### Added
- WebSocket log streaming with one-time token authentication (`/api/ws-token` + `/api/ws/logs`)
- IP whitelist management UI and backend (`/api/ip-whitelist` CRUD) — bypass direct-IP block for trusted LAN IPs
- Geo-based IP blocklist import (`/api/blacklists/import-geo`)
- PDF analytics report export (`/api/analytics/report/pdf`)
- SIEM syslog forwarding with JSON formatter
- CORS origin restriction via `CORS_ALLOWED_ORIGINS` env var
- Rate limiting on authentication (5 attempts per 5 minutes, per IP)
- Real traffic timeline endpoint (`/api/logs/timeline`) powering the 24h dashboard chart
- Security score endpoint (`/api/security/score`)
- End-to-end API test suite (`tests/e2e_test.py`) configurable via env vars

### Fixed
- Squid `http_access allow ip_whitelist` rule now correctly precedes `http_access deny direct_ip_*` rules so whitelisted destination IPs are not blocked by the direct-IP block
- Dashboard stat fields aligned to actual API response keys (`total_count`, `blocked_count`, `ip_blocks_count`)
- Blacklists page field names aligned to API response (`ip`, `added_date` instead of `ip_address`, `created_at`)
- Settings page initialization now correctly converts the API's array format to a key/value map
- Sidebar API health indicator now polls `/health` and shows real connected/disconnected state
- Backend API port bound to `127.0.0.1:5001` only — no external exposure

### Security
- SSRF protection on import URLs using `ipaddress` module (blocks all private, loopback, link-local, reserved ranges)
- Database export redacts sensitive settings (tokens, webhook URLs, SIEM credentials)
- WebSocket endpoint requires a single-use token fetched through the authenticated HTTP proxy
- `cache/statistics` endpoint no longer returns fabricated numbers; returns `simulated: true` when Squid mgr interface is unavailable
- Replaced `admin:admin` defaults in all README curl examples with `YOUR_USER:YOUR_PASS` placeholders

## [1.0.0] - 2024-11-15

### Added
- Initial release of Secure Proxy Manager
- Squid-based proxy engine with advanced caching
- Flask-based backend API for proxy management
- Modern Bootstrap 5 web UI
- IP and domain blacklisting with CIDR and wildcard support
- Blacklist import functionality (URL and direct content)
- Support for multiple file formats (plain text, JSON)
- Real-time traffic monitoring and analytics
- Security scoring and assessment
- Rate limiting protection
- HTTPS filtering with SSL certificate management
- Comprehensive logging and analysis
- Configuration backup and restore
- Health check endpoints
- Docker containerization with docker-compose
- Role-based access control
- API documentation endpoint
- End-to-end testing suite

### Security
- Basic authentication for API endpoints
- Rate limiting to prevent brute force attacks
- Security headers on all responses
- SSL/TLS certificate validation
- Configurable content policies

## Version History Notes

### How to Use This Changelog

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security-related changes

### Contributing

When contributing, please update this changelog with your changes under the `[Unreleased]` section.
Follow the format above and be concise but descriptive.

[0.14.2]: https://github.com/fabriziosalmi/secure-proxy-manager/releases/tag/v0.14.2
[0.14.1]: https://github.com/fabriziosalmi/secure-proxy-manager/releases/tag/v0.14.1
[0.14.0]: https://github.com/fabriziosalmi/secure-proxy-manager/releases/tag/v0.14.0
[1.0.0]: https://github.com/fabriziosalmi/secure-proxy-manager/releases/tag/v1.0.0
