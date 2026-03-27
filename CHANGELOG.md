# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
