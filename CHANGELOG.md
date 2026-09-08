# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Reading this for API changes.** Anything that alters the HTTP surface — a
route removed, a response shape changed, a status code changed — appears under
a `### Removed` or `### Changed` heading with the phrase **BREAKING** and the
`X-API-Version` it corresponds to. Endpoint removals used to be recorded under
`### Fixed`, so a caller had to read every bullet of every release to find the
changes affecting it. Retired routes answer `410 Gone` naming their replacement
for at least one minor release before disappearing.

## [3.12.0] - 2026-09-08

Remediation of a full code-metrics audit of `19c3e90b`: 81 findings admitted,
81 closed (#261). Every security-relevant fix is mutation-verified — the
original bug restored, the test required to fail. This is a minor, not a patch:
three changes below need action on upgrade.

First release to send `X-API-Version: 1`. Releases up to 3.11.6 carried no
contract version, so the shape changes below are BREAKING relative to them.

### Action required when upgrading from 3.11.x

- **`INTERNAL_ALERT_TOKEN` must be set**, on both the `waf` and `backend`
  services. The shipped compose files no longer hand the WAF
  `BASIC_AUTH_USERNAME`/`PASSWORD`, so with no token the WAF cannot
  authenticate its block notifications and drops them, with a log line in both
  containers. `deploy/install.sh` generates one on a fresh install and appends
  one to an existing `.env` that predates the variable; set it by hand
  (`openssl rand -hex 32`) if you do not run the installer. The backend still
  accepts admin auth on that route when the token is unset, so a hand-written
  compose that still passes `BASIC_AUTH_*` to the WAF keeps working.
- **`GRAFANA_ADMIN_PASSWORD` must be set to use the `observability` profile.**
  Grafana now refuses to start without it instead of coming up on
  `admin`/`admin`. Only affects that profile; the rest of the stack is
  unaffected.
- **Requests that exceed the documented field limits are now rejected with
  400.** The `validate:` bounds on the request models were never enforced, so
  an over-long `description`, `domain` or import `url` was accepted and stored.
  A client sending values past those limits will start seeing 400s.

Two startup paths also became fatal that previously degraded silently: an
`ENCRYPTION_KEY` that is not exactly 32 bytes of hex, and a failure to export
the blacklists to `/config`. Both refuse to start and name the remedy.

### Security

- **The WAF no longer holds the admin credential.** It authenticates to
  `POST /api/internal/alert` with `INTERNAL_ALERT_TOKEN`, scoped to that one
  route and compared in constant time. The container that parses
  attacker-controlled request bodies previously carried
  `BASIC_AUTH_USERNAME`/`PASSWORD` — full control of the management API, over
  plain HTTP on the internal network. (SECURE-AUTH-02)
- **`./data` is no longer mounted into the WAF or the proxy.** It holds
  `.jwt_secret` (signs every session token), `.enc_key` (decrypts every stored
  notification credential) and the database. Reachable now only by the backend
  that owns it. (SECURE-SEC-01)
- **The login lockout is enforceable again.** nginx sent
  `$proxy_add_x_forwarded_for`, which prepends the client's own header, and the
  left-most entry was taken as the client address — so an attacker rotating
  `X-Forwarded-For` never accumulated failures under any key and
  `MAX_LOGIN_ATTEMPTS` did nothing. (SECURE-AUTH-01, SECURE-AUTH-03)
- **JWT revocation fails closed.** An unreadable revocation store was read as
  "nothing is revoked". Tokens issued before the process started are now
  refused while the store is unavailable; tokens issued since are known to this
  process and still work. `/api/logout` answers 500 when the revocation cannot
  be persisted, instead of 200 for a token that comes back after a restart.
  (SECURE-ERR-02, SECURE-ERR-03)
- **Grafana no longer ships with `admin`/`admin`** in the production compose
  file — the one `install.sh` deploys. (SECURE-CONF-05)
- **The proxy CA and the htpasswd file.** The CA is 825 days behind a
  `umask 077` rather than 3650 days with a world-readable key; the basic-auth
  password is hashed through `openssl passwd -6` on stdin instead of `htpasswd
  -bc`, which put it in `argv`. (SECURE-SEC-03/04/05)
- **`WAF_FAIL_OPEN` reaches the data plane.** It now derives the ICAP
  `bypass=` directive; previously the switch existed and changed nothing.
- A sensitive setting whose encryption fails is refused with a 500 rather than
  written in cleartext with a 200, and a value that fails to decrypt is
  returned empty with `decrypt_failed` rather than as raw `enc::` ciphertext
  that the next Save re-encrypted, destroying the secret. (SECURE-ERR-04,
  SECURE-ERR-06)

### Added

- `internal/validate` enforces the `validate:` struct tags — `required`,
  `omitempty`, `min`, `max`, `oneof` — at all 11 request-decode sites. Strings
  are measured in runes. No new dependency. (SECURE-DOM-02)
- **CI quality gates that are real:** `golangci-lint` on both Go modules with an
  explicit, justified exclusion list; `shellcheck`; a squid-config fixture suite
  that runs the real generator *and the real entrypoint* in the real image; a
  WAF coverage floor; and a check that the WAF heuristic key set stays identical
  across its 7 files. `gosec` no longer excludes G104. (SECURE-QUAL-01,
  SECURE-TEST-01)
- `scripts/restore.sh`, which verifies backup integrity **before** swapping.
  (SECURE-DATA-02)
- `X-API-Version` on every response, deliberately separate from the build
  version. (SECURE-API-03)
- Prometheus now measures the product's own outcome — requests allowed vs
  blocked — counted where every log line is already parsed. (SECURE-OBS-01)

### Changed

- **BREAKING** (`X-API-Version: 1`) — `GET /api/analytics/clients` returns the
  collection under `data`, not `data.clients`. Every list endpoint now goes
  through one helper: collection under `data`, pagination under `meta`. The
  top-level `total`/`limit`/`offset` are still emitted and marked deprecated,
  so the old pagination shape stays reachable for a release. (SECURE-API-02)
- **BREAKING** (`X-API-Version: 1`) — Backup Config exports a versioned
  envelope carrying the five lists (both blacklists, both whitelists, the
  egress allowlist) alongside the settings. It previously exported the settings
  table alone, so an operator who exported before a risky change and imported
  afterwards had restored only the toggles. The v1 import shape is still
  accepted. (SECURE-DATA-04)
- **BREAKING** (`X-API-Version: 1`) — 14 handlers stopped passing `err.Error()`
  into the contractual `detail` field, so a 500 no longer returns whatever the
  SQLite driver said. They return a stable detail plus a machine-readable code
  and log the cause. The 400s that echo the caller's own input keep their
  message. (SECURE-API-04)
- One name for the client address in a log record: `source_ip`, which the
  schema and the highest-volume insert already used. It was previously carried
  as `client_ip` in the WebSocket payload, `source_ip` in the DB insert and
  `ip_address` in the clients endpoint. (SECURE-DOM-08)
- Config reload is acknowledged rather than assumed. The watchdog writes back
  the trigger's own mtime and both return codes; the handler reports "success"
  only when the proxy applied it, an explicit error when it refused and kept
  the previous config, and "pending" when nothing answered. (SECURE-ARCH-02)
- `/api/docs` is walked from the live router instead of hand-maintained. The
  hand-written list had drifted to 63 entries against 81 routes, silently
  omitting the entire egress-allowlist resource and `POST /api/auth/refresh`.
  A test asserts the catalogue and the router agree. (SECURE-API-01)
- `generate_squid_conf.sh` is the sole producer of `squid.conf`. 407 of
  `startup.sh`'s 490 lines were a byte-identical copy of it, so every unguarded
  mutation ran twice and every security edit had to land in two files or the
  boot path and the reload path diverged — which they had. (SECURE-ARCH-01)
- `handleReqmod` is split into named inspection stages: CCN 48 → 13, 226 → 50
  NLOC, every extracted helper CCN ≤ 8. Verdicts pinned by a characterization
  suite before the split and byte-identical after. (SECURE-QUAL-02)

### Fixed

- **Log ingestion dropped records.** `bufio.Scanner` reads ahead, so seeking to
  the file position after an early break skipped every line already buffered —
  476 of 12,000 in a mutation test. Consumed bytes are now tracked explicitly.
- **Log ingestion could OOM the backend during recovery.** A tick's batch was
  sized by the backlog, so a backend down for an hour read every line since the
  saved offset into one slice against a 128M limit, was killed, and re-read the
  same backlog on restart. Batches are bounded and transactional, and the
  offset is persisted per batch. (SECURE-SCAL-02)
- **The blacklist export could publish a truncated ACL.** Every write to the
  enforcement path — exports and watchdog copies — is now atomic (temp file,
  fsync, rename, directory sync) and serialized. The startup export is fatal on
  failure: a proxy enforcing rules that no longer match the database must not
  start silently. (SECURE-DATA-01)
- **The squid config generator always exited 1**, because its last line is a
  `[ -f … ] && cp` whose short-circuit becomes the exit status. Shipped
  alongside the watchdog change that makes a non-zero return refuse to
  reconfigure, every config reload would have stopped reaching the proxy while
  the container reported healthy. Found by the new fixture suite.
- **The proxy container could come up with no squid and no watchdog.** The
  generator is sourced by `startup.sh`, and a bare `exit 0` in it terminated
  the entrypoint before the swap init and the supervisord hand-off. It now
  returns when sourced and exits when executed. The fixture suite runs the real
  entrypoint end to end.
- A lost update in the WAF heuristics: `getClientState` returned a pointer and
  released the mutex before the caller re-acquired it, so an eviction in the gap
  left the request writing state into an object nothing would read again. Both
  accesses were locked, so the race detector could never see it.
  (SECURE-CONC-04)
- Supervisord no longer gives up on squid or the watchdog after a finite retry
  count — it marked them FATAL and kept running as PID 1, so nothing recovered
  the container and a transient failure became permanent. (SECURE-REL-01)

### Removed

- `RestoreConfigRequest`, `SettingUpdate` and `SettingsBulkUpdate` from
  `internal/models`: unreferenced, and two of them described request shapes the
  API does not accept. They read as a contract and were not one.

## [3.11.6] - 2026-08-03

Pre-release hardening pass (360° audit round 1): accessibility, performance,
SEO, and polish. No functional/API changes.

### Added

- Docs "How it compares" table now lists **Zion** — the single-binary Rust TLS
  reverse-proxy + WAF that complements SPM (ingress vs egress). (#217)
- Docs site SEO: Open Graph / Twitter card meta, per-page canonical + `og:url`,
  a generated `sitemap.xml`, and `robots.txt`. (#215)

### Changed

- **Accessibility pass** across the UI: Clients rows are keyboard-operable via a
  real "Details" button (no invalid `role` on `<tr>`); the device-setup OS
  switcher is a proper ARIA tablist (roles, `aria-selected`/`-controls`, roving
  tabindex, arrow-key nav); form labels in Settings/Blacklists are associated via
  `id`/`htmlFor`; login errors announce with `role="alert"`; tag and icon-only
  controls get accessible names. (#215, #218)
- **Performance:** `IpBadge` reads the asset-tag map from a shared, parse-once
  store (`useSyncExternalStore`) and is memoized — removes up to ~200 synchronous
  `localStorage`/`JSON.parse` calls per streamed log line in the Logs table. (#215)
- Shared recharts tooltip style extracted to `lib/chart.ts`; App reuses the
  tested `isTokenExpired()` helper instead of an inline JWT decode. (#218)

### Fixed

- Guard a divide-by-zero in Threat Intel that could produce `NaN` bar
  widths/opacity when the top bucket had a zero count. (#215)
- Sanitize the backend-provided update URL before using it as a link `href`
  (allowlist `http`/`https`; unsafe values render as non-links). (#218)
- Clear copy-confirmation timers on unmount; surface real failures (auth/5xx/
  network) instead of silently treating every error as "already exists" in the
  Settings bulk domain-import buttons. (#218)
- Page headers wrap on narrow viewports (no horizontal overflow at 375px); the
  demo terminal SVG respects `prefers-reduced-motion` and its summary lines wrap
  instead of overrunning the canvas. (#215, #218)

## [3.11.5] - 2026-08-02

### Added

- **Docker Hub images.** The signed multi-arch images are now mirrored to Docker
  Hub alongside GHCR (gated on `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`), for
  easier discovery and `docker pull`.
- **Config-matrix plane** in the adversarial harness (Phase 5): flips a WAF
  rule-category setting through the real backend→WAF path and asserts the live
  data plane changes accordingly (a disabled category's attack passes; another
  still blocks; re-enable blocks again). The `make adversarial` suite is now five
  planes: block-matrix · API attacker · bench/latency · config-matrix · resilience.

### Changed

- **Docs / positioning.** README reframed as a **self-hosted Secure Web Gateway
  (SWG)** with an expanded comparison table, a "Tested like an attacker" section
  surfacing the adversarial harness (`WAF: 21 categories · FN=0 gated`), an
  animated demo, and a Support section. No application-code changes in the docs
  pass.

## [3.11.4] - 2026-08-02

### Added

- **Adversarial e2e harness** (`tests/adversarial/`, `make adversarial`) — drives
  attacker-style traffic against the running product in an isolated sandbox and
  gates on security regressions, as a new **Adversarial block-matrix (proxy +
  WAF)** CI job. Four planes: (1) data-plane **block-matrix** through the real
  forward proxy + WAF/ICAP (false-negative/positive gate), (2) **API attacker**
  against the backend auth boundary (auth-bypass, forged/tampered JWTs, login
  SQLi, rate-limit), (3) **bench/latency** (k6, proxied p95 + ICAP overhead), and
  (4) **resilience** (WAF fail-closed on loss + self-heal). (#200)
- **Correlation event-id in the proxy access log.** The WAF stamps
  `X-WAF-Event-Id` on the 403 it returns via ICAP; Squid's new `spm` logformat
  carries it as an 11th field, and it lands in a new `proxy_logs.event_id`
  column — so a blocked request in the Logs page / analytics joins end-to-end to
  its WAF traffic-log record and notification. (#107)

### Changed

- **WAF pre-filter (performance).** Before evaluating the ~170 RE2 rules, the WAF
  screens the input with an in-repo Aho-Corasick automaton over required-literal
  keywords derived programmatically from the patterns, skipping the rule set on
  benign traffic (~4.4× faster on benign input). Sound by construction — rules
  with no extractable required literal always run, verified by a 170/170
  rule-positive coverage test + a differential-equivalence fuzzer. (#110)

## [3.11.3] - 2026-08-02

### Changed

- **React Router upgraded v7 → v8** (`react-router@8.3.0`; the `react-router-dom`
  package is dropped in v8, so all imports move to `react-router`). This clears
  **GHSA-qwww-vcr4-c8h2** (RSC-mode CSRF, fixed in 8.3.0) — the last remaining
  entry in the CVE-audit allowlist. `scripts/npm-audit-allowlist.json` and
  `.trivyignore` are now empty: the `npm audit` + Trivy gates pass with **zero**
  standing exceptions.

### Also

- WAF heuristic toggles are now wired end-to-end (runtime, no container restart)
  — see [#102].

[#102]: https://github.com/fabriziosalmi/secure-proxy-manager/issues/102

## [3.11.2] - 2026-07-25

### Security

- **Logout / token-revocation bypass via alternate JWT spelling
  ([GHSA-j5fj-8wxc-gvmj], CWE-613, CVSS 6.3).** The revocation blacklist is keyed
  by the SHA-256 of the compact JWT string, but `golang-jwt` decodes Base64URL
  non-strictly by default: a token whose final signature character is swapped for
  an equivalent spelling (only unused bits differ) decodes to the same signature
  bytes — so it still validates — yet hashes to a different blacklist key. A
  holder of a valid token could therefore keep authenticating after logout, and
  defeat one-time refresh-token rotation, using an equivalent spelling. Fixed by
  pinning `jwt.WithStrictDecoding()` at all three parse sites (`ValidateJWT`,
  `ValidateRefreshToken`, `tokenExpiry`), so only the canonical spelling parses
  and the string↔token identity the blacklist relies on is restored. Adds an
  HTTP-level regression test. Reported under coordinated disclosure by a UC
  Berkeley security research project: Corban Villa, Sohee Kim, and Austin Chu.

[GHSA-j5fj-8wxc-gvmj]: https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/GHSA-j5fj-8wxc-gvmj

## [3.11.1] - 2026-06-29

### Fixed

- **Proxy 502 after the dns (or waf) container is recreated.** squid bakes the
  dnsmasq IP (`dns_nameservers`) and the WAF ICAP IP into its config at
  generation time; when those containers are recreated they get new IPs, leaving
  squid pointing at dead addresses — every request 502s (dns) or skips ICAP
  (waf) until the proxy is manually restarted. The in-container watchdog now
  tracks the resolved dns/waf IPs and, on drift, regenerates the squid config
  and reconfigures in place (self-healing within ~2s, no proxy restart). This
  surfaced live during the 3.11.0 dev deploy (a partial rebuild recreated dns
  but not the proxy). A full `compose up` after a full build was already safe via
  dependency ordering; this covers partial deploys and ad-hoc recreates too.

## [3.11.0] - 2026-06-29

Hardening sweep across CI/release rigor, UX correctness, deployment robustness,
and adoption — driven by a focused audit after the 3.10.3–3.10.5 deploy churn.

### Added

- **CI now catches the class of bug that shipped green.** The e2e smoke no longer
  `chmod -R a+rwX ./logs` (that masking hid the dns capability/permission bug);
  it owns `./logs` by a non-container UID so the real cap path is exercised. A
  new `validate-compose` job runs `docker compose config -q` on **both** the dev
  and the prod compose (the prod file install.sh ships was never parsed in CI). A
  new `version-sync` job (+ `scripts/check-version-sync.sh`) fails on version
  drift across version.go / package.json / package-lock.json / CHANGELOG.
- **WAF_DISABLED_CATEGORIES** is now passed to the waf service (it was read by
  waf-go but never wired into the container).

### Changed

- **dns healthcheck** resolves an external name through dnsmasq instead of
  `nslookup localhost`, so a broken upstream-forwarding path is detected.
- **install.sh**: backs up `./data` before an upgrade (DB-migration safety),
  smoke-tests the forward proxy and prints `docker compose ps` before declaring
  success, and generates a typeable admin password.
- Documented the proxy's intentional full-capability retention as a guardrail in
  both compose files (so a future "harden everything" change can't reproduce the
  dns bug on the data plane).
- Adoption: README badges + docs-site link + a "How it compares" table; a
  SECURITY.md "Verifying release images" (cosign/SBOM) section and refreshed
  Supported Versions; removed stale version strings.

### Fixed

- **WAF heuristic toggles (#102, UI part):** SetupWizard/Presets wrote
  `heuristic_*` keys while Settings used `waf_h_*`, so selections never
  round-tripped — unified on `waf_h_*` (matching the WAF's `WAF_H_*` env), and
  corrected the misleading "Proxy restarted" save copy.
- **React Query "data undefined" crash class:** all queryFns now unwrap the API
  envelope via shared `lib/api` helpers (null-coalescing) instead of raw
  `r.data.data`, which threw on an error/empty/304 response.
- Light-mode chart tooltip (was a hardcoded dark colour); mobile horizontal
  overflow on the Blacklists and Egress Allowlist tables; the Logs page
  cold-start copy ("waiting for traffic" instead of "no logs match your search");
  `.env.example` `TAILSCALE_AUTHKEY` → `TS_AUTHKEY` and a documented
  `PROXY_BIND_IP`; a bogus `#nosec G704` (→ G107) in the backend.

## [3.10.5] - 2026-06-29

### Fixed

- **DNS container still unhealthy on deploy (follow-up to 3.10.4).** The real
  cause was not the log file's owner but `cap_drop: ALL` on the dns service:
  without `CAP_DAC_OVERRIDE`, even root cannot create/write dnsmasq's query log
  on the shared `./logs` bind-mount (owned by the proxy's UID), so dnsmasq looped
  on `cannot open log …: Permission denied` and the container never went healthy.
  Add `CAP_DAC_OVERRIDE` to the dns service and run `dnsmasq --user=root` so it
  keeps that capability to write the log. Verified end-to-end against a
  restrictive bind-mount with the exact runtime caps (dnsmasq healthy, log
  written, no permission error). The proxy was unaffected because squid runs as
  the same UID that owns `./logs`.

## [3.10.4] - 2026-06-29

### Fixed

- **DNS container unhealthy on real deploys (regression in 3.10.3).** The
  docker-decouple pointed dnsmasq's query log at `/var/log/dnsmasq.log` on the
  shared `./logs` bind-mount so the backend DNS tailer could read it, but the
  unprivileged user dnsmasq drops to could not write the root-owned file and
  exited in a restart loop (`cannot open log …: Permission denied`). The log is
  now `chown`ed to the `dnsmasq` user and dnsmasq runs with `--user=dnsmasq`, so
  it works regardless of the host directory's ownership. (CI masked this by
  making `./logs` world-writable; real deploys do not.)

## [3.10.3] - 2026-06-29

### Added

- **DNS sinkhole tailer.** The backend now tails the dnsmasq log and records
  blocked DNS resolutions into `proxy_logs`, correlating each block back to the
  client that queried it. The query→client correlation cache is bounded (2-minute
  TTL + 8192-entry hard cap) so it can no longer grow unbounded over the process
  lifetime.

### Changed

- **Docker client decoupled from handlers/workers.** Blacklist reloads and the
  dnsmasq reload signal now go through a shared `.reload-dns` file instead of the
  Docker API, so the analytics/maintenance handlers and the blacklist-refresh
  worker no longer depend on a Docker socket.

### Performance

- **Analytics conditional GETs.** Read-heavy analytics endpoints now emit an
  `ETag` and honour `If-None-Match`, returning `304 Not Modified` for unchanged
  payloads on repeated dashboard polls.
- **Domain blacklist snapshot cache.** `DomainStats` caches the blacklist
  (30-second TTL) instead of reloading the whole `domain_blacklist` table on
  every request.

### Fixed

- **Login page logo.** The login screen showed a generic shield icon instead of
  the brand eye logo used by the favicon and the rest of the UI.
- **ClientSetup contrast in light mode.** The setup command block used hardcoded
  near-black/emerald colors; it is now theme-aware while keeping the dark
  terminal look in dark mode.

## [3.10.2] - 2026-06-28

### Changed

- **Theme & UI Decoupling.** Decoupled light, dark, and auto themes. Extracted theme state to a new ThemeProvider, resolved dark mode contrast issues, and added light mode support with dynamic glassmorphism and chart variables. Added theme selection widgets to the Sidebar and Settings.

## [3.10.1] - 2026-06-27

### Added

- **Settings quick-nav.** A full-width sticky chip bar under the Settings header
  jumps to each section (Proxy, Notifications, DNS & WAF, Access, Certificates,
  Security, Account) and highlights the active one as you scroll. Makes the long
  Settings page far quicker to navigate.

## [3.10.0] - 2026-06-27

### Added

- **Observability stack.** The backend now exposes Prometheus metrics at
  `/metrics` (internal network only — nginx does not proxy it): RED metrics per
  matched route (`spm_http_requests_total`, `spm_http_request_duration_seconds`,
  `spm_http_requests_in_flight`), database connection-pool gauges
  (`spm_db_connections_*`), per-worker heartbeats
  (`spm_worker_last_success_timestamp_seconds`), build info, plus the standard
  Go runtime/process collectors. A structured zerolog access log is emitted for
  every request. The WAF gains a REQMOD latency histogram
  (`waf_reqmod_duration_seconds`) so p50/p95/p99 are derivable. An **opt-in**
  `observability` Docker Compose profile ships Prometheus + Grafana (localhost
  -bound, auto-provisioned datasource): `docker compose --profile observability up -d`.
- **Real readiness probe.** New `/readyz` (+ `/livez`, `/api/ready`) that pings
  the database (`PingContext` + `SELECT 1`) and returns `503` when it is
  unreachable. The container healthcheck now probes readiness, not bare
  liveness, so a wedged/locked SQLite surfaces as an unhealthy container instead
  of a falsely healthy one.

### Changed

- **WAF anti-evasion normalization.** Inline SQL/HTML comments are stripped
  (replaced with a space, matching how the DB/HTML parser tokenizes), so
  `UNION/**/SELECT` and `<scr<!-- -->ipt>` are caught while non-keyword splits
  like `UN/**/ION` are not false-positived. Input is NFKC-folded so fullwidth /
  homoglyph keyword variants (`＜script＞`, `ＳＥＬＥＣＴ`) collapse to the ASCII the
  rules expect (pure-ASCII requests skip the fold via a fast path).
- WAF traffic feature log falls back to a writable tmpfs path when `/data` is
  read-only instead of silently becoming a no-op, and over-broad custom rules
  (matching the empty string or every benign sample) are rejected at load.

### Security

- **Egress default-deny now fails closed.** If the Squid deny-rule injection
  cannot be verified (anchor drift), startup retries with a tolerant anchor and,
  failing that, denies all localnet egress rather than silently reverting to
  default-allow.
- **WAF ICAP responses carry an `ISTag`** (RFC 3507), derived from a ruleset
  hash and bumped on category toggles, so Squid invalidates cached allow/block
  verdicts when rules change.
- **Refresh-token rotation replay race closed** via an atomic consume-once
  revoke; `RestoreConfig` and bulk settings updates are now transactional.
- JWT expiry for the revocation blacklist is read from a **signature-verified**
  token (was `ParseUnverified`), closing a CodeQL `go/missing-jwt-signature-check`
  finding.
- `iptables` PREROUTING redirect rules are made idempotent (no duplicates across
  restarts).
- New coverage-gap signals so detection holes are observable rather than silent:
  oversize request bodies (`waf_body_truncated_total` + a corroborating score),
  compressed/uninspectable responses (`waf_respmod_uninspectable_total`), and
  shed forensics/alerts (`waf_trafficlog_*`, `waf_notify_dropped_total`).
- Dependency bumps clearing HIGH advisories: `form-data` 4.0.6, `undici` 7.28.0,
  `vite` 8.1.0 (UI), and `golang.org/x/crypto` 0.53.0 / `golang.org/x/net`
  0.56.0 kept current in the Go modules.

### Tests

- SSRF/IP-safety kill-switch (`netguard`) raised from 0% to a full table-driven
  matrix; added tests for ISTag, readiness, the refresh-token race, the
  observability middleware, the WAF latency histogram, and the new normalization
  /evasion paths.

## [3.9.0] - 2026-06-15

### Added

- **Egress destination allowlist (default-deny mode).** Opt-in via a new
  "Default-deny egress" toggle in Settings: a client behind the proxy may then
  reach only the destinations on the new **Egress Allowlist** (CIDR/IP or
  domain); everything else is denied. This turns the forward proxy from
  default-allow-destination into default-deny-destination — the basis for a
  sovereign / data-residency egress. Includes a managed allowlist page, a REST
  API (`/api/egress-allowlist`), and Squid `dst`/`dstdomain` enforcement driven
  by the existing list + toggle plumbing. Off by default.

### Security

- Bump Go 1.24 → 1.26, clearing newly-disclosed Go standard-library advisories
  (net/http, net, crypto/x509, net/textproto) that have no 1.24 patch.
- Bump esbuild to 0.28.1 (devDependency), clearing a HIGH npm advisory
  (GHSA-gv7w-rqvm-qjhr; affects the dev server only, not the production build).

## [3.5.0] - 2026-06-04

### Added

- **Audit Log page (#82).** A paginated, filterable view of administrative
  actions — logins, blacklist and settings changes, maintenance — with
  per-action badges and CSV export, backed by the existing `/api/audit-log`.
  Backend audit coverage was widened to also record blacklist additions and
  settings changes.
- **Clients page (#83).** A sortable table of source IPs (requests, blocked,
  block rate, last seen) with a per-client drill-down drawer (top destinations
  with blocked counts, recent requests), backed by an enriched
  `/api/clients/statistics` and a new `GET /api/clients/{ip}/details` endpoint.
- **Service-status panel in Settings (#84).** Live proxy up/down, listen
  address, version, clients seen, 24h request/block counts and cache hit rate
  at the top of the page. The setting cards now flow into two columns on wide
  screens to cut the scrolling, and `/api/status` reports the configured
  `proxy_port` from the database instead of a hard-coded value.
- **End-to-end CI smoke job (#85).** A new `E2E (compose up + smoke)` job runs
  the whole stack with `docker compose up` and exercises the core path —
  service health, proxy egress, the blacklist watchdog, the Squid→backend log
  pipeline, and the audit log — so fresh-deploy breakage can no longer ship
  green. It is enforced as a required status check via branch protection.

### Changed

- **No movement on hovered data.** Table rows now highlight with colour only;
  the previous `transform: translateX(2px)` on `.row-hover`, which shifted
  every row under the cursor, was removed across the Logs, Blacklists, Clients
  and Audit tables.

## [3.4.6] - 2026-06-04

### Fixed

- **A fresh `docker compose up` now works end-to-end (#80).** Six bugs broke a
  clean deploy and none were caught by CI (which builds the images but never
  runs the stack): the backend could not write its bind-mounted volumes
  (SQLite `CANTOPEN` — it now runs as root like the sibling proxy/dns/waf
  containers, because su-exec/gosu privilege drop fails on Proxmox/unprivileged
  LXC); `dns` crash-looped on a missing `config/dnsmasq.d/` (now shipped via a
  `.gitkeep`); the proxy and dns had no internet egress (they sat only on an
  `internal: true` network — both are now also on `frontend`); the blacklist
  watchdog never started (it was generated at runtime — it is now shipped as
  `proxy/blacklist_watchdog.py` and registered statically in supervisord); and
  the dashboard / Logs page stayed empty because Squid's `0640` access.log was
  unreadable by the backend container (the watchdog now re-asserts `0644`).
- **WebSocket log-stream keep-alive (#79).** The server now sends protocol-level
  pings (browsers answer automatically), so the stream no longer dies roughly
  every 90 s and reconnects. Removed the dead client-side text `ping`/`pong`
  and corrected the WebSocket API docs (authentication failures are HTTP 401
  before the upgrade, not WebSocket close codes).

### Security

- **react-router `7.13.1` → `7.16.0` (#76)** clears five advisories, including a
  turbo-stream RCE (`GHSA-49rj-9fvp-4h2h`) and two XSS issues.
- **CI `npm audit` gate tightened from `critical` to `high` (#78)** so this
  class of advisory fails at PR time instead of shipping green.

## [3.4.5] - 2026-06-04

### Fixed

- **proxy: live blacklist reload** — added `blacklist_watchdog.py` (Python 3,
  runs under supervisord) that polls `/config/{ip,domain}_blacklist.txt` every
  2 s and calls `squid -k reconfigure` when either file changes.  Previously
  the backend updated the database and rewrote the config files but Squid only
  picked up the new rules on a container restart.
- **proxy: ssl_db ownership** — `chmod 700 /config/ssl_db` replaced by
  `chown proxy:proxy /config/ssl_db && chmod 750`.  The old mode blocked Squid
  (running as `proxy`) from writing dynamic certificates during SSL bump.
- **proxy: log world-readable** — added `chmod 755 /var/log/squid` so the
  backend container (different UID) can read `access.log` for real-time
  analytics without requiring a shared group.
- **backend-go: version bump** `3.4.4` → `3.4.5`.

## [3.4.4] - 2026-05-05

### Security

- **axios `^1.13.6` → `^1.16.0`** — patches 13 high-severity CVEs in the UI:
  prototype pollution, CRLF injection, header injection, `no_proxy` bypass
  SSRF, and authentication bypass. `follow-redirects` is now pinned to
  `^1.16.0` via override (auth-header leak on cross-domain redirects).
- **postcss `^8.5.8` → `^8.5.10`** — fixes XSS via an unescaped `</style>`
  sequence; applied as a dependency override in both `ui/` and `docs/`.
- **vite `^6.4.2`** — pinned via override in `docs/` (path-traversal in
  optimised-deps `.map` handling).

### Documentation

- **README and VitePress site audited end-to-end against the codebase.**
  Every numeric and structural claim was checked against `backend-go/`,
  `waf-go/`, `proxy/`, `dns/`, `ui/`, `docker-compose.yml`, and
  `.env.example`. 15 files updated, +882/-679 lines.
- **WAF counters corrected**: 175 regex rules across 23 categories
  (previously documented as 166/21) plus 7 behavioural heuristics and 3
  ML-lite checks (DGA, typosquatting, safe-URL cache).
- **Authentication coverage rewritten**: documented Basic and JWT bearer
  side-by-side; `/api/auth/login` returns access + refresh tokens; added
  reference entries for `/api/auth/refresh`, `/api/logout`, `/api/audit-log`,
  `/api/dns/detect`, `/api/notifications/test`, `/api/security/cve`,
  `/api/waf/categories[/toggle]`, `/api/waf/test-rule`, `/api/internal/alert`.
- **Removed non-existent endpoints** from the reference: `/api/security/scan`,
  `/api/maintenance/optimize-cache`, `/api/analytics/report/pdf` (the PDF
  report is wired in the UI but not yet ported to the Go backend; tracked
  in the roadmap).
- **Environment variables aligned with `docker-compose.yml`**:
  `REQUEST_TIMEOUT` default 120 (previously documented as 30);
  `CORS_ALLOWED_ORIGINS` default `https://localhost:8443` (previously
  `http://localhost:8011,http://web:8011`); dropped phantom
  `MAX_RETRIES`, `BACKOFF_FACTOR`, `RETRY_WAIT_AFTER_STARTUP`,
  `DATABASE_PATH`; added `SECRET_KEY`, `PROXY_BIND_IP`, `PROXY_IP`,
  `GUI_IP_WHITELIST`, `WAF_DISABLED_CATEGORIES`, `TS_AUTHKEY`,
  `TAILSCALE_HOSTNAME`, `LETSENCRYPT_*`.
- **Bulk settings endpoint body** corrected to a flat name → value object
  (the documentation previously claimed `{settings: [{name, value}, …]}`,
  which the handler never accepted).
- **Database export redaction**: documented that columns named `password`,
  `secret`, or `token` are redacted (the docs previously listed six
  hard-coded setting keys that did not match the implementation).
- **Custom Squid configuration path** corrected to
  `/config/custom_squid_extra.conf` (the legacy `custom_squid.conf` is
  migrated automatically by `proxy/startup.sh`).
- **Transparent-proxy iptables snippet** corrected: HTTPS (443) is now
  redirected to `3128`, not the typo'd `3129`.
- **Architecture page rebuilt** to match `docker-compose.yml`: service is
  named `web` (Nginx + compiled SPA, host ports `80`, `443`, `8011`,
  `8443`), backend is Go (chi router) bound to `127.0.0.1:5001`,
  `proxy-internal` network is declared `internal: true`.
- **Popular blocklist names** synchronised with the UI catalogue (Firehol
  Level 1, Spamhaus DROP/EDROP, Emerging Threats, CINS Army, Stamparm
  Ipsum, Blocklist.de, Talos; Aggregated Blacklist, StevenBlack Unified,
  URLhaus, Phishing Army, OISD Big, HaGeZi Multi Pro, NoTracking,
  DanPollock).
- **VitePress site hygiene**: off-topic `INTEGRATION_ARCHITECTURE.md`
  removed from the sidebar and excluded from the build via `srcExclude`;
  `cleanUrls` and `lastUpdated` enabled. `vitepress build` completes with
  zero errors.
- **README cleanup**: stray broken code block in the *Updating* section
  removed; removed the dead `backend/` (legacy Python) entry from the
  project-structure tree (the directory no longer exists).

### Build / housekeeping

- All builds pass: UI build, UI tests `127/127`, VitePress docs build.

## [3.4.3] - 2026-05-05

### Security

- **WAF LAN bypass fixed (CRITICAL)**: `isLANHost` previously used a naive
  `strings.HasPrefix(host, "172.2")` check, which incorrectly classified the
  entire `172.200.0.0/8` public range (and similar) as LAN — traffic to those
  IPs bypassed all WAF inspection. Replaced with `net.ParseIP` +
  `IsPrivate / IsLoopback / IsLinkLocal{Unicast,Multicast} / IsUnspecified`,
  with regression tests for `172.200.0.1`, `172.255.255.255`, `100.64.0.0/10`
  (CGNAT — must be inspected), `[::1]:port`, `fe80::`, and `fc00::`.
  Verified live: 5 forced requests to `172.200.0.1` increased WAF
  `total_requests` by 5 (previously 0); 3 SQLi probes returned HTTP 403.
- **JWT type confusion fixed (HIGH)**: `ValidateJWT` did not check
  `claims["type"]`, so a 7-day refresh token could authenticate every API
  call as if it were a short-lived access token. Refresh tokens are now
  rejected on the access path; the blacklist lookup also moved to AFTER
  signature validation to avoid leaking revocation state via timing.
- **WAF management endpoint OOM fixed (MEDIUM)**: `/categories/toggle`
  now bounds request body via `http.MaxBytesReader` (4 KB).
- **DNS auto-discovery SSRF guard (MEDIUM)**: `/api/dns/detect` now
  rejects user-supplied subnets outside RFC1918 / loopback (`8.8.8`,
  `100.64.0`, `169.254.169` → 400) and gates concurrent scans to 2.
- **Docker client URL escaping**: container name and signal parameters
  on `KillContainer` / `RestartContainer` / `ExecContainer` are now
  passed through `url.PathEscape` / `url.QueryEscape`.
- **WAF log injection neutralised**: log lines emitting attacker-
  controlled hosts, URLs, domains, and typo-target/technique fields now
  use the `%q` verb so embedded CR/LF/ANSI escape sequences cannot
  forge or pollute log entries.
- **Squid hardening**: positive method allowlist (`Safe_methods` =
  GET/HEAD/POST/OPTIONS/CONNECT) added on top of the existing
  dangerous-method denylist; outbound TLS now requires
  `NO_SSLv3,NO_TLSv1,NO_TLSv1_1` and a cipher suite mandating ECDHE
  forward secrecy + AEAD (AESGCM/CHACHA20).
- **Silent-error swallowing fixed**: `RevokeJWT` DB persistence,
  `loadOrGenerateEncKey`, and `loadOrGenerateSecret` no longer ignore
  write errors (silent failures here would have rotated the encryption
  key on every restart, making encrypted settings unrecoverable).

### Added

- **WAF Prometheus `/metrics` endpoint** — unauthenticated text-exposition
  emitting only aggregate counters: `waf_requests_total`, `waf_blocked_total`,
  `waf_high_entropy_total`, `waf_requests_last_minute`, `waf_rules_total`,
  `waf_categories_total`, `waf_categories_disabled`, `waf_block_threshold`,
  `waf_heuristics_enabled`, `waf_safe_cache_hits_total`,
  `waf_safe_cache_size`. No rule names, destinations, or User-Agents — leak
  surface ≤ existing `/health`.
- New tests: `TestValidateJWTRejectsRefreshToken`,
  `TestDNSDetectHandlers_Detect_RejectsPublicSubnet`, regression cases for
  `isLANHost` covering CGNAT and bracketed IPv6.

### Changed

- **Backend `extractIP`** now uses stdlib `net.IP.IsPrivate / IsLoopback`
  instead of a hand-maintained CIDR list; X-Forwarded-For trust boundary
  documented inline.
- **Backend blacklist import**: dedup cursor now surfaces query errors and
  checks `rows.Err()`; batch insert tracks per-statement failures and the
  response counters (`added` / `skipped`) reflect what actually landed in
  the DB.
- **`Makefile setup`** also creates `config/dnsmasq.d/` (without it the
  dns container hit a restart loop on first boot).

### Frontend

- **Dashboard reset blast radius**: `queryClient.invalidateQueries()` was
  invalidating every cached query (incl. settings/auth). Now scoped to
  the seven keys the reset actually touches.
- **Settings double-click guard**: synchronous `useRef` latch blocks the
  second `handleSave` call within the same tick (the `disabled` prop on
  the button only takes effect on the next render, allowing duplicate
  POSTs from a rapid double-click).
- **Settings race fixed**: wizard-status fetch in `App.tsx` now uses
  `AbortController` to defeat the StrictMode double-effect and the
  re-mount race where a stale `settings` response could overwrite a
  fresh one.
- **Blacklists post-unmount toasts fixed**: mutation `onSuccess` /
  `onError` callbacks check a `mountedRef` before touching state or
  firing toasts.
- **Recharts is now lazy-loaded**: extracted the dashboard chart cards
  into `components/dashboard/DashboardCharts.tsx`, lazy-imported with
  `React.lazy`. The `vendor-charts.js` chunk (~110 KB gzip) is no longer
  in the initial route bundle.
- **Login**: replaced the `localStorage.setItem` global monkey-patch
  with an exported `setAuthToken()` helper.
- **Accessibility**: `GlobalSearch` and `SetupWizard` modals gain
  `role="dialog"` + `aria-modal` + `aria-labelledby`; `ChangePassword`
  inputs gain `htmlFor`/`id` association, `aria-invalid`,
  `aria-describedby`, and live region for password rule feedback;
  spinner elements gain `role="status"` + sr-only "Loading…" text;
  `Blacklists` tabs now use `role="tablist"` / `role="tab"` /
  `role="tabpanel"` with proper `aria-selected` and roving tabindex;
  table headers in `Logs` and `Blacklists` gain `scope="col"`.

## [3.3.1] - 2026-04-08

### Fixed

- **Real cache statistics**: `GET /api/cache/statistics` now queries live Squid metrics via `squidclient mgr:info` (Docker exec) instead of returning hardcoded zeros
- **Cache clear works**: `POST /api/maintenance/clear-cache` uses `squid -k purge` via Docker exec instead of posting to a non-existent HTTP endpoint
- **Config generation no longer overridden**: `custom_squid.conf` auto-migrated to `custom_squid_extra.conf` (append-only); all cache/memory/performance settings from the UI are now applied
- **`aggressive_caching_enabled` toggle functional**: writes override-expire refresh patterns for static assets, packages, media files
- **`cache_bypass_domains` functional**: comma-separated domain list in Settings generates Squid ACL + `cache deny` rules
- **`enable_offline_mode` functional**: enables `offline_mode on` + aggressive stale serving
- **Duplicate refresh patterns removed**: single consistent set in generated squid.conf
- **Added `cachemgr_passwd`** directive so squidclient can access cache manager stats

### Added

- `ExecContainer` method in Docker client (full Docker API exec flow with stream mux header stripping)
- Settings handler writes toggle files + `cache_bypass_domains.txt` for Squid

## [3.3.0] - 2026-04-08

### Performance

- **SQLite WAL mode fix**: `modernc.org/sqlite` driver now correctly activates WAL mode (`_pragma=` syntax), eliminating `database is locked` errors
- **WebSocket/CORS origin fix**: IP-based access now works for WebSocket and CORS headers
- **DashboardSummary optimized**: 8 separate COUNT queries consolidated into single aggregate query
- **Bubble sort replaced**: `sort.Slice` in ShadowIT handler (O(n^2) to O(n log n))
- **CIDR networks pre-compiled**: rate limiter no longer parses 4 CIDR strings per request
- **Log tailer buffered**: `bufio.Scanner` replaces `io.ReadAll`, preventing unbounded memory usage
- **GDPR setting cached**: 30s TTL cache eliminates per-row database query
- **HTTP client pooling**: WAF/proxy clients reused instead of allocated per request
- **readAll optimized**: `bytes.Buffer` for efficient memory allocation
- **Import timestamp pre-formatted**: single format call instead of per-entry

### Frontend

- Reduced API polling: Dashboard 10s to 30s, ThreatIntel 15s to 30s, staleTime 10s to 60s
- Sidebar health check skips when tab is hidden, interval 15s to 30s

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
