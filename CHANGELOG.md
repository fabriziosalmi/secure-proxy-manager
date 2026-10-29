# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Reading this for API changes.** Anything that alters the HTTP surface (a
route removed, a response shape changed, a status code changed) appears under
a `### Removed` or `### Changed` heading with the phrase **BREAKING** and the
`X-API-Version` it corresponds to. Endpoint removals used to be recorded under
`### Fixed`, so a caller had to read every bullet of every release to find the
changes affecting it. Retired routes answer `410 Gone` naming their replacement
for at least one minor release before disappearing.

## [Unreleased]

### Fixed

- **Analytics counts the internal addresses of its own 7 days.** "Requests
  from N internal addresses are not counted" under the blocks-per-day chart
  counted every internal address ever logged, sinkhole (DNS) rows included,
  so it read 4 where the Clients page, over the same days, read 2.
  `GET /api/analytics/blocked-by-day` now returns in `internal_sources` the
  internal sources that sent client requests in the chart's 7 days (networks
  in GDPR mode), and the text says "in these 7 days". The Clients page no
  longer says its internal addresses are "not counted on the Overview", whose
  own figure covers 24 hours: they are not counted in any statistic.

## [3.18.3] - 2026-10-28

A fix release. The web UI keeps working when the backend container is
recreated on its own. Only the web image changes behaviour; the other images
change only their version. Nothing is **BREAKING** and `X-API-Version`
stays 1.

### Fixed

- **The web UI keeps working when the backend container is recreated on
  its own.** nginx resolved the backend name once at start: a backend that
  came back on a new address (`docker compose up -d backend`, a rebuild of
  that service alone) left every `/api` request answering 502 until `web`
  was restarted. Seen on the standing test host after the v3.18.2 update:
  nginx kept 172.18.0.2, the backend was on 172.18.0.3. The backend name is
  now resolved again every 10 seconds through the container's resolver. A
  `BACKEND_URL` with an address, or with a name only `/etc/hosts` holds, is
  resolved once at start as before.

## [3.18.2] - 2026-10-28

A fix release. With SafeSearch or YouTube Restricted Mode on, Google, Bing,
DuckDuckGo and YouTube load again through the proxy. Only the dns image
changes behaviour; the other images change only their version. Nothing is
**BREAKING** and `X-API-Version` stays 1. `SAFESEARCH_REFRESH_SECONDS` is a
new optional setting (default 3600).

### Fixed

- **With SafeSearch or YouTube Restricted Mode on, Google, Bing, DuckDuckGo
  and YouTube load again.** Both features were `cname=` overrides to hosts
  dnsmasq does not know locally, and dnsmasq follows a CNAME only to a local
  name: it answered `www.google.com` with the CNAME and no address, so the
  proxy could not connect (`TCP_TUNNEL/503` in 1 ms) for as long as the
  feature was on. The enforcement hosts are now resolved through the
  upstream resolvers when dnsmasq starts and declared with `host-record`.
  If a lookup fails, Google and YouTube use 216.239.38.120, the address
  Google documents, and Bing and DuckDuckGo are blocked (0.0.0.0) rather
  than left unfiltered, with a warning in the dns log. The hosts are
  resolved again every hour (`SAFESEARCH_REFRESH_SECONDS`), so a blocked
  target recovers and a moved CDN address is followed; dnsmasq restarts
  only when an address in use changed.

### Internal

- **A release image whose signature Docker Hub lists a few seconds late
  passes the signing step.** The first v3.18.2 build signed the dns image
  on Docker Hub at 21:18:02Z (an OCI referrer), `cosign verify` ran at
  21:18:04Z and found none, and the build failed; a rerun did the same with
  3 s between the two. `scripts/cosign-sign.sh` now checks up to 6 times, 10 s apart,
  before it fails the step, and signs only once.

- **A release image is signed again after a transient failure, and the job
  checks the signature is there.** v3.18.1's Docker Hub copy of the backend
  image has no signature: Rekor recorded cosign's first upload, its
  response was lost, cosign's own retry got 409 "an equivalent entry
  already exists", and the signature was never attached. The GHCR images,
  which the installer and the compose files use, are signed.
  `scripts/cosign-sign.sh` runs cosign afresh up to three times (a new run
  uses a new key, so it cannot collide with the last attempt) and then runs
  `cosign verify` with the identity in SECURITY.md, so the step fails only
  when no valid signature is attached.

## [3.18.1] - 2026-10-28

A security fix release. A request body of 64 KiB or more crossing the WAF
no longer fails, and can no longer stop the proxy for every client
([GHSA-9x87-g42q-5w3f](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/GHSA-9x87-g42q-5w3f)).
Only the WAF changes behaviour; the other images change only their
version. Nothing is **BREAKING** and `X-API-Version` stays 1.

Until you can upgrade, `icap_service_failure_limit -1` in
`config/custom_squid_extra.conf`, followed by a restart of the proxy
container, prevents the outage.

### Security

- **A request body of 64 KiB or more no longer fails, and can no longer
  stop the proxy for every client** (GHSA-9x87-g42q-5w3f). Squid offers the WAF a 204 ("no
  modification") only for a message it can keep a copy of; for a body of
  64 KiB or more it does not. The WAF answered 204 anyway, so Squid
  answered the client 500, and after eleven such requests suspended the
  ICAP service: with REQMOD fail-closed (the default) every request from
  every client got 500 for 180 seconds, repeatable by anyone who can use
  the proxy. The WAF now returns the message itself in a 200 when a 204 is
  not offered, with the whole body: it inspects at most the first 1 MiB,
  and before this it also forwarded only what it had read. Measured on
  Squid 7.7: before, 65,535 bytes passed and 65,536 got 500; after, bodies
  up to 2 MB pass and eleven 64 KiB uploads leave the service up. Until you
  upgrade, `icap_service_failure_limit -1` in
  `config/custom_squid_extra.conf` prevents the suspension. Inspecting a
  large body costs about 1 microsecond per byte (about 0.95 s for 1 MB),
  which these uploads now pay instead of failing.

### Internal

- E2E (production compose + smoke) is a required check on `main`, in the
  ruleset and in `.github/branch-protection.json`, so a change that breaks
  only the production compose can no longer merge.

## [3.18.0] - 2026-10-28

The WAF and the backend get their shared service token without any
configuration, the WAF's block alerts are retried, counted and delivered on
shutdown, a log rotation no longer drops lines, the web container stops
publishing `/api/internal/`, and the domain statistics show the status the
proxy enforces. Nothing is **BREAKING** and `X-API-Version` stays 1.

Three things change on upgrade. A boolean setting stored as anything other
than `"true"` or `"false"` (such as `"1"`) is now read as off everywhere,
including by the WAF reconciler, and the API refuses such a value with 400. A
`data/.enc_key` that is not 64 hex characters stops the backend instead of
being replaced. A deployment that keeps its own compose file, and leaves
`INTERNAL_ALERT_TOKEN` empty, needs the new `service-token` volume on the
backend (read-write) and the waf (read-only); with the variable set, nothing
changes.

### Changed

- **A boolean setting takes only `"true"` or `"false"`.** Every setting whose
  default is one of the two, and `wizard_completed`, now refuses any other
  value with 400 on `POST /api/settings` and `PUT /api/settings/{name}`, and a
  restore skips it with the reason. A value such as `"1"` used to be stored
  and read two ways: the WAF reconciler took it as on, the Settings page and
  every other reader as off, so a heuristic the page showed as off ran in the
  WAF. The reconciler now reads only `"true"` as on, like the others; a
  heuristic stored as `"1"` before this version is pushed to the WAF as off,
  which is what the page already showed.

- **`INTERNAL_ALERT_TOKEN` can be left empty.** The backend then generates the
  service token at first start into a new `service-token` volume, mounted
  read-write in the backend and read-only in the WAF and in no other service
  (`scripts/check-config-contract.sh` enforces this for both compose files),
  and the WAF reads it when it needs it. A manual install from `.env.example`
  used to start with the token empty: every WAF block alert was dropped and
  the WAF refused the backend's management calls, with only a warning. A
  value set in the environment still wins. A deployment that keeps its own
  compose file needs the volume on both services to use this.

### Fixed

- **A failed read of the dashboard's all-time counts is no longer served as
  zero for 25 seconds.** The query's error was discarded and the zeros it left
  were cached as the counts, so a busy database made the Overview show wrong
  totals to every tab. The previous counts are kept, the failure is logged,
  and the next request retries.
- **A damaged `data/.enc_key` stops the backend instead of being replaced.**
  A file that exists but is not 64 hex characters (a partial restore, a stray
  edit) was treated as missing: a new key was generated and written over it,
  destroying the only copy that could decrypt the stored alert credentials and
  the proxy password. The backend now exits with an error naming the file and
  what to do. A damaged `data/.jwt_secret`, which costs only the open
  sessions, is moved to `.jwt_secret.rejected-<time>` and replaced, with a log
  line.
- **The log tailers' read offset survives a power loss.** It was written with
  a plain write and rename and no fsync, so a crash could leave an empty
  `.pos` that reads back as 0 and re-ingests the whole access log as
  duplicate rows; anything left at the fixed temporary name also made every
  offset write fail. It is now written through the same fsync-and-rename path
  as the key files, and that path has tests of its own.

- **A log rotation no longer drops the lines the tailer had not read yet.**
  When Squid rotated `access.log` (daily, to `access.log.0`), the tailer saw
  a file shorter than its offset and started the new one from 0, so the unread
  end of the old file never reached `proxy_logs`: always the last moments
  before each rotation, and the whole backlog when the proxy logged faster
  than the 5,000 lines per 500 ms the tailer reads. It now reads the rest of
  `access.log.0` first, batch by batch, and keeps its offset to retry if that
  insert fails.

- **The web container no longer publishes `/api/internal/`.** nginx proxied
  every path under `/api/`, so `POST /api/internal/alert`, the WAF's
  service-to-service route, was reachable from anything that could reach the
  UI, guarded only by `INTERNAL_ALERT_TOKEN`. It now answers `404` there; the
  WAF keeps posting to `backend:5000` on the internal network.

- **A WAF alert the backend refuses or never answers is counted and, when it
  may succeed, retried.** It used to be one log line and no metric: with
  `INTERNAL_ALERT_TOKEN` set differently on the two services every block alert
  was lost while `waf_notify_dropped_total` stayed 0. Network errors and 5xx
  are now tried 3 times with a short backoff; every delivery that still fails
  is counted in `waf_notify_failed_total{reason}` (`network`, `rejected`,
  `server_error`, `no_credential`) and logged with its event ID.
- **The WAF delivers its queued alerts and flushes the traffic log on
  SIGTERM.** It had no signal handler, so every `docker compose` restart or
  upgrade lost up to 64 queued alerts and the unflushed tail of the traffic
  log. It now waits up to 5 seconds for the queue. ICAP transactions in flight
  at that moment are still cut, because the ICAP library has no graceful
  shutdown (#143).
- **The WAF's management port has timeouts.** `:8080` (health, metrics, the
  backend's management calls) ran with none, so idle connections could hold
  it; it now has read, write, header and idle timeouts.

- **The domain statistics show the status the proxy enforces, without loading
  the blocklist into memory.** `GET /api/domains/statistics` read every
  blocklist entry into a map every 30 seconds (measured 83.7 MiB for
  1,000,000 names, against the backend's 128 MB limit) and then compared it
  with the raw destination, a URL or `host:port`, which rarely matched: a
  blocked domain reached over CONNECT showed as Allowed unless a request to it
  had been blocked. Each of the 50 destinations is now looked up by its host,
  through the indexes, against the name the proxy enforces (exact name, the
  `*.` and `.` prefixes dropped, any case), and a name on the allowed list is
  not reported as blocked.
- **A response the WAF blocks now reaches the notifications and carries an
  event ID.** A blocked download (`application/x-msdownload`, a JAR, a
  shortcut) or a response leaking a private key or a token was answered with
  the 403 but with no `X-WAF-Event-Id` and no alert to the backend, so it sent
  no notification and could not be joined to its access log row. It now gets
  an event ID on the 403, a `RESPMOD BLOCKED` log line with the event ID, the
  client and the URL, and a `waf_block` notification with `source: RESPONSE`.
- **`waf_safe_cache_hits_total` and `waf_safe_cache_size` are exported.**
  The WAF's `/metrics` looked the two values up under keys the cache never
  returned, so neither line was ever written.

### Internal

- **CI starts the production compose.** A new job, E2E (production compose +
  smoke), builds the five images under the names
  `deploy/docker-compose.prod.yml` uses, tags them `:ci`, and runs the compose
  smoke through that file the way `deploy/install.sh` deploys it, with nothing
  pulled. Until now CI only validated the file (`docker compose config -q`)
  and ran the development compose, so a mistake only in the production file
  reached users untested. `tests/ci-e2e.sh` takes `E2E_PROD=1` and
  `SPM_IMAGE_TAG` for it.

- *Verify popular list URLs* checks every URL even when a host is slow. It ran
  under `set -e`, so the first curl timeout (exit 28) ended the step without
  checking the URLs after it, and the red job stopped merges that had nothing
  to do with the lists. `scripts/check-list-urls.sh` tries each URL up to three
  times (again only on no response, 429 or 5xx); a host that never answers is
  a warning, a status other than 200 is still a failure, and so is a run where
  no URL answered at all.

## [3.17.0] - 2026-10-28

Each access log row records the server address the proxy connected to, the
SQL the backend builds is a type a request value cannot reach, and the
third-party images the compose files pin move to tags that drop their fixable
findings. Nothing is **BREAKING** and `X-API-Version` stays 1.

On the first start the backend adds the nullable column `resolved_ip` to
`proxy_logs` (no index, no schema version change). Rows logged before the
upgrade read `null`. The CSV export gains `resolved_ip` as its last column.

### Added

- Each access log row records the server address the proxy connected to
  (`resolved_ip`, from the `%<a` field of the `spm` log format): in
  `GET /api/logs`, the live feed, a new last column of the CSV export, and
  the request details on the Logs page ("Server address"). It is `null` for a
  request that reached no server (a denied one) and for rows logged before.
  It is a server's address, so GDPR mode does not mask it. The column is
  added to `proxy_logs` without an index.

### Security

- **Grafana in the `observability` profile moves 13.2.4 to 13.3.0**, in both
  compose files. CVE-2026-116587 (go-jose v4.1.4, a denial of service when
  parsing JWKs with RSA keys) reached the Trivy database on 2026-10-28 and
  turned the compose-image scan red; 13.2.5 still carries it, 13.3.0 does not.
  The same move retires the grpc and kin-openapi findings of the Grafana
  binary, and Grafana's curl and brotli packages.

  The Trivy ignore file loses ten entries no pinned image needs any more: the
  seven Grafana 13.2.4 ones above, and three for tailscale v1.102.5 that have
  been dead since the pin moved to v1.104.1. An ignore nothing needs is one a
  regression could hide behind.

  Checked before the change: the compose Grafana service still refuses to start
  without `GRAFANA_ADMIN_PASSWORD`, reports 13.3.0 healthy, and provisions the
  Prometheus datasource read-only. The provisioning messages it logs are the
  same as on 13.2.4.
- **Prometheus moves v3.15.0 to v3.15.1 and tailscale v1.104.1 to v1.104.2**,
  each pinned by digest. Without the ignore file, Prometheus goes from four
  fixable HIGH/CRITICAL findings to none and tailscale from four to one
  (golang.org/x/net 0.59.0, no tag fixes it yet). The tailscale pin moves in
  `overlay/tailscale/Dockerfile` and the production compose together, as
  `scripts/check-image-pins.sh` requires. Prometheus v3.15.1 loads the same
  six alert rules as v3.15.0 with no error in its log.
- **The test and adversarial stacks serve their mocks from
  `nginx:1.31.8-alpine-slim`**, pinned by digest, instead of the unpinned
  `nginx:1.31.8-alpine`. The slim image ships neither curl nor brotli, so
  their two findings (curl 8.22.0-r0, brotli-libs 1.2.0-r1) and the two
  ignore entries for them are gone, the one expiring on 2026-11-15 among
  them. The mocks need no module the slim image lacks, and the health checks
  use busybox `wget`, which it has.

  The ignore file holds seven entries, all for Go modules or Alpine packages
  inside the Grafana 13.3.0 bundled plugins, k6 2.3.0 and tailscale
  v1.104.2, each the newest tag of its image.

### Internal

- SQL statement text is its own type, `database.SQLText` (#467). An untyped
  constant converts to it; a string variable does not compile, so a request
  value cannot reach the text of a query by mistake. `database.Placeholders`
  and `database.JoinSQL` are the only explicit conversions, and
  `TestNoValueCanReachSQLText` walks every Go file and fails on any other, or
  on a concatenation passed straight to `Query`, `QueryRow`, `Exec` or
  `Prepare`. The daily breakdown binds its day index instead of formatting it.
- slopless 1.18.1 runs in CI at error severity (#467). Every error it reported
  was checked and is a false positive; each of the 36 is marked in place with
  its reason, so a new one fails the job.

## [3.16.0] - 2026-10-28

Egress can follow the IP ranges a provider publishes, the dashboard session
moves to an HttpOnly cookie that no script in the page can read, and with
GDPR mode on client addresses are masked everywhere they leave the backend.
Two API changes are **BREAKING** under `X-API-Version: 1`: read the Upgrade
notes and Removed first.

### Upgrade notes

- **Take a backup first.** On the first start the backend runs schema
  versions 7 (creates `egress_providers` and `egress_provider_entries`) and 8
  (archives three retired settings into the Audit log and deletes them, see
  below), each once; `PRAGMA user_version` is 8 afterwards.
- **The dashboard signs in with an HttpOnly session cookie** (`spm_session`)
  instead of keeping the token in the browser's `localStorage`. Everyone
  signed in to the dashboard signs in once more after the upgrade; a token an
  earlier version left in `localStorage` is revoked and removed on the first
  load. API clients are unchanged: `POST /api/auth/login` without
  `X-SPM-Session: cookie` still returns `access_token` and `refresh_token`, and
  Basic and bearer authentication work as before. An external reverse proxy
  in front of the dashboard must pass the `Cookie` and `X-Requested-With`
  headers through (nginx and Caddy do by default).

- **The backend service joins the proxy group: `group_add: ["13"]`** in
  `docker-compose.yml` and `deploy/docker-compose.prod.yml`. A deployment that
  keeps its own compose file should add it to the backend service; without it
  the backend logs a warning on each proxy password change and new
  credentials get `407` until the proxy reloads, as before.

- **Schema version 8 archives and deletes `allowed_networks`, `waf_custom_rules`
  and `waf_block_threshold` from `settings`** (#444). If any of the three keys
  had a row in `settings`, the migration copies its previous value into the
  Audit log (`action = retire_setting_value`, `username = system`, `target` set
  to the key name, `details` holding `{"value": "..."}`, truncated at 64 KiB
  with `"truncated": true` when longer) before deleting the row. `retire_setting_value`
  rows follow the Audit log retention of 365 days (`AuditRetentionDays`), so
  values can be recovered from the Audit log for a year or from a database
  export at any time. `waf_custom_rules` in the database was never read by the
  WAF: active custom rules live in `/config/waf_custom_rules.txt`.

### Removed

- **BREAKING** (`X-API-Version: 1`): **the settings `allowed_networks`,
  `waf_custom_rules` and `waf_block_threshold`, which nothing in the backend,
  proxy or WAF read** (#444). Schema version 8 archives their values into
  `audit_log` (`retire_setting_value`) and deletes their rows; `POST
  /api/settings` skips them, `PUT /api/settings/{name}` answers 400, and
  `POST /api/maintenance/restore-config` lists them in `skipped_settings`.

### Added

- `scripts/local-ci.sh` runs the 26 required CI gates locally, including the
  Docker stack suites, Playwright and Trivy, and writes `results.txt` with
  one line per gate. It runs only in a linked git worktree, since the suites
  wipe `config/`, `data/` and `logs/` and rewrite `.env`
  (`SPM_LOCAL_CI_ALLOW_RESET=1` accepts a disposable clone), and holds a lock
  so two runs on one Docker host never collide; a lock left by a process that
  no longer runs is taken over. See `tests/README.md`.
- The global search (Cmd+K / Ctrl+K) also searches Allowed IPs, Allowed
  domains and the egress allowlist, and a result opens its own tab of
  Blacklists, or the Egress page, with the searched term in the filter. The
  "Domain blacklist" line of Analytics opens the Blocked domains tab.

- Managed egress destination provider lists (`GET /api/egress-providers`,
  `PUT /api/egress-providers/{name}`, `POST /api/egress-providers/url`,
  `DELETE /api/egress-providers/url/{id}`,
  `POST /api/egress-providers/{name}/refresh`,
  `POST /api/egress-providers/{name}/apply-held`) and the **Provider lists**
  section on the Egress allowlist page: operators can enable IPv4 and IPv6 CIDR
  ranges from a fixed 12-provider catalog (`amazon`, `cloudflare`,
  `digitalocean`, `facebook`, `github`, `google`, `linode`, `microsoft`,
  `oracle`, `telegram`, `twitter`, `vultr`, plus `all`) fetched at a pinned
  commit of `lord-alfred/ipranges`, or add custom CIDR list URLs.
  Shared-network providers require explicit confirmation (`confirm_shared:
  true`, with a confirmation dialog in the UI and a danger dialog showing the
  IPv4 space percentage for `all`). Updates are validated as a whole before
  replacing the previous list (rejecting malformed lines, prefixes wider than
  `/8` in IPv4 or `/16` in IPv6, any non-public range, or lists over 50,000
  entries), held for manual approval when covered addresses grow by more than
  25% or when a previously empty address family appears from zero while the
  other family already had entries, refreshed every
  `egress_provider_refresh_hours` hours (default 24, from 6 to 168, configurable
  under Settings, Filtering), recorded in the Audit log with commit SHA and
  counts, and exported into `dst_allow_ip.txt` as a deduplicated union without
  touching the manual egress allowlist.
- The `observability` profile starts: `infra/` holds the Prometheus
  configuration (scraping `backend:5000/metrics` and `waf:8080/metrics`), six
  alert rules in `infra/prometheus/rules/spm.rules.yml` and the Grafana
  Prometheus datasource. A CI job starts the profile and checks both.
- `GET /api/status` and `GET /api/security/cve` report `cves_checked`, false
  for a Squid major version the CVE list does not cover (the Squid 7 the image
  ships); the dashboard shows "Not checked for Squid 7.x" instead of a zero
  count.

### Changed

- **Dashboard sessions moved from `localStorage` to an HttpOnly cookie.**
  Script in the page, an injected one included, can no longer read the
  session token. The cookie is `SameSite=Strict`, `Path=/api`, `Secure` over
  https, and lasts `JWT_EXPIRE_DURATION`. A state-changing request
  authenticated by the cookie alone needs `X-Requested-With: spm` and a
  same-site `Origin`, or answers `403`. `GET /api/session` reports the session
  (`username`, `via`, `expires_at`), and logout and password changes clear or
  renew the cookie. CORS no longer names the dashboard's host over plain
  `http://`.

- The notification queue reads and decrypts the notification settings once
  for a burst of alerts instead of once per alert (measured: about 28 µs and
  119 allocations per read on an Apple M4, 31 ns for a cached one). A save
  through the API, a config restore or a database reset applies to the next
  alert; a change made outside the API reaches the queue within 2 seconds.

- The UI no longer shows the global "Failed to load data" toast on top of the
  error each page already reports in place. Signing in reads
  `GET /api/settings` once instead of twice, and the active Blacklists tab and
  the Egress page take the list count from the page they already download
  instead of a second `?limit=1` request. The sign-in screen, the setup wizard
  and the global search load as separate chunks: the entry chunk goes from
  76.3 kB to 35.7 kB (23.1 kB to 11.0 kB gzip). Unused CSS, components and the
  `zod` dependency are gone.
- The setup wizard writes only the settings it shows: it no longer sets
  `enable_proxy_auth`, `ssl_bump_enabled`, `enable_time_restrictions` and
  `enable_bandwidth_limits` to `false`.

- **BREAKING** (`X-API-Version: 1`): **with `gdpr_mode` on, client endpoints
  and log filters operate on `/24` (IPv4) and `/64` (IPv6) networks instead of
  single addresses** (#459). `GET /api/clients/statistics` and `top_clients` in
  `GET /api/dashboard/summary` aggregate rows by network (`ip_address` / `ip`
  masked as `192.168.1.x` or `2001:db8:1:2::x`, `network` CIDR, distinct
  `addresses` count, and `"mixed"` classification when a network mixes internal
  and external addresses); `GET /api/clients/{ip}/details` and the `source_ip`
  filter on `GET /api/logs` and `GET /api/logs/export` accept `/24` and `/64`
  CIDRs (both URL-encoded `%2F` and `/api/clients/{ip}/{prefix}/details`) and
  refuse single addresses with `400` while `gdpr_mode` is on; `GET
  /api/database/export` adds `"contains_unmasked_addresses": true` when
  `gdpr_mode` is on.
- The sign-in page, the setup wizard and the device setup panel use the design
  system the other pages use (tokens, shared buttons and notices, both
  themes); a test fails if a legacy colour or shadcn class returns under
  `ui/src`. The unused `IpBadge` and `Card` components are removed.
- `WAF_FAIL_OPEN` reaches the WAF as well as the proxy in both compose files,
  as their comment said; the config contract check fails if a shared variable
  is missing from either service.
- A new install stores a 2000 MB disk cache, the size Squid already used until
  the first save; an install that saved 1000 keeps 1000.

### Fixed

- Signing out with unsaved Settings changes asks first ("Sign out and lose 3
  unsaved changes?", naming the sections); before, the changes were dropped
  without a word.
- A database reset now clears the cached `gdpr_mode`, which kept its old
  value for up to 30 seconds after the reset emptied the settings.

- Proxy login: a changed proxy password works at once. The backend writes
  `proxy_users.htpasswd` with the proxy group (gid 13) itself, also on the
  file's first write, as a member of that group through `group_add` and with
  no capabilities added. Before, the file kept the backend's group until the
  proxy's generator reset it on the next reload, and Squid answered `407` to
  the new credentials in between. `scripts/check-config-contract.sh` fails if
  a compose file loses `group_add`, and the ACL matrix fails if the proxy
  image's `proxy` user moves off gid 13.

- Accessibility: the password reveal button sits inside the field and keeps
  one name ("Show password") with a pressed state; the expanded Search button's
  name matches its visible text; the sidebar is an `aside` landmark; the global
  search is a combobox with a listbox, `aria-activedescendant` and a spoken
  result count; tables keep a keyboard-focusable scroll box without repeating
  the name of the section around them as a second region.
- A settings refetch that fails after the first load (after a save, say) no
  longer replaces the whole UI with the "backend did not answer" screen and
  its unsaved drafts; a sign-in screen or wizard chunk that fails to load
  shows an error instead of a blank page.

- With `gdpr_mode` on, `GET /api/dashboard/summary` (`last_24h_clients` and
  `last_24h_internal_sources`) counts distinct `/24` and `/64` networks via
  `privacy.NetworkPrefix` instead of distinct unmasked IP addresses, as
  `GET /api/clients/statistics` already does (#459); `Clients`
  labels the search box (`Filter clients by network or IP address`) and lifetime
  detail note (`for this network`) for network rows, and `Logs` converts masked
  `192.168.1.x` and `2001:db8:1:2::x` addresses to `/24` and `/64` CIDRs (`Show
  this network's requests`) instead of hiding the filter action.
- `POST /api/maintenance/restore-config` no longer adds `restored_egress_providers`
  into `restored_entries`; `Maintenance` states in the Backup description that
  enabled egress providers and custom URLs are backed up without their downloaded
  entries, lists egress providers in the pre-restore confirmation and post-restore
  result (`8 list entries and 1 egress provider`), notes when provider lists are
  downloading in the background (`egress_providers_refreshing`), and invalidates
  the query cache after a restore; `egress_provider_refresh_hours` uses its own
  `provider_cycle` apply mode (`StartEgressProviderRefresh` sleeps for the full
  interval even when `egress_default_deny` is off), and `ChangePassword` uses
  sentence case on its field labels and submit button.
- First-run sign-in, setup wizard and client setup report what actually
  happened: `Login` distinguishes 401 (`Invalid username or password`), 429
  rate-limit responses (showing the backend's `detail`), 5xx or unreachable
  backend errors, and missing tokens, and adds a password reveal toggle (also
  added to Confirm New Password in Settings); `App` shows a retry notice instead
  of skipping the setup wizard when `GET /api/settings` fails on initial load;
  `SetupWizard` removes the misleading devices step, describes every setup and
  strictness option by the exact settings it enables without turning on
  bandwidth limits or `aggressive_caching_enabled`, invalidates the settings
  query cache after saving, and reports the real `applyToProxy()` outcome
  (`applied`, `pending`, `refused`, `failed`) referencing `Settings, Admin and
  backup, Reload the proxy`; `POST /api/maintenance/reload-config` answers 500
  (`code: trigger_write_failed`) instead of 200 `success` when `.reload-squid`
  cannot be written; `ClientSetup` awaits `navigator.clipboard.writeText` before
  reporting a copy, shows `Authentication: Username and password` on iOS when
  `enable_proxy_auth` is on, and removes the duplicate `Connect Your Devices`
  heading.
- `gdpr_mode` (Settings > Logs and privacy > Mask client IPs) masks client
  addresses everywhere they leave the backend: `GET /api/clients/statistics`,
  `GET /api/clients/{ip}/details`, `GET /api/dashboard/summary` (`top_clients`
  and `recent_blocks`), `GET /api/logs`, `GET /api/logs/export`, `/api/ws/logs`,
  the MCP server and outbound WAF alert notifications (formatted messages, raw
  webhooks and digests), instead of leaving full addresses in client statistics,
  the dashboard and alerts; IPv6 addresses are masked to their `/64` prefix
  (`2001:db8:1:2::x`) instead of only the last 16-bit group (#459).
- Squid serves distinct branded error pages for DNS lookup failures
  (`ERR_DNS_FAIL`), refused or unreachable destinations (`ERR_CONNECT_FAIL`),
  interrupted reads (`ERR_READ_ERROR`), socket creation failures
  (`ERR_SOCKET_FAILURE`), unreachable ICAP security inspection when
  `WAF_FAIL_OPEN=0` (`ERR_ICAP_FAILURE`), and every other Squid 7 error
  template, instead of showing "Access Denied" for network errors or stock
  Squid pages with `ERROR: loading file` lines in `cache.log`; the Access
  Denied page shows the client IP address instead of `"-"` (#443).
- `POST /api/database/reset` clears the tables in one transaction and answers
  500 naming the table that failed, instead of reporting success after errors;
  its own audit row is written after the wipe, so it is the first row of the
  new log.
- `GET /api/docs` is listed as requiring authentication, as it does.
- The installer's port check and its hint read `compose.prod.yml`, the file
  the production stack runs.

## [3.15.0] - 2026-10-25

The interface is rebuilt page by page on what the backend measures, every
request records the rule that blocked it, and the proxy no longer loads a
list the backend has not vouched for. `X-API-Version` stays 1; the changes to
the HTTP surface are marked **BREAKING** under Removed and Changed. Read
**Action worth knowing about on upgrade** first: four schema steps run once on
the first start and cannot be undone, and a blocklist that fails verification
at boot stops all traffic until a verified copy arrives.

### Security

- **Turning on the proxy login makes the proxy ask for credentials**
  (GHSA-g9jf-vq92-4vpp, medium). The configuration generator inserted the
  login rule only when `/config/proxy_users.htpasswd` existed, and created
  that file only from `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD`, which no
  shipped compose file passes to the proxy. With "Require proxy login" on, the
  generator logged that authentication was enabled and wrote a configuration
  without the rule, so every client on an allowed network kept using the proxy
  without logging in (from 3.4.1). The proxy login now has its own credentials,
  set in Settings, Clients and access, Login: `proxy_auth_username` and the
  write-only secret `proxy_auth_password`. The backend writes the password
  file itself, as bcrypt, and asks the proxy to reload; the proxy container
  never receives the dashboard's admin password. With the login on and no
  usable password file, the proxy refuses every client on the allowed networks
  with 403 and the block reason `proxy_auth_unset`, and the dashboard says so
  on the Overview and in the section. `/api/status` reports `proxy_auth` and
  `/api/analytics/coverage` `proxy_login_status`. After a change of
  credentials, Squid reads the new file within about 2 seconds; a client
  without cached credentials gets 407 in that window. The password file holds
  bcrypt hashes only and is readable, inside the stack, by the services that
  mount `config/`.
- The `web` image ships curl and libcurl 8.23.0-r0, fixing CVE-2026-92392
  (HTTP/2 upload use-after-free, HIGH), on a base image that still carries
  8.22.0-r0 (#452).

### Action worth knowing about on upgrade

- **An install that turned on the proxy login before 3.15.0 refuses every
  client until proxy credentials are set** (GHSA-g9jf-vq92-4vpp). The login
  was never enforced; after the upgrade it is, and without credentials the
  proxy fails closed. Set them in Settings, Clients and access, Login, then
  configure the devices with them. An install that passed `BASIC_AUTH_*` to
  the proxy by hand keeps its password file and keeps working.
- **Take a backup first; the migrations are not reversible.** On the first
  start the backend runs schema versions 3 to 6, each once, in one transaction
  that also records the version (`PRAGMA user_version` 6 afterwards, logged as
  `schema migrated` with the version). Rolling back to 3.14.x means restoring
  the backup taken before the upgrade. The steps:
  - **3** counts as blocked the requests the DNS sinkhole stopped before block
    reasons were recorded (#424): a row whose reason is `unclassified`, whose
    status ends in `/503`, that is a client request and not a DNS resolver
    row, whose host is a domain blacklist entry (`name` or `*.name`, in lower
    case) not excluded by the domain whitelist, and that was logged at or
    after the entry was added, becomes `blocked = 1` with the reason
    `domain_blacklist_dns_reconstructed` ("Domain blacklist (DNS),
    reconstructed"). Nothing else is reinterpreted. On 1,000,000 log rows and
    640,000 blacklisted domains the step took 27 to 31 s at the compose limits
    (measured for #424), so the first start takes that much longer.
  - **4** creates `list_sources` and gives the four IP and domain lists a
    `source_id` (#426). Entries from before the upgrade show "Source not
    recorded".
  - **5** rewrites egress allowlist entries stored as `*.name` to `.name`,
    which is what Squid can match; an entry whose `.name` form is already
    listed, and a bare `*.`, are removed instead. One audit row by `system`
    (`rewrite_egress_wildcards`) names them (#431).
  - **6** deletes the rows of the retired settings listed under Removed
    (#432).

  The log table also gains a `block_reason` column (existing rows read
  `unclassified` and keep their blocked flag) and the partial index
  `idx_proxy_logs_blocked_reason` (#419, #429).
- **A blocklist that fails manifest verification at boot denies every
  client** (#445). The proxy now copies the exported lists at boot through
  the watchdog's verified copy. If the IP or domain blacklist does not match
  `/config/lists.manifest.json`, or the manifest cannot be read, Squid has no
  copy to fall back to and every client request is denied (logged as
  `lists_unverified`, #446) until the watchdog copies a verified list; an
  allowlist without a verified copy starts empty. A backend that writes no
  manifest at all is still accepted, with a warning. Upgrade the backend and
  the proxy together.
- **Installs that set `WAF_H_*` in `.env` and never saved the heuristics in
  Settings** now have the compose defaults stored (all heuristics on except
  sequence validation), and the WAF reconciler pushes them to the WAF (#432).
  Set the heuristics under Settings, Inspection to keep values of your own.
- **`GET /api/logs`, its CSV export and the MCP tool `spm_recent_logs` leave
  the stack's own traffic out by default** (#429). Pass
  `include_internal=true` for the previous result. A `source_ip` that names an
  internal address is still answered.
- API callers that read notification secrets back from `GET /api/settings`
  now get no value (#425), and callers that write a retired setting with
  `PUT /api/settings/{name}` get 400 (#432). Tailscale is configured with
  `TS_AUTHKEY` in `.env`, as before.

### Removed

- **BREAKING** (`X-API-Version: 1`): `GET /api/security/score` answers
  `410 Gone` (#432). The score counted four settings that nothing enforced:
  `enable_ip_blacklist`, `enable_domain_blacklist`, `block_direct_ip` and
  `enable_waf`. Squid always denies the IP and domain blacklists and direct-IP
  URLs, and the WAF is always on the ICAP path, so a working install scored
  low and flipping a switch raised the score without changing anything. The
  MCP tool `spm_security_score` is removed with it.
- **BREAKING** (`X-API-Version: 1`): **the settings `enable_ip_blacklist`,
  `enable_domain_blacklist`, `enable_waf` and `block_direct_ip`, which nothing
  enforced, and `tailscale_enabled`, `tailscale_auth_key`,
  `tailscale_hostname`, `ddns_enabled`, `ddns_provider`, `ddns_domain`,
  `ddns_token` and `auth_method`, which nothing read** (#432). The Tailscale
  and DDNS tokens were stored in clear. Schema version 6 deletes their rows.
  `POST /api/settings` skips them as it skips the other keys it does not write
  (the rest of the request is saved), `PUT /api/settings/{name}` answers 400
  for them, and a restore lists them as not restored.
- The UI no longer depends on recharts (#430), and the README's four unused
  screenshots and `examples/test_import.sh`, which called retired endpoints,
  are gone (#437, #438).

### Added

- **Every request records the rule that decided it** (#419). Each Squid deny
  rule sets a reason that the access log carries, and a WAF block is marked
  by the WAF's own ICAP reply, which an upstream server cannot forge. Log
  rows carry `block_reason`; `blocked` is derived from it, so an origin
  server's own 403 is no longer counted as a block. The log statistics, the
  dashboard summary and the client detail report `blocked_by_reason`, and the
  Analytics breakdown groups by reason instead of guessing from the status
  code. The vocabulary is in `docs/design/block-reasons.md`. A request the
  fail-closed lists gate denies has its own reason, `lists_unverified`
  ("Lists not verified"), instead of `other` (#446).
- **Notification limits** (#439). Every WAF block and every failed sign-in
  used to become one alert to every channel, braked only by queue overflow,
  which drops at random: a scanner blocked 1,000 times sent 1,000 Telegram
  messages. The backend's notification queue now groups alerts by event type
  and client address: the first is sent at once, the rest within
  `notify_group_window_minutes` (default 10, 1 to 1440) are counted (WAF
  blocks by category) and one digest follows when the window ends
  (`event_type` `waf_block_digest` or `login_failure_digest`, with `count`,
  `window_minutes` and, for blocks, `category_counts`). Each channel sends at
  most `notify_max_per_hour` deliveries in any rolling hour (default 20,
  1 to 1000), digests included; past it the channel holds the rest and sends
  one `alerts_held_back` notice with the count once a slot of the hour frees.
  `notify_waf_block`, `notify_login_failure` and `notify_min_level`
  (`info`, `warning`, `error`) switch event types and low levels off. All
  five are seeded, validated by the backend and set under Settings, Alerts.
  The test alert is outside the limits. At most 10,000 addresses are grouped
  at a time. The counts are in memory: a graceful shutdown sends the pending
  digests and notices, a crash loses them.
  `spm_notifications_held_total{reason, channel}` counts what was held:
  `reason="cap"` on the channel that held it, `reason="grouped"` with
  `channel="all"`. The WAF is unchanged.
- **Where list entries came from** (#426). Every import, URL refresh,
  Popular list, manual add, geo-block, paste and restore records its source.
  `GET /api/{ip,domain}-{blacklist,whitelist}/sources` lists them,
  `DELETE .../sources/{id}` removes one source's entries and re-exports the
  lists, and `GET .../export` downloads a whole list.
  `GET /api/blacklists/enforcement` reports what enforces each list: the
  domain limit, what the allowed list removes, and the proxy's records of
  what Squid loaded (`domain_acl_status.json`, and the new
  `ip_blacklist_acl_status.json`).
- `POST /api/ip-whitelist/import` and `POST /api/domain-whitelist/import`
  check each pasted line as the single add does, in one transaction under one
  "Pasted list" source, and report added, skipped and refused with reasons
  (#436).
- `GET /api/logs` filters on the server (`source_ip`, `outcome`, `reason`,
  `q`, `include_internal`, `before_id`, `sort=id`); a malformed value answers
  400, `meta.total` counts the filtered rows and `meta.internal` the internal
  rows left out. Rows, live ones included, carry `reason_label`, `internal`
  and `kind`. `GET /api/logs/export` streams the same filters as CSV, with
  cells starting `=`, `+`, `-` or `@` written as text (#429).
- `GET /api/audit-logs?category=changes|signins` filters on the server and
  reports `meta.retention_days` (#431).
- `GET /api/analytics/blocked-by-day?tz=<IANA zone>` (calendar days in the
  viewer's zone, stacked by reason) and `GET /api/analytics/coverage` (what
  protection is in force, from the WAF and the proxy's own records) (#428).
- **The stack's own addresses are told apart from clients** (#422). An
  address is internal when it is loopback, one of the backend's own, or in a
  subnet of the backend's interfaces into which the proxy resolves; no range
  is hard-coded, so a LAN device in 172.16.0.0/12 stays a client.
  `/api/clients/statistics` rows carry `internal` and `kind` and
  `meta.internal` counts them; the summary gains `last_24h_internal_sources`
  and `last_24h_internal_requests`.
- The dashboard summary reports the last 24 hours (`last_24h_requests`,
  `last_24h_blocked`, `last_24h_clients`, `blocked_by_reason_24h`) and
  whether Squid holds its own copy of the domain blacklist
  (`squid_domain_acl`) (#421).
- `GET /api/waf/heuristics`: which heuristics the running WAF applies, or why
  the WAF could not be asked (#432).
- `POST /api/notifications/test` reports each channel's delivery
  (`data.channels`: channel, delivered, HTTP status, reason) and whether
  alerts are switched on (`data.notifications_enabled`). It tests every
  channel that has all of its settings stored, also while alerts are off
  (#432).
- `webhook_bearer_token`: an optional secret sent as
  `Authorization: Bearer <token>` with every webhook delivery, stored
  encrypted and never returned, like the other channel secrets (#432).
- `POST /api/settings` answers a refused request with every refused value in
  `errors` (`{key: message}`); `detail` still names the first. A save that
  carries WAF heuristics reports what the WAF did with each in `data.waf`
  (#432).
- The gauge `spm_db_integrity_ok`, a `startup step` log line with the duration
  of each start-up step, and `scripts/measure-backend-startup.sh`, which
  repeats the start-up measurement under the compose limits (#441).

### Changed

- **BREAKING** (`X-API-Version: 1`): **notification secrets are write-only**
  (#425). `GET /api/settings` returns no value for the nine channel secrets
  (`webhook_url`, `webhook_bearer_token`, `gotify_url`, `gotify_token`,
  `teams_webhook_url`, `telegram_bot_token`, `telegram_chat_id`, `ntfy_url`,
  `ntfy_topic`); each row carries `secret`, `is_set` and, when the stored
  value cannot be decrypted, `decrypt_failed`. `POST /api/settings` keeps a
  stored secret that arrives empty; `?clear=<key>` removes one. Before, a
  secret the backend could not decrypt came back empty and the next Save
  wiped it. `PUT /api/settings/{name}` with an empty value still clears it.
- **BREAKING** (`X-API-Version: 1`): **`GET /api/cache/statistics` reports
  what Squid measured** (#423). The statistics were never collected: the
  watchdog called `squidclient`, which is not in the image. The watchdog now
  reads Squid's cache manager on localhost once a minute (kept out of the
  access log and the WAF) and writes `/config/cache_stats.json`. The answer
  carries `state` (`current`, `stale` after three missed collections,
  `not_collected`, `unreadable`), `collected_at`, `age_s`, `interval_s`,
  `stale_after_s` and Squid's values, each `null` when Squid did not print it
  (the hit ratios for Squid's first minute). The previous fields stay for
  this release as deprecated aliases, but carry `null` where they carried 0:
  `hit_rate` and `byte_hit_rate` are the 5-minute ratios, `cache_size` and
  `max_cache_size` the disk figures as text, `objects_cached` the store
  entries, `simulated` is true whenever the values are not current, and
  `hits`, `misses` and `requests`, which were never measured, are always
  `null`. Each collection is one request Squid counts, as a miss.
- **BREAKING** (`X-API-Version: 1`), changed default: `GET /api/logs`, its
  CSV export and `spm_recent_logs` leave internal sources out unless
  `include_internal=true` (#429). See the upgrade notes.
- **BREAKING** (`X-API-Version: 1`): **Clear cache empties the disk cache and
  says what happened** (#435). `squid -k purge` is not a Squid command: it
  exited 1, the watchdog restarted Squid and every object on disk survived,
  while the API answered success as soon as it wrote the trigger. The
  watchdog now stops Squid, empties the `cache_dir` (only a disk cache under
  `/var/spool/squid`; anything else is refused before Squid is stopped),
  recreates it and always starts Squid again. `POST
  /api/maintenance/clear-cache` waits up to 45 s for the watchdog and answers
  200 `success` with `data.objects_removed`, 500 `clear_cache_failed` with
  `detail` and `data.step`, or 200 `pending` when the proxy did not answer in
  time; a trigger that cannot be written is a 500.
- **The interface is rebuilt on what the backend measures** (#415 to #422,
  #425, #428, #429, #431, #432, #437). Pages show "Not collected", "Not
  reported" or "Not available" instead of a zero nothing measured, counts use
  one format whatever the browser locale, and timestamps stored in UTC are
  shown in the viewer's zone.
  - New design tokens with contrast checked in both themes, shared
    components tested with axe-core, and a grouped sidebar (Overview,
    Traffic, Protection, System) that collapses to icons and becomes a drawer
    on narrow screens. Threat Intel becomes Analytics at `/analytics`;
    `/threats` redirects there.
  - Overview: the last 24 hours from the API, requests per hour, blocks by
    rule, the most blocked destinations and the latest blocks with their real
    reason, and only the notices the state calls for.
  - Clients: devices only, with the selected client detailed beside the
    table and a link to its requests.
  - Access logs: server-side filters, the stack's own traffic hidden unless
    asked for, CSV export, and "Allow this domain" on a reconstructed DNS
    block.
  - Analytics: blocks per day by rule, protection coverage in place of the
    score, and statistics that say what they count.
  - Blacklists: the source of every entry, what enforces each list, and
    Block DoH and the essential whitelist as tabs.
  - Egress allowlist and Audit log: what the list does right now, and every
    audit event written as a sentence.
  - Settings: one URL per section (`/settings/:section`, nine sections, the
    last one Appearance for the theme), one draft per section, a save that
    reports whether the proxy applied it, write-only secret fields, HTTPS
    inspection install steps per platform, and each action's result under
    its button. The sidebar shows the product's logo and a health line that
    names what is not running.
  - The README shows the current Overview and links a 30-second tour on the
    documentation site, regenerated by `scripts/demo/media.sh` from synthetic
    traffic.
- **Statistics count client requests.** Rows the DNS resolver logs for the
  proxy stay in the log but leave every count, a name looked up for A and
  AAAA is stored once (#419), and the stack's own addresses leave the
  Overview's counts, top lists and timeline (#422). `recent_blocks` covers
  the same 24 hours as the counts, and the all-time and today counts come
  from one snapshot, so today can no longer exceed all time (#421). The top
  destinations count `host:443` and `host` as one (#415). Shadow IT, service
  types and file types count clients only and read every host; service type
  matches the host, not the path, and file type reads the URL path instead
  of taking the top-level domain for an extension (#428).
- **A client asking for a sinkholed name gets the block page** (#419). Squid
  denies a destination that resolved to `0.0.0.0` or `::`, where the client
  used to see a connection error and the row counted as not blocked.
- The Squid access log line gains two fields at the end: the block reason
  and the WAF's `X-SPM-Reason` (#419). Anything parsing `access.log` must
  allow for them.
- The backend's proxy health probe opens and closes a connection instead of
  sending `GET` to Squid, and Squid logs only transactions that carry a
  request: the access log no longer gains a `NONE_NONE/400` row every 30
  seconds per open tab. `proxy_status` now means the port accepts
  connections (#429).
- **Every change to the blocked, allowed and egress lists writes an audit
  row** with its counts: single add and remove, bulk remove, clear-all, URL
  and Popular list import, pasted text, geo-block, source removal, restore,
  and one row per auto-refresh run by `system` (#431). Before, clearing
  640,929 domains left no row. A list URL is recorded without its user,
  password and credential-named query values. Removing an entry writes
  `remove_<list>` with the entry as target; rows written before as
  `delete_ip` or `delete_domain` with `id=N` are still read by the Audit page.
- A successful sign-in and a sign-out record the client address as the audit
  row's target, as a failed sign-in already did; the Audit page shows "From
  <address>", and "Address not recorded" for older rows (#433).
- `POST /api/egress-allowlist` and restore refuse `*.name`, which Squid
  matches against nothing, and name the `.name` form (#431).
- Notifications are no longer delivered to loopback, link-local, multicast
  or unspecified addresses, or into the networks the backend is attached to
  (the WAF, the proxy and the other containers of the stack). LAN, Tailscale
  and public addresses are delivered to as before. Redirects are not followed
  (#432).
- New validation in `POST /api/settings`: `cache_size` (1 to 9999999 MB) and
  `memory_cache` (1 to 999999 MB), the limits the proxy's generator reads;
  `auto_refresh_hours` (1 to 168); `blocked_file_types` (letters and digits);
  `cache_bypass_domains` (domain names); notification URLs (http or https, no
  credentials, not this host); the allowed-hours window must end after it
  starts; content filtering needs at least one extension (#432).
- Where no value is stored, the backend stores the defaults the services
  apply: the WAF heuristics as the shipped compose starts the WAF, the
  bandwidth and time values it writes when nothing is stored, and a blocked
  extension list (`exe,bat,cmd,dll,msi,scr,ps1,vbs`) so content filtering that
  is on blocks something. At startup the backend rewrites the blocked
  extensions and cache bypass files from the stored settings when they
  differ, and asks the proxy to reload. The setup wizard writes only settings
  something enforces, and no profile blocks `.js` (#432).
- **The backend checks the database in two stages** (#441). Before serving it
  runs `PRAGMA quick_check` (every page and constraint; a damaged page still
  stops the start), and 30 seconds after start it runs the full `PRAGMA
  integrity_check`, which also compares every index with its table, on a
  read-only connection of its own. A failure of the full check is logged as
  an error, sets `spm_db_integrity_ok` to 0 and makes `/readyz` answer 503,
  so the container reports unhealthy. Each SQLite connection's page cache is
  8 MB instead of 50 MB. On 1,000,000 log rows the start to the HTTP server
  went from 75 to 100 s to 13 to 19 s at the compose limit of 0.25 CPU.
- **Slow reconfigures are retried, not taken as applied** (#445). `squid -k
  parse` and `squid -k reconfigure` may take 40 s (they had 15 s and 10 s;
  Squid needs about 17 s to load 1,000,000 names at the compose limits). A
  reconfigure that times out stays pending and is retried on the next poll,
  and the reload trigger is not consumed.
- Squid is stopped with SIGINT: with SIGTERM it waited 30 s, past
  supervisord's 10 s, and every stop ended in SIGKILL. `docker stop` now
  closes requests in progress at once (#435).
- With GDPR mode on, the live log feed (`/api/ws/logs`) masks client
  addresses as `GET /api/logs` does; it carried the full address (#432).
- API messages, the WAF block alert, the proxy's log lines and the Squid
  error page title no longer contain em dashes (#445, #447).
- The documentation was checked claim by claim against the code and
  rewritten where it differed, with re-measured benchmarks (#438).

### Fixed

- **`/api/status` counts today's requests in the zone the logs are stored
  in.** It compared the UTC timestamps with the server's local date, so on a
  server east of UTC `requests_count` read 0 from local midnight to UTC
  midnight.
- **The content filter blocks `.EXE`, `.Exe` and a blocked extension
  followed by a query string** (#434). The ACL had no `-i`, and Squid matches
  the path with its query, so `/X.EXE` and `/x.exe?dl=1` passed. The pattern
  is now `\.exe(\?.*)?$`, matched without case; `/x.exe.txt?y=1` and
  `/get?f=a.exe&b=2` still pass. A file written by an older release is
  upgraded on the first start.
- **An allowed domain takes a blocked entry out however it is written**
  (#436). The exclusion compared stored strings, so an allowed `dot.example`
  did not remove a blocked `.dot.example`, `*.dot.example` or `Dot.Example`,
  which Squid and dnsmasq enforce as that name. One rule (lower case, no
  `*.` or leading dot) now drives the exclusion, the DNS hosts file and the
  counts.
- **A blocked domain written as `.name` is sinkholed**: dnsmasq did not
  answer for a hosts line `0.0.0.0 .name`; the hosts file now carries the
  name. `*.example.com` and `.example.com` each block `example.com` itself
  (#436).
- **Adding or removing an allowed IP or domain takes effect at once**: it did
  not export the lists, so it waited for the next blacklist change. Export
  downloads the whole list, not the 50 rows on screen (#426).
- **`PUT /api/settings/{name}` applies the setting as `POST /api/settings`
  does** (#442): it writes the marker file, list file or env file the proxy
  reads and pushes WAF heuristics to the running WAF. It wrote the database
  row only, so a toggle set this way (for example `egress_default_deny`)
  answered success and was not applied. A refused value still answers 400,
  and a secret named with an empty value is still cleared. The answer now
  carries `data`, and `status: "partial"` with `data.failed` when a proxy
  file could not be written.
- **The backend starts on a large database without being killed** (#441). On
  1,000,000 log rows and 640,000 blacklisted domains it was killed by the
  out-of-memory killer during start-up when the host had no swap, and
  restarted into the same loop: one 50 MB page cache costs about 110 MiB in
  this SQLite build, and the blacklist export held the 640,000 names in
  memory on top of it. Start-up now peaks at 31 MiB of anonymous memory. The
  export writes rows as it reads them, and a read error part way through
  fails the export instead of publishing a short list.
- **The proxy's configuration generator runs no Squid command** (#445).
  Three comments in its heredoc held commands in backticks, which the shell
  ran on every generation: three "FATAL: Unable to open configuration file"
  lines at boot, and on a running proxy a log rotation, a reconfigure on the
  old file and a second Squid on every regeneration. With 640,000 names the
  generator took 74 to 154 s; it now takes under a second.
- **The boot copy of the lists is verified against the backend's manifest**
  (#445). It was a plain `cp`, so a truncated export became the live list at
  boot, and every regeneration replaced the verified copy the watchdog had
  loaded. See the upgrade notes for the fail-closed gate.
- **The live log feed connects in a browser** (#418): the server selects the
  `spm.v1` subprotocol the UI offers, without which every browser failed the
  handshake.
- Restore writes the proxy's files as a Save does and reports the settings it
  applied and skipped, with reasons; it wrote the database only. Backup
  Config downloads the envelope Restore reads, not the database export
  (#425).
- `POST /api/settings` refuses a secret it cannot encrypt; it stored it in
  clear (#432).
- The Clients page and the Settings clients tile were always empty, the
  Blacklists tab counts read a deprecated field and showed 0, and charts
  drew three hourly points as a smooth curve (#415).
- The client detail drawer and the confirmation dialogs cover the whole
  window with an opaque panel, whatever page opens them (#416, #417).
- Global search sends `q` and `limit`, which the backend reads; it sent
  `search` and `page_size`, which were ignored (#429).
- An empty week in the analytics returns `[]` instead of `null` (#428).
- The documentation site builds again: the tour page wrote its asset paths
  with the site base already in them (#440).

### Internal

- `scripts/check-no-dashes.sh` gates `ui/src`, `docs/`, every Markdown file,
  the Squid error pages, `ui/index.html`, `ui/public` and `.env.example`
  (#415, #445, #447). A Go test in each module scans every non-test Go file
  token by token and fails on an em or en dash in a string literal (#448).
- The documentation workflow builds the site on pull requests that touch it
  (#440), and the web TLS check waits for the container's log line instead of
  reading the log once (#427).

## [3.14.3] - 2026-10-25

Fixes three defects found on a test deployment right after 3.14.2, two of
which stop the proxy. Nothing is required on upgrade and `X-API-Version` stays
1.

### Fixed

- **The proxy starts with any IP blacklist.** Squid warns once for every list
  entry another entry already covers (a single address inside a listed /24, for
  example) and aborts at startup once more than 1000 messages are queued before
  its log is open. A 50,772-entry import with 5,368 covered entries kept the
  proxy in a restart loop while the backend reported healthy; 3.14.1 fails the
  same way on the same data. The IP blacklist, the IP whitelist and the egress
  IP allowlist now reach Squid collapsed to the smallest set of networks that
  covers the same addresses, at boot and after every change. Lines that are not
  an address or a CIDR are dropped and counted in the proxy log.
- **Squid's own domain deny matches entries listed as `*.name`.** The backend
  stores wildcard entries in that form, which Squid read as a literal host name
  that never matches, so the deny added in 3.14.2 did nothing for them. Squid
  now holds the exact name, which is the name the DNS sinkhole blocks, and
  applies `SPM_SQUID_DOMAIN_ACL_MAX` to the names after removing duplicates.
- **HTTPS filtering (SSL-bump) no longer stops the proxy.** The certificate
  database was never created: the setup ran `security_file_certgen -c` on a
  directory it had just made, which the tool refuses ("Cannot create
  /config/ssl_db"), while the log said "initialized". With SSL-bump enabled,
  Squid then stopped ("sslcrtd_program helpers are crashing too rapidly"). The
  defect dates back to at least 3.10.3. The database is now created on the next
  start, and an existing one is kept.
- A default install no longer logs "ignoring EXTRA_SSL_PORTS" on every start:
  the empty default value was refused by the settings parser added in 3.14.2.
- The restore drill (`tests/shell/restore_test.sh`) no longer runs the host's
  real `docker compose`: it uses a stub and checks the whole swap.

### Changed

- The documentation site's toolchain pins vite 6.4.4, which closes five
  advisories in a development dependency that is not part of any image.
- The documentation and the GitHub Pages site were proofread for punctuation,
  and three README links that pointed at removed sections now point at real
  ones.
- The canary that keeps the project's test deployment on `main` waits for a
  healthy proxy before it probes, reports a probe host that is on the
  deployment's blacklist instead of blaming the WAF, and no longer replaces the
  exported blacklists with the repository's sample files when it updates.

## [3.14.2] - 2026-10-25

Security release. It fixes five advisories, two of them critical, found in a
full review of 3.14.1; upgrading is the remedy. `X-API-Version` stays 1. Read
**Action worth knowing about on upgrade** first: three fixes change what a
working deployment does.

### Security

- **Only LAN and listed sources may use the proxy, and every access restriction
  is evaluated before any allow** (GHSA-rwc6-g88c-xcxh, critical). The
  generated `http_access` rules allowed requests by destination before any rule
  looked at the client, so a client from any address could tunnel into the LAN
  on any safe port, and a hostname starting with `10.` or `192.168.` was
  forwarded to any public address. Proxy authentication, content filtering and
  time restrictions were written after `http_access deny all` and never
  evaluated; the IP blacklist blocked no destination; the cache manager was open
  to every client. A source gate now comes first, the restrictions are placed
  ahead of the allows, the IP blacklist is a destination rule, and the cache
  manager answers only localhost. The proxy authentication helper can now read
  its password file: it refused every credential, which nobody could see while
  the rule was never reached.
- **Nothing in a settings file runs as root, and a configuration that does not
  parse is never replaced by an unfiltered one** (GHSA-29vv-f64w-8x2c,
  critical, needs administrator access). The configuration generator sourced
  three settings files as root, and its check let `KEY=value command` through.
  The files are now parsed (known keys, one pattern per key, never executed),
  and the values are validated by the API, when the files are written, and on
  restore. At boot, a configuration that does not parse is regenerated once
  without the extras file, and the container exits if that does not parse
  either; it used to fall back to a base file with no DNS resolver, no egress
  default-deny, no SSL bump and no authentication, and stayed healthy. The
  watchdog replaces the live configuration only with one Squid has parsed.
- **A password change or logout ends the sessions it should**
  (GHSA-xxcf-crp3-prrj, high). Tokens are bound to the current password, so a
  password change ends every earlier session and returns a fresh pair to the
  caller. Refresh chains end seven days after the login they descend from.
  Logout revokes the access token on the server, and a refresh token passed in
  the body; the UI used to clear its token only in the browser. Two tokens issued in the same second are distinct. A failed login
  reserves its attempt before the password is checked: 40 concurrent guesses
  against a limit of 5 were all evaluated.
- **Unauthenticated clients can no longer grow backend memory or the audit
  log** (GHSA-2p9h-3hxh-292r, high). The HTTP metrics label was the raw request
  method, recorded before authentication: each invented method created a series
  that was never freed. It is folded to a fixed set. A locked-out address is
  audited and alerted once per lockout window, not once per request, and the
  audit log is pruned after a year. `/api/ws/` gets the request limit every
  other `/api/` path has.
- **A safe-cache hit in the WAF skips only the URL scan** (GHSA-xw5v-w568-j234,
  medium). After one clean GET, the same URL with a payload in an inspected
  header or in a GET body was returned clean with no inspection, no heuristics
  and no traffic-log entry. Headers, bodies and heuristics are now inspected on
  every request, only URLs whose whole request scored zero are cached, and the
  cache key hash has a per-process random seed.
- **The images are built with Go 1.27.3.** The 3.14.1 binaries were built with
  go1.27.1 and carried known standard-library vulnerabilities.
- **The web image carries the fixed libexpat, brotli-libs and libx11**, on nginx
  1.31.8. The proxy image no longer ships the unused `/usr/bin/pebble` binary
  from its base image.
- **Static assets carry the security headers.** JS, CSS and SVG were served
  without HSTS, nosniff, CSP or X-Frame-Options. `connect-src` is `'self'`
  instead of any WebSocket host, and the theme bootstrap is a file instead of an
  inline script the CSP blocked.
- **The audit CSV export writes cells starting with `=`, `+`, `-` or `@` as
  text.** A failed login stores any username, unauthenticated, and it became a
  live spreadsheet formula.
- **The MCP server (`spm-mcp` 0.2.0) is read-only unless
  `SPM_MCP_READONLY=false`**, and the traffic data it returns is marked as
  attacker-influenced. It is published to PyPI as `spm-mcp` by Trusted
  Publishing.

### Action worth knowing about on upgrade

- **Every user signs in once.** Tokens issued before 3.14.2 do not carry the
  password binding and are refused.
- **Proxy clients outside the private ranges must be listed.** The proxy accepts
  clients from 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 and
  fe80::/10. Any other client network, for example a Tailscale range
  (100.64.0.0/10), goes in `GUI_IP_WHITELIST`; until then it is refused.
- **Proxy authentication, time restrictions and content filtering now apply.**
  On 3.14.1 they were configurable but had no effect. If one of them is enabled,
  it starts restricting clients after the upgrade.
- A settings value that does not match its rule is ignored by the configuration
  generator with a warning in the proxy log, refused by the API, and skipped
  (with a warning) when a configuration backup is restored.

### Fixed

- **A domain added to the blacklist is refused at once, also for clients that
  visited it before.** Squid answered from its own DNS cache (up to six hours)
  and its HTTP cache, which the DNS sinkhole cannot reach. Squid's DNS cache is
  capped at one minute, and Squid denies blacklisted domains itself while the
  list has at most `SPM_SQUID_DOMAIN_ACL_MAX` entries (default 250,000; larger
  lists rely on the sinkhole alone, with a warning in the log).
- **The domain blacklist is capped at what dnsmasq can hold.** dnsmasq keeps
  every name in memory (about 195 MiB per million domains, measured), and the
  aggregated list Popular Lists offered got it killed for lack of memory, which
  left the proxy unable to resolve anything. `SPM_DNS_BLOCKLIST_MAX_DOMAINS`
  (default 1,000,000) bounds every path: an import that would exceed it is
  refused whole with 413, a single add at the limit is refused, the
  auto-refresh stops adding and logs it, a restore skips what does not fit.
- **Popular Lists offers only lists that load and answer.** The aggregated list
  is no longer offered; NoTracking (archived) and Talos (refuses non-browser
  clients) are removed; HaGeZi Multi Pro moves to its current URL; the URLhaus
  entry and the auto-refresh default use the malware-filter mirror, since
  abuse.ch answers 410 Gone to unauthenticated downloads.
- **The backend reaches the WAF management API.** The WAF answered 403 to the
  backend on every deployment of the shipped compose, so WAF statistics,
  category and heuristic toggles and the reconciler all failed silently. The
  backend now uses the shared service token, and the dashboard always shows its
  WAF cards and states why statistics are missing (`waf_status` in
  `/api/dashboard/summary`).
- **Bulk Add on a whitelist tab adds to the whitelist.** It wrote to the
  blacklist.
- **The web container starts when `LETSENCRYPT_DOMAIN` is set.** certbot is not
  in the image and the self-signed fallback never ran, so the container exited
  on every start. It now always starts with a certificate; the documentation
  describes the TLS options that exist.
- The live Logs feed no longer shows login events as blank rows, and the
  Dashboard no longer offers a PDF report that has no backend route.
- `scripts/restore.sh` says why it refuses a backup SQLite cannot open, instead
  of exiting silently.

### Changed

- **Releases are scanned before they are tagged.** Each image is pushed by
  digest, scanned for both architectures, and only then tagged and signed; a
  manual run is a dry run. `deploy/docker-compose.prod.yml` pins
  `${SPM_IMAGE_TAG:-v3.14.2}` instead of `:latest`, and `deploy/install.sh`
  verifies every image signature with cosign 3 when it is installed.
- Squid no longer adds an HSTS header to every proxied response.
- The documentation states what the code and the shipped compose do: container
  users and capabilities, ciphers, WAF rule counts (172 request rules, 5
  response rules, 6 heuristics), body inspection limits, and the reverse-proxy
  example (port 8443).

## [3.14.1] - 2026-09-30

UI-only. Nothing is required on upgrade and `X-API-Version` stays 1.

### Fixed

- **Search fields and icon-only buttons have an accessible name.** The filter and
  search inputs (Clients, Audit, Logs, Blacklists, the egress allowlist), the
  regex playground's period select and the copy buttons carry an `aria-label`; a
  placeholder is not a name. The mobile menu toggle also reports `aria-expanded`
  and controls the sidebar.
- **Small muted text is legible.** Text in the sidebar, the global search and the
  presets that was layered at 50-60% opacity now uses the solid muted colour.

### Changed

- `parseUtc` and `relative` (timestamps as "5m ago") exist once, in
  `ui/src/lib/utils.ts`, instead of being copied into two pages, and the change
  password form uses the shared password rule. No visible change.

## [3.14.0] - 2026-09-30

A sweep of the findings of a code-metrics audit, one category at a time. Nothing
is removed and `X-API-Version` stays 1. Read **Action worth knowing about on
upgrade** below (a one-time schema migration) and the **Changed** list for the
few behaviours that differ.

### Changed

- **The backend now vouches for the lists Squid enforces.** After writing the
  five exported lists (`ip_blacklist`, `ip_whitelist`, `domain_blacklist`,
  `dst_allow_ip`, `dst_allow_domain`) it writes `/config/lists.manifest.json`
  with a version and a sha256 per list. The proxy's watchdog hashes the bytes
  as it copies and publishes a list only if they match. On a mismatch, an
  unlisted file or an unreadable manifest it keeps the previous good list,
  retries, and logs `REFUSED` once per state. Before, a truncated list was
  copied verbatim and became the live blocklist with no signal. A backend
  that predates the manifest is still accepted, with one warning, so a
  mixed-version upgrade keeps working; the boot-time copy in
  `generate_squid_conf.sh` is not yet verified.
- The authentication handlers are given a small store (`database.AuthStore`)
  instead of the database handle. No behaviour change; the other handler groups
  still take the handle.

- **The WAF logs JSON.** Its records are structured (`log/slog`), one JSON object
  per line, like the backend's; `LOG_FORMAT=pretty` restores readable text for
  development. Anything parsing the old free-text WAF lines must be updated. The
  WAF also exposes `waf_build_info`, `waf_trafficlog_writable` and
  `waf_trafficlog_sink_dropped_total`.
- **The WAF says so when it rejects a setting.** A numeric or boolean environment
  value it cannot parse is logged and the default is used, where before it was
  dropped silently. Boolean values are now case-insensitive (`TRUE` works).
- **The backend reports a failed WAF reconciliation.** The reconciler that pushes
  the stored heuristic configuration to a restarted WAF now retries until it
  succeeds and exports `spm_waf_reconcile_total{outcome}` and
  `spm_waf_reconcile_last_success_timestamp_seconds`; the observability profile
  ships an alert, `SPMWafReconcileFailing`.
- **Notifications are delivered per channel.** Each configured channel has its own
  bounded queue and retries, so a slow or failing channel no longer delays the
  others; the failure log no longer prints the webhook URL. Queued alerts are
  drained on shutdown, and the WebSocket hub is closed after the workers stop.
- **The DNS log tailer caps its per-tick read**, as the Squid tailer already did,
  and both share one implementation.
- **Build and CI.** CI and the images build with Go 1.27 (the linters stay on
  1.26 until they can type-check 1.27); `scripts/check-image-pins.sh` fails when
  the Go, Playwright, tailscale or Squid pins drift, and the proxy image refuses
  to build with a Squid older than its floor. The WAF binary is built with
  `-trimpath` and carries its git commit.
- **Every function is now at or under cyclomatic complexity 15** (the worst was
  30). No intended behaviour change.

### Fixed

- **A domain entry could plant extra records in the DNS blocklist file.** The
  add endpoints refused a space but not a tab or a newline, and the restore
  endpoint checked nothing, so an authenticated caller (or a crafted backup) could
  store `x.test<newline>203.0.113.9<tab>update.example.com` and dnsmasq would
  answer `update.example.com` with that address for every client. Domain entries
  are now validated as DNS names at every entry point (add, import, restore and
  the automatic refresh), the exporters skip any row that contains whitespace or
  a control character, and the restore reports what it skipped as
  `skipped_entries`.

  What changes for you: a domain with a port (`example.com:8080`), a trailing
  dot, or any character outside letters, digits, hyphen, underscore and dot is
  now refused when added or imported, where before it was stored. A URL is still
  accepted and reduced to its hostname (the port is dropped). Entries already in
  your database are not removed; the exporter skips only the ones that could not
  be read back as a single line, and logs how many.

- **A failed dnsmasq write is reported.** The export used to succeed when only the
  dnsmasq blocklist could not be written; it now returns an error saying the
  Squid lists were written and the dnsmasq one was not.
- **A failed `COUNT` is an error, not a zero.** List and log endpoints no longer
  answer an empty total when the count query failed.
- **The WAF no longer latches its traffic log to `/dev/null`** after a transient
  failure: it retries and recovers, and reports the state as a metric.
- **The log feed in the UI never gives up reconnecting.** It backs off to 30 s and
  reconnects at once when the tab becomes visible or the network returns.
- **`restore.sh` refuses to restore a backup it cannot verify.** It needs
  `sqlite3` for the integrity check; pass `--skip-check` to restore without one.

### Action worth knowing about on upgrade

The database gains a schema version (`PRAGMA user_version`) and, on the first
start after upgrading, two tables are rebuilt once so that `dst_allowlist.type`
and `domain_whitelist.type` carry the same `CHECK` constraint a new database
already had. Existing databases could not receive it before, because SQLite
needs a table rebuild to add a constraint. **Take a backup first, as for any
upgrade;** the rebuild runs in one transaction and is not repeated.

It touches data only where a row already violated the constraint, and each case
is logged as a warning with a row count:

- **`dst_allowlist`:** a row whose `type` was neither `cidr` nor `domain` has its
  type re-derived from the entry (an address or CIDR becomes `cidr`, anything
  else `domain`). Such a row was listed in the UI but reached neither Squid
  file, so it now starts to take effect: an entry you believed was allowed, and
  which did nothing, will begin to allow that destination.
- **`domain_whitelist`:** a row whose `type` was anything other than `fqdn`
  (the old `url-regex` type) is **not carried over**. Nothing read those rows,
  so enforcement does not change, but they disappear from the list. Rows with no
  type become `fqdn`.

The exporter also refuses to write the lists if a `domain_whitelist` row with a
type other than `fqdn` is ever found, as it already did for `dst_allowlist`.

Nothing is required if neither table held such rows; the log line
`schema migrated` (version 2) confirms the migration ran.

## [3.13.2] - 2026-09-30

Two fixes in the UI, and a sweep of the container images the compose files
pin, which nothing had been watching, because Dependabot's docker ecosystem
reads Dockerfiles and Kubernetes YAML and never a compose file.

Nothing is required on upgrade and `X-API-Version` stays 1.

### Action worth taking if you run the observability profile

Grafana moves 11.4.0 to 13.2.3 and Prometheus v3.1.0 to v3.15.0. Both were
exercised before release: Prometheus loads all six alert rules across the
three groups, and Grafana comes up healthy and provisions the datasource
unchanged (`apiVersion: 1` is still accepted two majors later). Only the
`observability` profile is affected.

### Fixed

- **The blacklist import forms could be submitted twice.** `handleBulkAdd`,
  `handleImport` and `handleGeoBlock` had no pending state, so a second click
  sent a second POST and imported twice. The single-add form and the
  popular-list import already guarded themselves; these three did not.
- **Two-character strings that are not country codes reached the geo-import
  API.** The handler parsed inline with a length check only, so `12` and `A1`
  were accepted. It now uses `parseGeoCountries` from `lib/validation`, which
  also requires `/^[A-Z]{2}$/` and is covered by tests; the inline copy was a
  weaker reimplementation of a validator that already existed.
- **`sanitiseSort` returns the whitelist literal rather than the request
  parameter.** The two compare equal on that path, so behaviour is unchanged,
  but only one of them is a constant this codebase controls. The value is
  interpolated into a query, and keeping the caller's string alive that far is
  what a taint analyser follows; returning the literal makes the property
  provable instead of argued.

### Security

- **The images pinned in the compose files carried 462 fixable HIGH/CRITICAL
  findings between them; they now carry 14**, and the 14 are upstream's: Go
  modules vendored inside the Grafana and tailscale binaries, and Alpine
  packages not yet rebuilt.

  The one worth reading twice: `deploy/docker-compose.prod.yml` pulled
  `tailscale/tailscale:v1.80.3` while `overlay/tailscale/Dockerfile` was at
  v1.102.5. Twenty-two minor versions apart, 122 fixable findings against 5,
  and the file an operator deploys with was the one left behind, because
  Dependabot updates the Dockerfile and cannot see a compose file.

  `scripts/check-image-pins.sh` now fails when a version pinned in more than
  one place disagrees with itself, and a new CI step scans the compose-pinned
  images, deriving the list from the compose files so a later bump cannot
  leave it pointed at a version nobody runs.

### Internal

- CI runs on a daily schedule as well as on pull requests: `npm audit`,
  `govulncheck` and Trivy answer a question whose answer changes without a
  commit, and the default branch had gone eleven days without being evaluated.
- The Playwright image and `@playwright/test` are kept on one version; they
  had drifted three ways, which made every E2E test fail at 0ms: the suite
  never started.
- The UI test toolchain takes four major bumps (vitest 5, jsdom 30, jest-dom 7,
  @types/node 26) together with the Node version they require.

## [3.13.1] - 2026-09-30

A patch for one WAF bypass. `admin'--` in a **request body** scored 6 against a
threshold of 10 and passed, and a login form submits its credentials in a
body, so that was the realistic delivery of the payload rather than an exotic
one.

In a URL the same input blocked, because SQLi-018 paired with SQLi-015, which
sees the `%27` on the raw URL and adds 4. A body has no percent-encoded quote
to pair with. The rule's own comment had anticipated this and the conclusion
was never carried over.

### Fixed

- **SQLi-018 blocks a comment terminator on its own, in a body as well as a
  URL** (#266). Raising the severity alone would have been wrong: the old
  pattern `['"]\s*(?:--|#)` also matches a quote *opening* a literal that
  begins with dashes or a hash (`{"args":["--json"]}`, `"--brand-color"`,
  `"# heading"`), six of eight benign JSON and CSS samples, which is exactly
  why it could not carry a block. Requiring a word character or a closing
  paren before the quote separates the end of a quoted literal from the start
  of one: zero false positives on those samples, seven attack shapes matched.

  Three cases were added to the adversarial corpus: the two body payloads
  that used to pass, and the JSON-with-CLI-flags shape the old rule could not
  tell from an attack. The gap had been invisible precisely because the corpus
  that reports FN=0 for the WAF held no SQL-injection payload in a body at all.
  The suite now runs 41/41 with FN=0 and FP=0 across 22 categories.

### Documentation

- The published site carries Schema.org JSON-LD, an `llms.txt` in the
  llmstxt.org format, and `max-image-preview:large`. The last of these is a
  `<meta>` rather than a `robots.txt` directive on purpose: the site is a
  `*.github.io` project sub-path, and crawlers read `robots.txt` only from the
  domain root, which this repository does not own.

## [3.13.0] - 2026-09-09

Remediation of a full code-metrics audit of `1c81e762`, the 3.12.0 release
itself: 36 findings admitted, 36 closed (#303). Every security-relevant fix is
mutation-verified: the original defect restored, the test required to fail.

This is a minor, not a patch: a route that used to answer without credentials
now requires them, and an endpoint that could never report success now can.

`X-API-Version` stays `1`. No documented request or response shape changed;
the one contract change below is to a route the reference never listed as
public, and bumping the contract version would tell every client to re-verify
shapes that did not move.

### Action required when upgrading from 3.12.0

- **`GET /api/docs` now requires authentication.** **BREAKING** for any caller
  that fetched the route catalogue anonymously: it now answers `401`.
  `RegisterAPIDocs` accepted an auth middleware and never applied it, so the
  complete list of 80 routes, each with a flag naming which need no
  credentials, was served to anyone who could reach the API.
- **`POST /api/maintenance/reload-config` can now return `success`.** It could
  not before (see below). A caller that treated `pending` as the terminal
  outcome, or polled around it, should re-read `docs/api/settings.md`: the
  three outcomes and their blocking behaviour are documented there now.
- **The WAF's source layout moved.** Detection now lives in
  `waf-go/internal/engine`; `package main` is the ICAP transport. Nothing about
  the running service changes, but local patches against `waf-go/*.go` need to
  be re-applied against the new paths. The first restart after upgrading also
  publishes a new `ISTag`, so Squid drops its cached verdicts once.

### Fixed

- **`POST /api/maintenance/reload-config` could never return success.** The
  watchdog wrote `trigger_mtime` from `os.path.getmtime` (a float) and the
  backend decodes it into an `int64`, which Go's `encoding/json` refuses for
  every float form including `.0`. So every acknowledgement failed to parse,
  the handler spun for its full 8-second deadline, and only the `pending`
  branch was reachable. The stamp now comes from the trigger file's *content*,
  which the backend already writes as an integer. That removes the float, the
  filesystem timestamp granularity and any clock skew at once. The test that
  should have caught this built its fixture with `json.Marshal` from a Go
  `int64`; the regression guard now runs the real Python producer in the real
  image.
- **The watchdog dropped reload triggers.** It recorded the trigger's mtime
  *before* attempting the reload, so a reload that failed was never retried:
  the trigger looked handled. The mtime is now recorded only after the attempt.
- **A CIDR did not survive backup and restore.** The export omitted
  `dst_allowlist.type` and the restore inserted without it, so a CIDR came back
  classified as a domain and was written to the `dstdomain` ACL, where Squid can
  never match it. Under egress default-deny that is a destination the UI lists
  as allowed and the proxy refuses. The type is now re-derived on restore, and
  a `CHECK` constraint keeps the column to the two values the exporter
  understands.
- **The WAF missed `admin' OR '1'='1`.** The tautology rule's comparands were
  bare digits, so the canonical quoted form did not match. The corpus that
  reports FN=0 for the WAF contained exactly one SQL-injection case
  (`UNION SELECT`) and no tautology at all, so the gap was invisible to the
  suite that certifies the detection. Both are fixed: two rules added, four
  tautology cases added to the corpus.
- **The proxy healthcheck depended on the internet.** Its "cheap local probe"
  called `squidclient`, which is not in the image and is not packaged for
  Ubuntu 26.04, so every 15-second check fell through to proxying a request to
  an external host. Verified in an air-gapped container: the old check declared
  a healthy Squid dead. It now uses `ss` against the listening port.
- **Released binaries reported that they were not built by the release
  pipeline.** The release workflow never passed `GIT_SHA` to the image build, so
  `GitCommit` shipped as `unknown`. Confirmed against the published v3.12.0
  image.
- **The encryption key and the JWT secret were written non-atomically.** They
  were the only persisted state using a plain `os.WriteFile`: truncate in
  place, then write. A torn write there is answered by generating a *new* key,
  silently orphaning every stored credential. Both now go through the same
  create-temp/fsync/rename discipline the log-tailer offset already had.
- **The security-notification queue had no owner.** Its goroutine was never
  cancelled, waited for or drained, so alerts in flight were lost on shutdown.
  It is now tracked, cancellable and drained, and emits a heartbeat: zero
  notifications is a normal state, so silence could not previously be
  distinguished from a dead worker.
- **The WAF reported an unreadable custom-rules file as an absent one.**
  `/config` is a bind mount and the container runs read-only with dropped
  capabilities, so a permission problem is realistic, and it left an operator
  running with strictly less detection than they configured, told nothing
  distinguishable from having written no rules.

### Changed

- **The WAF's management credential is compared in constant time.** Both
  fields are always compared and the results combined with a bitwise AND, so
  the total does not reveal which one failed. This credential guards
  `/categories/toggle` (the route that can switch off SQL-injection
  inspection) on the internal bridge, where an attacker holding another
  container has a low-jitter path.
- **`POST /api/blacklists/import-geo` fetches concurrently.** Up to 50
  countries were fetched sequentially at a 30-second timeout each, inside a
  request bounded by a 60-second write timeout. Bounded at 8 in flight with a
  10-second per-feed timeout: measured 244 ms against 1.92 s for the sequential
  path.
- **Three units were refactored behind characterization suites** written
  against the pre-refactor code: `SettingsHandlers.BulkUpdate` (cyclomatic
  complexity 37 to 4), `BlacklistHandlers.Import` (41 to 8), and the WAF's flat
  package. Behaviour is unchanged and pinned.
- **The SSL-bump CA rotation procedure exists.** The code cited a documented
  procedure for the 825-day lifetime that had never been written.
  `DEPLOYMENT.md` now carries it, along with rotation for the other two keys,
  and its Updating section names the two env variables an upgrade needs.

### Added

- **Python is linted and tested in CI.** The proxy's enforcement-path sidecar
  had neither. `ruff.toml` selects beyond the default `E`/`F` (the default set
  passes on this repository, which would have made the gate decorative) and
  surfaced 19 real findings. Eight unit tests now cover the sidecar's failure
  branches.
- **A restore drill.** `scripts/restore.sh` was invoked by no test and no
  Makefile target. The drill proves it refuses a corrupt backup and that `data/`
  survives the refusal. `PRAGMA integrity_check` returns `ok` for corruption in
  headers and free space (verified directly), so the drill corrupts a data page
  and the script's message says "structural" rather than implying the backup is
  byte-perfect.
- **Prometheus alert rules**, six of them, shipped with the observability
  profile that previously ran a Prometheus with no rule files at all. Writing
  them produced the failure they exist to prevent: the first draft alerted on
  `outcome="failed"` while the code emits `"failure"`, so it would have been
  permanently inert. A test now asserts every metric name and label value used
  in the rules exists in the code.
- **Two consistency gates**: one comparing the five `/config` filenames across
  the three components that agree on them, one comparing the WAF heuristic key
  set across the seven files that enumerate it.
- **A worker heartbeat metric**, so a queue that is idle can be told apart from
  one that has died.

## [3.12.0] - 2026-09-08

Remediation of a full code-metrics audit of `19c3e90b`: 81 findings admitted,
81 closed (#261). Every security-relevant fix is mutation-verified: the
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
  `BASIC_AUTH_USERNAME`/`PASSWORD`: full control of the management API, over
  plain HTTP on the internal network. (SECURE-AUTH-02)
- **`./data` is no longer mounted into the WAF or the proxy.** It holds
  `.jwt_secret` (signs every session token), `.enc_key` (decrypts every stored
  notification credential) and the database. Reachable now only by the backend
  that owns it. (SECURE-SEC-01)
- **The login lockout is enforceable again.** nginx sent
  `$proxy_add_x_forwarded_for`, which prepends the client's own header, and the
  left-most entry was taken as the client address, so an attacker rotating
  `X-Forwarded-For` never accumulated failures under any key and
  `MAX_LOGIN_ATTEMPTS` did nothing. (SECURE-AUTH-01, SECURE-AUTH-03)
- **JWT revocation fails closed.** An unreadable revocation store was read as
  "nothing is revoked". Tokens issued before the process started are now
  refused while the store is unavailable; tokens issued since are known to this
  process and still work. `/api/logout` answers 500 when the revocation cannot
  be persisted, instead of 200 for a token that comes back after a restart.
  (SECURE-ERR-02, SECURE-ERR-03)
- **Grafana no longer ships with `admin`/`admin`** in the production compose
  file, the one `install.sh` deploys. (SECURE-CONF-05)
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

- `internal/validate` enforces the `validate:` struct tags (`required`,
  `omitempty`, `min`, `max`, `oneof`) at all 11 request-decode sites. Strings
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
- Prometheus now measures the product's own outcome, requests allowed vs
  blocked, counted where every log line is already parsed. (SECURE-OBS-01)

### Changed

- **BREAKING** (`X-API-Version: 1`): `GET /api/analytics/clients` returns the
  collection under `data`, not `data.clients`. Every list endpoint now goes
  through one helper: collection under `data`, pagination under `meta`. The
  top-level `total`/`limit`/`offset` are still emitted and marked deprecated,
  so the old pagination shape stays reachable for a release. (SECURE-API-02)
- **BREAKING** (`X-API-Version: 1`): Backup Config exports a versioned
  envelope carrying the five lists (both blacklists, both whitelists, the
  egress allowlist) alongside the settings. It previously exported the settings
  table alone, so an operator who exported before a risky change and imported
  afterwards had restored only the toggles. The v1 import shape is still
  accepted. (SECURE-DATA-04)
- **BREAKING** (`X-API-Version: 1`): 14 handlers stopped passing `err.Error()`
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
  boot path and the reload path diverged, which they had. (SECURE-ARCH-01)
- `handleReqmod` is split into named inspection stages: CCN 48 → 13, 226 → 50
  NLOC, every extracted helper CCN ≤ 8. Verdicts pinned by a characterization
  suite before the split and byte-identical after. (SECURE-QUAL-02)

### Fixed

- **Log ingestion dropped records.** `bufio.Scanner` reads ahead, so seeking to
  the file position after an early break skipped every line already buffered:
  476 of 12,000 in a mutation test. Consumed bytes are now tracked explicitly.
- **Log ingestion could OOM the backend during recovery.** A tick's batch was
  sized by the backlog, so a backend down for an hour read every line since the
  saved offset into one slice against a 128M limit, was killed, and re-read the
  same backlog on restart. Batches are bounded and transactional, and the
  offset is persisted per batch. (SECURE-SCAL-02)
- **The blacklist export could publish a truncated ACL.** Every write to the
  enforcement path, exports and watchdog copies, is now atomic (temp file,
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
  count: it marked them FATAL and kept running as PID 1, so nothing recovered
  the container and a transient failure became permanent. (SECURE-REL-01)

### Removed

- `RestoreConfigRequest`, `SettingUpdate` and `SettingsBulkUpdate` from
  `internal/models`: unreferenced, and two of them described request shapes the
  API does not accept. They read as a contract and were not one.

## [3.11.6] - 2026-08-03

Pre-release hardening pass (360° audit round 1): accessibility, performance,
SEO, and polish. No functional/API changes.

### Added

- Docs "How it compares" table now lists **Zion**, the single-binary Rust TLS
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
  store (`useSyncExternalStore`) and is memoized, which removes up to ~200 synchronous
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

- **Adversarial e2e harness** (`tests/adversarial/`, `make adversarial`): drives
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
  column, so a blocked request in the Logs page / analytics joins end-to-end to
  its WAF traffic-log record and notification. (#107)

### Changed

- **WAF pre-filter (performance).** Before evaluating the ~170 RE2 rules, the WAF
  screens the input with an in-repo Aho-Corasick automaton over required-literal
  keywords derived programmatically from the patterns, skipping the rule set on
  benign traffic (~4.4× faster on benign input). Sound by construction: rules
  with no extractable required literal always run, verified by a 170/170
  rule-positive coverage test + a differential-equivalence fuzzer. (#110)

## [3.11.3] - 2026-08-02

### Changed

- **React Router upgraded v7 → v8** (`react-router@8.3.0`; the `react-router-dom`
  package is dropped in v8, so all imports move to `react-router`). This clears
  **GHSA-qwww-vcr4-c8h2** (RSC-mode CSRF, fixed in 8.3.0), the last remaining
  entry in the CVE-audit allowlist. `scripts/npm-audit-allowlist.json` and
  `.trivyignore` are now empty: the `npm audit` + Trivy gates pass with **zero**
  standing exceptions.

### Also

- WAF heuristic toggles are now wired end-to-end (runtime, no container restart);
  see [#102].

[#102]: https://github.com/fabriziosalmi/secure-proxy-manager/issues/102

## [3.11.2] - 2026-07-25

### Security

- **Logout / token-revocation bypass via alternate JWT spelling
  ([GHSA-j5fj-8wxc-gvmj], CWE-613, CVSS 6.3).** The revocation blacklist is keyed
  by the SHA-256 of the compact JWT string, but `golang-jwt` decodes Base64URL
  non-strictly by default: a token whose final signature character is swapped for
  an equivalent spelling (only unused bits differ) decodes to the same signature
  bytes, so it still validates, yet hashes to a different blacklist key. A
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
  squid pointing at dead addresses: every request 502s (dns) or skips ICAP
  (waf) until the proxy is manually restarted. The in-container watchdog now
  tracks the resolved dns/waf IPs and, on drift, regenerates the squid config
  and reconfigures in place (self-healing within ~2s, no proxy restart). This
  surfaced live during the 3.11.0 dev deploy (a partial rebuild recreated dns
  but not the proxy). A full `compose up` after a full build was already safe via
  dependency ordering; this covers partial deploys and ad-hoc recreates too.

## [3.11.0] - 2026-06-29

Hardening sweep across CI/release rigor, UX correctness, deployment robustness,
and adoption, driven by a focused audit after the 3.10.3 to 3.10.5 deploy churn.

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
  round-tripped. Unified on `waf_h_*` (matching the WAF's `WAF_H_*` env), and
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
  `/metrics` (internal network only: nginx does not proxy it): RED metrics per
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
  default-allow-destination into default-deny-destination, the basis for a
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
  actions (logins, blacklist and settings changes, maintenance) with
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
  the whole stack with `docker compose up` and exercises the core path
  (service health, proxy egress, the blacklist watchdog, the Squid→backend log
  pipeline, and the audit log), so fresh-deploy breakage can no longer ship
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
  (SQLite `CANTOPEN`; it now runs as root like the sibling proxy/dns/waf
  containers, because su-exec/gosu privilege drop fails on Proxmox/unprivileged
  LXC); `dns` crash-looped on a missing `config/dnsmasq.d/` (now shipped via a
  `.gitkeep`); the proxy and dns had no internet egress (they sat only on an
  `internal: true` network; both are now also on `frontend`); the blacklist
  watchdog never started (it was generated at runtime; it is now shipped as
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

- **proxy: live blacklist reload**: added `blacklist_watchdog.py` (Python 3,
  runs under supervisord) that polls `/config/{ip,domain}_blacklist.txt` every
  2 s and calls `squid -k reconfigure` when either file changes.  Previously
  the backend updated the database and rewrote the config files but Squid only
  picked up the new rules on a container restart.
- **proxy: ssl_db ownership**: `chmod 700 /config/ssl_db` replaced by
  `chown proxy:proxy /config/ssl_db && chmod 750`.  The old mode blocked Squid
  (running as `proxy`) from writing dynamic certificates during SSL bump.
- **proxy: log world-readable**: added `chmod 755 /var/log/squid` so the
  backend container (different UID) can read `access.log` for real-time
  analytics without requiring a shared group.
- **backend-go: version bump** `3.4.4` → `3.4.5`.

## [3.4.4] - 2026-05-05

### Security

- **axios `^1.13.6` → `^1.16.0`**: patches 13 high-severity CVEs in the UI:
  prototype pollution, CRLF injection, header injection, `no_proxy` bypass
  SSRF, and authentication bypass. `follow-redirects` is now pinned to
  `^1.16.0` via override (auth-header leak on cross-domain redirects).
- **postcss `^8.5.8` → `^8.5.10`**: fixes XSS via an unescaped `</style>`
  sequence; applied as a dependency override in both `ui/` and `docs/`.
- **vite `^6.4.2`**: pinned via override in `docs/` (path-traversal in
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
  entire `172.200.0.0/8` public range (and similar) as LAN: traffic to those
  IPs bypassed all WAF inspection. Replaced with `net.ParseIP` +
  `IsPrivate / IsLoopback / IsLinkLocal{Unicast,Multicast} / IsUnspecified`,
  with regression tests for `172.200.0.1`, `172.255.255.255`, `100.64.0.0/10`
  (CGNAT: must be inspected), `[::1]:port`, `fe80::`, and `fc00::`.
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

- **WAF Prometheus `/metrics` endpoint**: unauthenticated text-exposition
  emitting only aggregate counters: `waf_requests_total`, `waf_blocked_total`,
  `waf_high_entropy_total`, `waf_requests_last_minute`, `waf_rules_total`,
  `waf_categories_total`, `waf_categories_disabled`, `waf_block_threshold`,
  `waf_heuristics_enabled`, `waf_safe_cache_hits_total`,
  `waf_safe_cache_size`. No rule names, destinations, or User-Agents. Leak
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

- **Glass morphism UI**: Full design system overhaul: `backdrop-blur` glass surfaces, animated number counters (rAF with ease-out cubic), staggered card entrance animations, progress bar glow effects with color-matched `box-shadow`, frosted ⌘K search modal, ambient login glow, custom 4px themed scrollbars, and gradient typography across all pages
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
- **AdminPasswordHash loaded from DB**: Previously missing; the bcrypt hash is now loaded at startup so auth uses it correctly

#### New Security Infrastructure
- **Global rate limiting**: Token bucket per-IP middleware (20 req/s sustained, 60 burst) on all endpoints, not just login
- **Circuit breaker**: WAF service calls protected against cascading failures (3 failures → open 30s → half-open probe)
- **Notification retry**: Failed webhook/Telegram/Gotify/ntfy deliveries retry 3x with exponential backoff (1s, 2s, 4s)
- **WebSocket origin validation**: `CheckOrigin` now validates against CORS allowlist instead of accepting all origins
- **CSP tightened**: Removed `unsafe-eval` from script-src, `*` from connect-src → `script-src 'self'; connect-src 'self' ws: wss:`
- **Self-signed cert reduced**: Validity 10 years → 1 year for better security hygiene

#### Performance & Reliability
- **3 new SQLite indexes**: `idx_proxy_logs_ts_ip`, `idx_proxy_logs_ts_dest`, `idx_proxy_logs_status`. Accelerates analytics queries on large DBs
- **Query LIMIT clauses**: UserAgents (50), FileExtensions (50000) prevent unbounded result sets
- **Worker graceful shutdown**: All 4 background workers now accept `context.Context` and stop cleanly on SIGTERM
- **pprof endpoint**: `/debug/pprof/*` routes (auth-protected) for production CPU/memory profiling

#### CI/CD Improvements
- **Backend unit tests in CI**: New job with race detector and 60% coverage threshold
- **gosec security scanning**: Automated vulnerability scanning for both backend-go and waf-go
- **npm audit**: Frontend dependency audit (high severity) in CI pipeline

### Added
- `backend-go/internal/crypto/`: AES-256-GCM encryption package with tests
- `backend-go/internal/middleware/ratelimit.go`: Per-IP token bucket rate limiter
- `backend-go/internal/middleware/circuitbreaker.go`: Circuit breaker (closed/open/half-open)
- `PLAN.md`: Comprehensive project analysis and action plan

### Changed
- `auth.go`: bcrypt-first password verification, JWT blacklist uses SHA-256 hashed keys
- `main.go`: Worker context propagation, pprof routes, WS origin check, DB hash loading
- `settings.go`: Transparent encrypt-on-write / decrypt-on-read for sensitive settings
- `security.go`: Notification retry with backoff, encrypted settings decryption
- `analytics.go`: Circuit breaker on WAF calls, LIMIT on queries
- `ci.yml`: 3 new jobs (backend tests, gosec, npm audit)
- `docker-entrypoint.sh`: Cert validity 3650 → 365 days
- `nginx.conf.template`: CSP aligned with backend middleware

## [3.0.0] - 2026-03-28

### Added: 17 New Features
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
- **API Documentation**: GET /api/docs, 60+ endpoints with descriptions
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
- IP whitelist management UI and backend (`/api/ip-whitelist` CRUD): bypass direct-IP block for trusted LAN IPs
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
- Backend API port bound to `127.0.0.1:5001` only: no external exposure

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
