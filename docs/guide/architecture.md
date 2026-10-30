# Architecture

Secure Proxy Manager is a Docker Compose application. Each service has one
job, and the services that enforce policy read it from files in the shared
`./config` directory.

## Services

```
                    Browser                       Proxy clients
                       |                                |
                       v                                v
+---------------------------------------+   +---------------------------+
| web     host 80, 443, 8011, 8443      |   | proxy   host 3128         |
| nginx: React build, /api/ and         |   | Squid + watchdog          |
| /api/ws/ proxied to backend:5000      |   | reads /config lists and   |
+-------------------+-------------------+   | toggle files              |
                    |                       +------+-------------+------+
                    v                              |             |
+---------------------------------------+   ICAP REQMOD     DNS queries
| backend   host 127.0.0.1:5001         |   and RESPMOD        |
| Go API, SQLite (WAL)                  |          |             v
| /data/proxy_manager.db                |          v      +--------------+
| writes /config, tails /logs           |   +-----------+ | dns          |
+---------------------------------------+   | waf :1344 | | dnsmasq :53  |
                                            | Go ICAP   | +--------------+
                                            +-----------+
```

Networks: `frontend` is a normal bridge with outbound access. `proxy-internal`
is declared `internal: true` (no route out). `backend`, `proxy` and `dns` are
on both; `waf` is on `proxy-internal` only; `web` is on `frontend` only.

### `web`: nginx

- Serves the compiled React app and proxies `/api/` and `/api/ws/` to the
  backend (`BACKEND_URL`, default `http://backend:5000`), except
  `/api/internal/`, which it answers with `404`: that route is for the WAF on
  the internal network. A backend name is resolved again every 10 seconds
  through the container's resolver, so a recreated backend on a new address
  is reached without restarting `web`; an address, or a name only
  `/etc/hosts` holds, is resolved once at start.
- Port 8011 redirects to `https://<host>:8443` except `/health`, `/wpad.dat`
  and `/.well-known/acme-challenge/`; port 8443 serves the UI with TLS 1.2 and
  1.3 and HSTS.
- At start it uses a certificate mounted at `/etc/nginx/ssl/server.crt` and
  `server.key`, or generates a self-signed one valid for 365 days. The image
  has no certbot, so `LETSENCRYPT_DOMAIN` does not obtain a certificate; the
  entrypoint logs that and falls back.
- nginx limits `/api/` to 20 requests per second per client address, with a
  burst of 40, and request bodies to 10 MB.

### `backend`: Go API

- Built from `backend-go/` with the chi router. It listens on port 5000; the
  host binding is `127.0.0.1:5001`.
- SQLite in WAL mode at `/data/proxy_manager.db` (`DATABASE_PATH`), with a
  pool of four connections and a 5 second busy timeout.
- Workers: the access-log tailer (`/logs/access.log`) and the dnsmasq log
  tailer, log retention (daily), the blocklist refresh, the list exporter, the
  WAF reconciler (pushes the stored heuristic settings to the WAF every 30
  seconds until it matches), the update checker (GitHub releases, every 6
  hours) and the Squid CVE check at start.
- It applies list changes by writing `/config/ip_blacklist.txt`,
  `ip_whitelist.txt`, `domain_blacklist.txt`, `dst_allow_ip.txt`,
  `dst_allow_domain.txt`, a checksum manifest `lists.manifest.json`, and the
  dnsmasq hosts file `dnsmasq.d/blocklist.hosts`, each written to a temporary
  file and renamed. At start it exports the lists before it serves, so the
  files match the database.
- Settings that the proxy reads become marker files (for example
  `/config/egress_default_deny`, `/config/ssl_bump_enabled`) and small env
  files, written when settings are saved through `POST /api/settings` or
  restored.
- Probes: `/livez` and `/health` (process up), `/readyz` and `/api/ready`
  (database answers within 2 seconds, otherwise `503`). The container
  healthcheck runs `/server -healthcheck`, which calls `/readyz`.
- Alerts: WAF blocks (the WAF posts them to `/api/internal/alert`) and failed
  sign-ins go through one queue to the configured channels (webhook, Telegram,
  Gotify, ntfy, Teams). The queue groups alerts of one type from one address
  for `notify_group_window_minutes` (the first is sent, the rest are counted
  into one digest) and lets each channel send at most `notify_max_per_hour`
  in any hour, then one notice with the count it held
  ([Settings API: notification limits](../api/settings.md#notification-limits)).
  The counts are in memory: a graceful shutdown sends what is pending, a
  crash loses it.
- Prometheus metrics at `/metrics` on port 5000, not proxied by nginx.

### `proxy`: Squid

- `proxy/generate_squid_conf.sh` is the **sole producer** of `squid.conf`. `proxy/startup.sh`
  sources it at boot, checks the result with `squid -k parse`, initialises the
  cache and starts supervisord. If the configuration does not parse, it
  regenerates once without `/config/custom_squid_extra.conf`, and exits if
  that fails too.
- `blacklist_watchdog.py` polls `/config` every 2 seconds. It copies the
  exported lists into Squid's ACL files after checking them against the
  manifest, merges overlapping IP ranges, writes the `*_acl_status.json`
  records the Enforcement section shows, and runs `squid -k reconfigure`. On
  `/config/.reload-squid` it regenerates the whole configuration and writes the
  outcome to `/config/.reload-squid.result`. Once a minute it reads Squid's
  cache manager on localhost and writes `/config/cache_stats.json`.
- The generator copies the lists through the same check
  (`blacklist_watchdog.py --sync-lists`), at boot and on every regeneration. A
  list that does not match the manifest is not copied and Squid keeps the copy
  it holds. At boot there is none: a refused allowlist starts empty, and a
  refused blocklist closes a gate that denies every client request (logged
  with the reason `lists_unverified`) until the watchdog copies a verified
  one. Without a manifest the lists are copied unverified, with a warning.
- `squid -k parse` and `squid -k reconfigure` may take 40 seconds: both read
  the whole configuration first, about 11 seconds with 640,000 names in
  Squid's domain ACL at 0.5 CPU. A reconfigure that does not finish is not
  taken as applied: the watchdog retries it, and a reload acknowledges it with
  `reconfigure_rc` null.
- ICAP: REQMOD with `bypass=0` (fail closed) unless `WAF_FAIL_OPEN=1`, and
  RESPMOD with `bypass=1`.
- The SSL-bump CA is `/config/ssl_cert.pem` and `ssl_key.pem`, generated on
  first start when absent (RSA 2048, 825 days).
- `startup.sh` installs iptables rules that redirect ports 80 and 443 to 3128
  inside the container, but Squid has no intercept port, so redirected
  traffic is not served (see [Transparent proxy](./security.md#transparent-proxy)).

### `waf`: Go ICAP server

- Packages: `waf-go/internal/engine` holds the built-in rules, pre-filter,
  heuristics, DGA and typosquatting checks and the state behind a block
  decision; `waf-go/internal/crs` holds the OWASP Core Rule Set
  configuration; `waf-go/internal/inspect` runs one request through both;
  package `main` is the ICAP transport and builds the engines from the
  environment at start.
- ICAP on port 1344. Built-in rules: 179 request rules in 22 categories and 5
  response rules in 2 (`waf-go/internal/engine/rules.go`), plus custom rules
  from `/config/waf_custom_rules.txt`.
- Each built-in match adds its rule's severity to an anomaly score; a request
  is blocked when the score reaches `WAF_BLOCK_THRESHOLD` (default `10`).
  Categories in `WAF_OBSERVE_CATEGORIES` match and are logged with no score.
- With `WAF_ENGINE=hybrid` (the default) a request the built-in rules let
  through then goes to the OWASP Core Rule Set 4.25.0 on Coraza 3.8.1, at
  paranoia level 1, which blocks at an inbound anomaly score of 5. It reads
  what the WAF can read: plain HTTP and, with SSL bump, decrypted HTTPS; it
  does not run on a `CONNECT`, which carries only a host and a port.
  Responses are inspected by the built-in rules only. A Core Rule Set block
  is reported under its rule family (`CRS_SQLI`, `CRS_XSS`, `CRS_PHP`, ...)
  with rule IDs of the form `CRS-942100`. The category toggles and
  `WAF_DISABLED_CATEGORIES` switch the built-in categories only; the Core
  Rule Set is switched as a whole, by `WAF_ENGINE=legacy`, and rule by rule
  by the WAF policy.
- The built-in rules match the URL and each inspected header value on its
  own, and a form, JSON or multipart body argument by argument
  (`name=value`, a JSON key with its value, a part's headers and its
  content), so a pattern cannot run from one header or argument into the
  next. A body that does not parse, or has more than 100,000 arguments or
  JSON nested deeper than 64, is matched whole; a `text/plain` body always
  is.
- The rules run on Go's `regexp` by default. A pre-filter skips the rules an
  input cannot match: by a literal each pattern requires, and for the rules
  with none by a gate (`waf-go/internal/engine/gates.go`). With
  `WAF_REGEX_ENGINE=re2` they run on RE2 compiled to WebAssembly, in-process,
  and so do the Core Rule Set's `rx`, `pm`, `detectSQLi` and `detectXSS`
  operators; the input reaches RE2 as Go's `regexp` reads it, each byte that
  is not valid UTF-8 as U+FFFD.
- The WAF policy (`waf-go/internal/policy`, `/config/waf_policy.json`) takes
  single rules off a host, a path or, for a Core Rule Set rule, an argument,
  or leaves rules, categories or the whole WAF to log only. It is re-read
  while the WAF runs; each request reads the policy in force once. Core Rule
  Set exceptions are removed from that request's transaction, so a reload
  compiles nothing; built-in exceptions apply while the rules are matched.
- Core Rule Set adjustments for a forward proxy (`waf-go/internal/crs`):
  `CONNECT`, `PUT`, `PATCH` and `DELETE` are allowed methods; the rules that
  enforce what a destination accepts are removed (920420, 920450, 920451,
  920480), with the session-fixation rules 943110 and 943120, 930130 and
  932370; 920440 runs on a list of backup, temporary and server-side file
  extensions only; 942100 skips arguments named like a privacy string
  (`us_privacy`, `usp`, `ccpa`); unexpanded ad-tech macros (`${NAME}`) are
  neutralized in the URI; a body that is not a form, multipart, JSON or XML
  is read raw rather than parsed into arguments.
- Input normalisation before matching: multi-pass URL decoding, IIS
  `%uXXXX` escapes included, overlong UTF-8 sequences for an ASCII character
  read as that character, HTML decoding, removal of inline SQL and HTML
  comments, NFKC Unicode folding, and four separator lookalikes the
  traversal payloads use (U+2215, U+2216, U+EFC8, U+F025) read as `/` or
  `\`.
- A base64 token of eight characters or more in the URL or a body argument
  is decoded and matched by the traversal, path manipulation and command
  injection rules, less CMDi-003 and CMDi-004 (`$(...)` and backticks, which
  decoded bytes hold by chance). Header values are not decoded.
- Request bodies are inspected up to 1 MB; a larger body adds the
  `WAF-BODY-OVERSIZE` finding and the rest is not inspected.
- When a client has been blocked more than three times within 60 seconds,
  each further block is answered after a 10 second delay.
- Blocks are posted to the backend at `POST /api/internal/alert` with
  `INTERNAL_ALERT_TOKEN`. The same token authenticates the backend to the WAF
  management API on port 8080 (`/stats`, `/reset`, `/categories`,
  `/categories/toggle`, `/heuristics`, `/heuristics/toggle`, `/policy`,
  `/policy/reload`, `/policy/validate`); `/health` and `/metrics` there are
  open on the internal network.
- The backend keeps each block the WAF reports (`waf_events`, pruned with the
  access log) under the event ID the access log row carries, so a block can
  be looked up and turned into a policy exception.
- Every ICAP response carries an ISTag derived from the rule set, the engine
  and the observe-only categories, and bumped on each category toggle, so
  Squid drops cached verdicts when rules change.

### `dns`: dnsmasq

- Squid's resolver. The service publishes no port, so LAN clients cannot query
  it.
- Answers `0.0.0.0` and `::` for each blocked domain, from the hosts file the
  backend writes; Domain exceptions are left out of that file. A change is picked
  up with `SIGHUP` within about 2 seconds.
- Upstream resolvers `DNS_UPSTREAM_1..3`, default `1.1.1.3`, `9.9.9.9`,
  `8.8.8.8`.
- SafeSearch and YouTube restricted mode are CNAME overrides added when their
  marker files exist; dnsmasq restarts when they change. The enforcement
  hosts (forcesafesearch.google.com, restrict.youtube.com, strict.bing.com,
  safe.duckduckgo.com) are resolved through the upstream resolvers when
  dnsmasq starts and declared with `host-record`, since dnsmasq follows a
  CNAME only to a name it knows locally. If a lookup fails, Google and
  YouTube use 216.239.38.120, the address Google documents, and Bing and
  DuckDuckGo are pinned to 0.0.0.0 (blocked). The hosts are resolved again
  every `SAFESEARCH_REFRESH_SECONDS` (default 3600): when every one answers
  and an address in use is no longer among the answers, dnsmasq restarts
  with the new ones; when one does not answer, the running addresses stay.

### `tailscale`: optional

- Defined under the `tailscale` profile (`docker compose --profile tailscale
  up -d`), with `TS_AUTHKEY` and `TAILSCALE_HOSTNAME` from `.env`.
- It is attached only to `proxy-internal`, which has no route out. Whether it
  can reach the Tailscale coordination servers from there has not been
  verified.

## Request flow

1. A client sends a request to Squid on port 3128.
2. Squid evaluates its access rules, first match wins: dangerous methods and
   FTP, ports outside `Safe_ports`, sources outside the allowed client ranges,
   the cache manager, the IP blacklist, the domain blacklist, a name that
   resolved to the sinkhole address, the policy rules inserted for the access
   settings that are on, `CONNECT` to a LAN destination
   (allowed), `CONNECT` to a port outside `SSL_ports` (denied), IP exceptions and
   LAN destinations (allowed), direct-IP URLs (denied), the egress rule when
   default-deny is on, and finally local clients (allowed) and everything else
   (denied).
3. A request Squid allows is sent to the WAF over ICAP REQMOD. The WAF scores
   the URL, headers and body; at or above the threshold it answers with a 403
   that Squid returns to the client.
4. Squid forwards the request. The response goes through RESPMOD, where the
   WAF can block executable content types and text that matches the response
   rules. With SSL bump on, HTTPS is decrypted for both steps.
5. Squid writes the request to `/var/log/squid/access.log` (the host's
   `./logs`) with the rule that decided it.
6. The backend's tailer reads the line from `/logs/access.log`, stores it in
   `proxy_logs` with its block reason, and broadcasts it to the WebSocket feed.

## Volumes

| Volume | Mounted in | Purpose |
|---|---|---|
| `./config` | backend, proxy (read-write); waf, dns (read-only) | Exported lists, marker and trigger files, SSL-bump CA, status records |
| `./data` | backend | SQLite database, `.jwt_secret`, `.enc_key` |
| `./logs` | backend (`/logs`), proxy (`/var/log/squid`), dns (`/var/log`) | Squid and dnsmasq logs |
| `squid-cache` | proxy | Squid disk cache |
| `waf-traffic` | waf | WAF traffic feature log |
| `letsencrypt` | web | Mounted at `/etc/letsencrypt`; unused by the shipped image, which has no certbot |
| `tailscale-data` | tailscale | Tailscale node state |

## Limits

Single node by design: the failed-login counters and the token revocation
cache are in process memory, the state is on bind mounts, and each container
generates its own configuration. These are the bounds in the code:

| Bound | Value | At the limit |
|---|---|---|
| Database | One SQLite file, 4 connections, `busy_timeout` 5 s | Writes wait for the lock; past 5 s they fail |
| WAF per-client heuristic state | 10,000 client addresses | An entry is evicted |
| Live log feed | 256 queued messages, 64 per viewer | Messages to a slow viewer are dropped |
| WAF block alerts | 64 queued, 8 delivery workers, 3 attempts per alert | Alerts are dropped and counted in `waf_notify_dropped_total`; deliveries the backend refuses or never answers are counted in `waf_notify_failed_total{reason}`; the block itself still happens. On SIGTERM the WAF waits up to 5 s for the queue to empty |
| Backend alert queue | 256 queued, 64 per channel, 10,000 addresses with an open group | A full queue drops the alert (`spm_notifications_total{channel="queue", outcome="dropped"}`); past 10,000 addresses a new one joins its event type's overflow group, whose digest says "from other addresses" |
| Backend request rate | 20 per second per address, burst 60 | `429` with `Retry-After: 1` |
| Concurrent DNS detection scans | 2 | `429` |
| Request body | 10 MB through nginx; 55 MB at the backend; 32 MB per list download | `413`, or the import fails |
| Log ingest | 5,000 lines per 500 ms | A backlog is read over the following ticks; after a rotation the lines left in `access.log.0` are read first. A backlog that outlasts two rotations, or a new file that has already grown past the saved offset when the tailer looks, is not recovered |
| Domain blacklist | `SPM_DNS_BLOCKLIST_MAX_DOMAINS`, default 1,000,000 | Adds and imports refused with `413` |
| Backend container | 0.25 CPU, 128 MB | Raise `deploy.resources.limits` in the compose file |

`proxy_logs` is pruned once a day to `log_retention_days` (default 30). If that
setting is not a positive number pruning stops and the metric
`spm_log_retention_enabled` is 0. The audit log keeps 365 days.
