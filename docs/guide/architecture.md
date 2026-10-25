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
  backend (`BACKEND_URL`, default `http://backend:5000`).
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
  with the reason `other`) until the watchdog copies a verified one. Without a
  manifest the lists are copied unverified, with a warning.
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

- Two packages: `waf-go/internal/engine` holds the rules, pre-filter,
  heuristics, DGA and typosquatting checks and the state behind a block
  decision; package `main` is the ICAP transport and builds one engine from
  the environment at start.
- ICAP on port 1344. Rules: 172 request rules in 21 categories and 5 response
  rules in 2 (`waf-go/internal/engine/rules.go`), plus custom rules from
  `/config/waf_custom_rules.txt`.
- Each match adds its rule's severity to an anomaly score; a request is
  blocked when the score reaches `WAF_BLOCK_THRESHOLD` (default `10`).
- Input normalisation before matching: multi-pass URL and HTML decoding,
  removal of inline SQL and HTML comments, NFKC Unicode folding.
- Request bodies are inspected up to 1 MB; a larger body adds the
  `WAF-BODY-OVERSIZE` finding and the rest is not inspected.
- When a client has been blocked more than three times within 60 seconds,
  each further block is answered after a 10 second delay.
- Blocks are posted to the backend at `POST /api/internal/alert` with
  `INTERNAL_ALERT_TOKEN`. The same token authenticates the backend to the WAF
  management API on port 8080 (`/stats`, `/reset`, `/categories`,
  `/categories/toggle`, `/heuristics`, `/heuristics/toggle`); `/health` and
  `/metrics` there are open on the internal network.
- Every ICAP response carries an ISTag derived from the rule set and bumped on
  each category toggle, so Squid drops cached verdicts when rules change.

### `dns`: dnsmasq

- Squid's resolver. The service publishes no port, so LAN clients cannot query
  it.
- Answers `0.0.0.0` and `::` for each blocked domain, from the hosts file the
  backend writes; Allowed domains are left out of that file. A change is picked
  up with `SIGHUP` within about 2 seconds.
- Upstream resolvers `DNS_UPSTREAM_1..3`, default `1.1.1.3`, `9.9.9.9`,
  `8.8.8.8`.
- SafeSearch and YouTube restricted mode are CNAME overrides added when their
  marker files exist; dnsmasq restarts when they change.

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
   (allowed), `CONNECT` to a port outside `SSL_ports` (denied), Allowed IPs and
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
| WAF block alerts | 64 queued, 8 delivery workers | Alerts are dropped and counted in `waf_notify_dropped_total`; the block itself still happens |
| Backend alert queue | 256 queued, 64 per channel, 10,000 addresses with an open group | A full queue drops the alert (`spm_notifications_total{channel="queue", outcome="dropped"}`); past 10,000 addresses a new one joins its event type's overflow group, whose digest says "from other addresses" |
| Backend request rate | 20 per second per address, burst 60 | `429` with `Retry-After: 1` |
| Concurrent DNS detection scans | 2 | `429` |
| Request body | 10 MB through nginx; 55 MB at the backend; 32 MB per list download | `413`, or the import fails |
| Log ingest | 5,000 lines per 500 ms | A backlog is read over the following ticks |
| Domain blacklist | `SPM_DNS_BLOCKLIST_MAX_DOMAINS`, default 1,000,000 | Adds and imports refused with `413` |
| Backend container | 0.25 CPU, 128 MB | Raise `deploy.resources.limits` in the compose file |

`proxy_logs` is pruned once a day to `log_retention_days` (default 30). If that
setting is not a positive number pruning stops and the metric
`spm_log_retention_enabled` is 0. The audit log keeps 365 days.
