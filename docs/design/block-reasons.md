# Block reasons and client attribution

Status: implemented and merged; this page is the design record. Line
references marked `main:` are to `main` at 8d9166e, before the change. The
other line numbers were taken on the `feat/block-reasons` branch ("this
branch" below) and have since moved: search the named file for the rule or
function instead. The measurements are those taken on that branch.

## 1. Problem, as measured on the test deployment

| Symptom | Measured | Cause |
|---|---|---|
| Dashboard: 146 blocked | Client 192.168.0.109 alone: 908 of 1,180 requests blocked by the domain blacklist (900 at DNS, 8 by Squid) | A request to a sinkholed name is logged by Squid as `TCP_TUNNEL/503`, and `blocked` is derived from the status string (`main:backend-go/internal/workers/log_tailer.go:296-301`), so it counts 0 |
| The client sees a connection error, not the block page | same | Squid connects to the sinkhole address `::` and fails (section 2.3) |
| The proxy is a client | 128 of the 146 "blocked" are dnsmasq rows with `source_ip` 172.18.0.4 (the proxy container), each lookup twice (A, AAAA) | `main:backend-go/internal/workers/dns_tailer.go:145-163` stores every sinkhole answer as a blocked request from the address that asked, which is always Squid |
| Threats: 12 "WAF Block" vs 4 real | | `main:backend-go/internal/handlers/analytics.go:720` guesses: any status containing 403 is "WAF Block" (Squid denials too), any denied destination with `:` is "Direct IP" (every denied `CONNECT host:443`) |

## 2. How each deny is produced today (origin/main)

### 2.1 Squid http_access rules (`main:proxy/generate_squid_conf.sh`)

Squid stops at the first matching rule. All logged `TCP_DENIED/403` (or `/407`)
in the stock-format line with nothing naming the rule.

| Line | Rule | Applies to |
|---|---|---|
| 318-319 | `deny Dangerous_methods`, `deny !Safe_methods` | PUT DELETE PATCH TRACE TRACK, anything not GET HEAD POST OPTIONS CONNECT |
| 322 | `deny ftp_proto` | `ftp://` |
| 323 | `deny !Safe_ports` | port not in Safe_ports |
| 328 | `deny !localnet !localhost` | source gate: client outside localnet |
| 332-333 | `allow localhost manager`, `deny manager` | cache manager |
| 335 | `deny ip_blacklist` | destination IP (`dst`) |
| 348 | `deny domain_blacklist` | destination name (`dstdomain`), list up to SPM_SQUID_DOMAIN_ACL_MAX |
| 350 | `@@SPM_POLICY@@`: proxy auth 697, content filter 710, time 733 | inserted by `insert_policy` (53-63) |
| 353-354 | `allow CONNECT local_dst`, `deny CONNECT !SSL_ports` | CONNECT |
| 357-358 | `allow ip_whitelist`, `allow local_dst` | |
| 360-365 | `deny direct_ip_*` | IP literal in the URL or host |
| 563, 572 | egress: `deny localnet !egress_dst_allow_ip !egress_dst_allow_dom` before `allow localnet` | when `/config/egress_default_deny` exists |
| 367-369 | `allow localnet`, `allow localhost`, `deny all` | |
| 31-37 | the same direct-IP rules, appended only if missing | `ensure_ip_blocking_rules` |

### 2.2 WAF (ICAP REQMOD and RESPMOD)

`main:waf-go/main.go:751-771` `sendBlockResponse` answers ICAP 200 with an
encapsulated HTTP 403 and, for REQMOD, an `X-WAF-Event-Id` HTTP header. Squid
logs a REQMOD block as `NONE_NONE/403` and a RESPMOD block as `TCP_MISS/403`
(measured, section 4). Nothing in the line says the WAF decided. `X-WAF-Event-Id`
is read with `%{X-WAF-Event-Id}<h` from the HTTP reply (`main:...generate_squid_conf.sh:425`),
which an upstream server can also send.

### 2.3 DNS sinkhole

dnsmasq answers `0.0.0.0` and `::` for every blacklisted name
(`backend-go/internal/database/db.go:610`). Squid does not deny that answer; it
connects to it. Measured with the origin/main generator, real dnsmasq:

```
TCP_MISS_ABORTED/503 4889 GET http://sink.test/ - HIER_DIRECT/:: text/html -
TCP_TUNNEL/503 0 CONNECT sink.test:443 - HIER_DIRECT/:: - -
```

### 2.4 SSL-bump

With SSL-bump on, a denied CONNECT is logged twice (measured): the CONNECT as
`TCP_DENIED/200` and the error page Squid serves inside the bumped tunnel as
`NONE_NONE/403 GET https://...`. That second line and a WAF block have the same
action and status, which is what the deployment showed.

## 3. Mechanism

| Decision | Choice | Evidence |
|---|---|---|
| Record the Squid rule | An `annotate_transaction` ACL per reason (`spm_r_<reason>`, sets note `spm_reason`), placed **last** on each deny rule, and `spm_r_none` last on each allow rule (`proxy/generate_squid_conf.sh:300-321`, `:341-402`) | Squid 7.7 logs the note via `%{spm_reason}note` for GET and CONNECT denials, with and without SSL-bump (section 4) |
| Why allow rules set `none` | The proxy-auth rule must keep its auth ACL last (407 challenge), so its annotation goes **before** it (`:738`) and is set for every request that reaches the rule; the admitting allow rule resets it | Measured: authenticated request logs `none`. With the annotation placed after the auth ACL instead, 407 is still returned but no note is logged (`- -`), because the auth ACL ends the check |
| Record a WAF block | ICAP response header `X-SPM-Reason: waf` set in `sendBlockResponse` (`waf-go/main.go:770-774`), logged with `%{X-SPM-Reason}adapt::<last_h` | Measured for REQMOD (`NONE_NONE/403 ... none waf`), RESPMOD (`TCP_MISS/403 ... none waf`) and a WAF block inside a bumped tunnel. Read from the ICAP reply, so an upstream cannot forge it |
| DNS-sinkholed requests | **Squid-side**: `acl dns_sinkhole dst 0.0.0.0 ::` and `http_access deny dns_sinkhole spm_r_domain_blacklist_dns` after the domain ACL (`:372-382`) | Measured with real dnsmasq: `TCP_DENIED/403 ... domain_blacklist_dns` for GET and CONNECT, and the client gets the block page (403, 4862 bytes) instead of a 503. dnsmasq logged one A and one AAAA query for the name across a GET and a CONNECT to it (Squid's ipcache); `ip_blacklist` (`:358`), evaluated earlier, is a `dst` ACL as well. Not measured: an upstream resolver that itself answers `0.0.0.0` for names it filters would be counted under the same reason |
| Ingestion fallback | A line whose hierarchy address is `0.0.0.0` or `::` (Squid connected to the sinkhole) is `domain_blacklist_dns`, in any format (`backend-go/internal/workers/block_reason.go`, `sinkholeAddr`) | Covers a proxy still on the old config. Rejected alternative: matching the name against the 640,929-entry list at ingestion; the address is already in the line, the list is not needed |
| Log format | Two fields appended to `spm`: `%{spm_reason}note %{X-SPM-Reason}adapt::<last_h` (`:458-463`); `-` when absent | The parser is positional; 10 stock fields and the event id keep their place |

## 4. Measurements (Squid 7.7, this branch)

Harness: the proxy image running the real generator, the real WAF image and a
real dnsmasq (dns image, blocklist written as the backend writes it) on one
docker network. The same cases run in `tests/shell/squid_acl_matrix_test.sh`,
which CI runs as part of the required check *Squid config generation*. Lines
as written by Squid (timestamp and client trimmed):

| Request | Client sees | Logged |
|---|---|---|
| allowed | 200 | `TCP_MISS/200 ... - none -` |
| blacklisted domain (Squid ACL) | 403 | `TCP_DENIED/403 ... - domain_blacklist -` |
| sinkholed name, GET / CONNECT | 403 / 403 | `TCP_DENIED/403 ... - domain_blacklist_dns -` |
| blacklisted IP | 403 | `... ip_blacklist -` |
| `.exe` with content filter | 403 | `... content_filter -` |
| `http://8.8.8.8/`, `CONNECT 8.8.8.8:443` | 403 | `... direct_ip -` |
| port 21, `CONNECT :22` | 403 | `... port_policy -` |
| PUT | 403 | `... protocol_policy -` |
| proxy auth, no or wrong credentials | 407 | `TCP_DENIED/407 ... proxy_auth -` |
| proxy auth, good credentials | 200 | `TCP_MISS/200 ... u1 ... none -` |
| outside allowed hours | 403 | `... time_restriction -` |
| egress default-deny, not allowlisted | 403 | `... egress_policy -` (matrix test) |
| external client | 403 | `... source_gate -` (matrix test) |
| blocklist not vouched for by the manifest at boot (lists gate closed), GET / CONNECT | 403 / 403 | `TCP_DENIED/403 ... - lists_unverified -` (matrix test) |
| WAF REQMOD block | 403 | `NONE_NONE/403 205 ... dmdts8y4qdl2-3 none waf` |
| WAF RESPMOD block (`application/x-msdownload`) | 403 | `TCP_MISS/403 189 ... - none waf` |
| origin server's own 403 | 403 | `TCP_MISS/403 ... - none -` |
| WAF unreachable, fail closed | 500 | `NONE_NONE/500 ... - none -` |
| SSL-bump, denied CONNECT | 403 in tunnel | `TCP_DENIED/200 CONNECT ... domain_blacklist -` then `NONE_NONE/403 GET https://... - - -` |
| SSL-bump, WAF block in tunnel | 403 | `NONE_NONE/403 GET https://... none waf` |

dnsmasq for one Squid lookup of a sinkholed name (from 192.168.88.10, the proxy):
`query[A]`, `is 0.0.0.0`, `query[AAAA]`, `is ::`, all in the same second.

## 5. Classification at ingestion (`backend-go/internal/workers/block_reason.go`)

In order; the first that applies wins:

1. 13-field line and the note is a deny reason: that reason.
2. 13-field line and the ICAP field is `waf`: `waf`.
3. Hierarchy address `0.0.0.0` or `::`: `domain_blacklist_dns`.
4. Fewer than 13 fields: `unclassified`, `blocked` from the old status heuristic (unchanged).
5. Any other note (an annotation we did not write): `other`.
6. `TCP_DENIED` with no note: `other`.
7. Otherwise `none`.

`blocked` is 1 for every reason except `none` (and `unclassified`, which keeps
the heuristic). Consequences, all measured lines above: an origin 403 is not a
block; the error page inside a bumped tunnel is not a second block (the CONNECT
line already counts it); a fail-closed WAF outage (500) is an error, not a block.

## 6. Attribution

| Fact | Evidence |
|---|---|
| dnsmasq is not reachable by LAN clients | `docker-compose.yml:176-227`: the `dns` service publishes no `ports:`; it is on `proxy-internal` and `frontend` only. `proxy/startup.sh:39-42` redirects only TCP 80 and 443 |
| Only Squid uses it | `proxy/generate_squid_conf.sh` writes `dns_nameservers $DNS_IP` (the `dns` container); no other service is configured with it. `dns/dnsmasq.conf:2-3`: "used ONLY by Squid internally" |
| So every dnsmasq row is the proxy resolving for a client Squid also logs | dnsmasq log above: `from 192.168.88.10` (the proxy) |

Decision: dnsmasq rows are kept in `proxy_logs` as the resolver's record
(method `DNS`, reason `domain_blacklist_dns`, source = the proxy) and left out
of every statistic by one predicate, `clientRows = IFNULL(method,'') != 'DNS'`
(`backend-go/internal/handlers/analytics.go`). The A and AAAA answers of one
lookup are stored once: a second answer for the same name and asker within one
second of the first, by the log line's own timestamp, is dropped
(`dns_tailer.go`, `dnsDedupe`). The client's request is counted once, from
Squid's line, attributed to the client.

## 7. Schema

`proxy_logs.block_reason TEXT NOT NULL DEFAULT 'unclassified'`, added by the
replayed ADD COLUMN list (`backend-go/internal/database/db.go:182-186`, the
style of `event_id`; a constant default rewrites no row). Partial index
`idx_proxy_logs_dns ... WHERE method = 'DNS'` keeps the lifetime total an
index count. The start-up `blocked` backfill is limited to `unclassified`
rows, so it cannot flip an origin 403 (`none`) back to blocked.

Schema version 3 (`backend-go/internal/database/reconstruct.go`) reassigns,
once, the sinkholed requests logged before reasons were recorded: Squid
logged them as a `/503` with `blocked = 0`. A row gets
`domain_blacklist_dns_reconstructed` and `blocked = 1` when it is
`unclassified`, its status ends in `/503`, its method is not `DNS`, its host
(`database.HostKey`, lower case) is on the domain blacklist as `name` or
`*.name` (compared in lower case) and not whitelisted, and it was logged at
or after that entry's `added_date`. A `/503` from before the listing is left
alone: it was an origin or network failure. The reason is separate from
`domain_blacklist_dns` so a reconstructed block never reads as a recorded
one. The step commits with `PRAGMA user_version = 3`, so it never runs twice.
Measured on 1,000,000 rows and 640,000 names (200,000 rows reassigned): 3.3
to 3.8 s on an M4, 27 to 31 s in a container with the backend's limits (128
MiB, 0.25 CPU), peak anonymous memory 120 MiB against 118 MiB for the same
start-up without the step.

| Reason | Rule (this branch, `proxy/generate_squid_conf.sh`) |
|---|---|
| `ip_blacklist` | `deny ip_blacklist` (`:358`) |
| `domain_blacklist` | `deny domain_blacklist` (`:371`) |
| `domain_blacklist_dns` | `deny dns_sinkhole` (`:382`); also a line whose upstream address is the sinkhole; also every dnsmasq row |
| `direct_ip` | `deny direct_ip_*` (`:394-399`, `:32-37`) |
| `egress_policy` | egress deny (`:601`, `:610`) and its fail-closed form (`:622`) |
| `waf` | WAF block, ICAP `X-SPM-Reason: waf` (`waf-go/main.go:774`) |
| `proxy_auth` | `deny !localhost spm_r_proxy_auth !authenticated` (`:738`) |
| `time_restriction` | `deny !allowed_hours localnet` (`:774`) |
| `content_filter` | `deny blocked_extensions` (`:751`) |
| `source_gate` | `deny !localnet !localhost` (`:351`) |
| `port_policy` | `deny !Safe_ports` (`:346`), `deny CONNECT !SSL_ports` (`:388`) |
| `protocol_policy` | `deny Dangerous_methods`, `deny !Safe_methods`, `deny ftp_proto` (`:341-345`). Not in the original list: methods and the FTP scheme are neither ports nor "other" |
| `lists_unverified` | `deny spm_lists_gate`, the fail-closed lists gate: a blocklist the backend's manifest did not vouch for at boot has no copy in Squid, so `/etc/squid/lists_gate.txt` holds `all` and every client request is denied until the watchdog copies a verified list. Added after this branch; search the generator for `spm_r_lists_unverified` |
| `other` | `deny manager` (`:356`), `deny all` (`:402`), a `TCP_DENIED` line without a note, an unknown note |
| `domain_blacklist_dns_reconstructed` | not written at ingestion: a pre-reason `/503` to a listed name, reassigned once at start-up (schema version 3, section 7) |
| `none` | not blocked |
| `unclassified` | no reason recorded: rows from before this change, lines without the reason fields |

## 8. Effect on the API and the UI

All statistics count client requests only (`clientRows`). Response fields kept;
added fields are additive, so X-API-Version stays 1.

| Endpoint | Field | Change |
|---|---|---|
| `/api/dashboard/summary` | `total_requests`, `blocked_requests`, `today_*` | client requests; blocked = a reason other than none (plus legacy rows the heuristic flagged) |
| | block rate (UI: blocked / total) | follows the two above |
| | `top_blocked`, `top_clients`, `recent_blocks` | DNS rows out; the proxy is no longer a top client; `recent_blocks[].reason` added |
| | `threat_categories` | same shape, `category` is now the reason's label from `GROUP BY block_reason` |
| | `blocked_by_reason` | new: `[{reason, label, count}]`, 7 days |
| | `blocked_by_reason_24h`, `last_24h_requests`, `last_24h_blocked`, `last_24h_clients`, `last_request_at` | new: the last 24 hours, the Overview's window |
| | `top_blocked[].reasons`, `recent_blocks[].reason_label`, `recent_blocks[].host` | new: the rules that blocked each host, the label of each recent block, its destination reduced to the host |
| `/api/clients/statistics` | `data[]`, `meta.total` | DNS rows out: the proxy container is not a client |
| `/api/clients/{ip}/details` | totals, `top_domains`, `recent` | client requests; `recent[].reason` and `blocked_by_reason` added |
| `/api/traffic/statistics`, `/api/logs/timeline` | buckets | client requests |
| `/api/logs/stats` | counts | client requests; `ip_blocks_count` = reason `direct_ip`, legacy rows keep the URL heuristic; `blocked_by_reason` added |
| `/api/logs`, `/api/logs/export` | rows | the log, internal sources left out unless `include_internal=true` (DNS rows come from the proxy, so they are internal); `blocked`, `reason` and `reason_label` added; filter by `reason` (`idx_proxy_logs_blocked_reason`) |
| `/api/status`, `/api/domains/statistics`, `/api/analytics/*`, `/api/waf/test-rule` | | DNS rows out |

## 9. Upgrade

Existing rows get `unclassified` and keep their `blocked` flag; nothing is
reinterpreted. They are shown as "Unclassified (no reason recorded)" in
`blocked_by_reason` and `threat_categories`. Old rows that were in fact
DNS-sinkholed (`TCP_TUNNEL/503`, blocked 0) stay unblocked: the stored row has
no upstream address to identify them. Old dnsmasq rows (method `DNS`) leave
every statistic at once, since the predicate is on the method. New counts are
therefore not comparable with the old ones across the upgrade, in both
directions: the proxy's rows disappear, the client's sinkholed requests appear.
