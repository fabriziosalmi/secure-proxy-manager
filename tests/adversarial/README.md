# Adversarial e2e harness (proxy + WAF data plane, backend API)

Drives attacker-style traffic against the running product in an isolated
sandbox and gates on security regressions. Five planes:

- **Plane 1 — data-plane block-matrix.** Traffic **through the real forward
  proxy + WAF/ICAP**; measures block/allow correctness (FP/FN).
- **Plane 2 — API attacker.** Hits the **backend's auth boundary directly**
  (auth-bypass, forged/tampered JWTs, login SQLi, rate-limit).
- **Plane 3 — bench/latency.** k6 load through the proxy + WAF vs a direct
  baseline; p50/p95, throughput, ICAP overhead, with a p95/error-rate gate.
- **Plane 4 — resilience.** Kills/restarts waf & dns and asserts the WAF
  **fails closed** (no fail-open hole) and the stack **self-heals**.
- **Plane 5 — config-matrix.** Flips WAF settings through the real backend→WAF
  push path and asserts the **data plane changes** accordingly (a disabled
  rule-category's attack now passes; another category still blocks; re-enable
  blocks again) — proving settings actually take effect, selectively.

This is the counterpart to the UI Playwright suite and the API/UI-only
`docker-compose.test.yml` (which deliberately excludes proxy + WAF).

Tracks issue [#200](https://github.com/fabriziosalmi/secure-proxy-manager/issues/200).

```
plane 1:  attacker ──http_proxy──▶ proxy (Squid) ──ICAP──▶ waf   (REQMOD / RESPMOD)
                                        │  resolves via dns (dnsmasq)
                                        └──────────────▶ mock-upstream (controlled)
plane 2:  attacker ─────────────────────────────────────▶ backend (Go API, direct)
```

## Run

```bash
make adversarial          # or: bash tests/adversarial/run.sh
```

The run builds the sandbox, executes both planes, prints their reports, and
tears the stack down. Exit code is the CI gate: **non-zero if plane 1 has a hard
false negative/positive, or plane 2 has a hard auth/authorization regression.**

Useful env:

| Var | Effect |
|---|---|
| `KEEP_UP=1` | Leave the stack running after the report (debugging). |
| `NO_BUILD=1` | Skip image rebuild (faster re-runs after a corpus-only edit). |

Reports are written to `tests/adversarial/report/` (git-ignored):
`report.md`, `report.json`, `results.json`.

## How it works

- **Isolation.** Two networks: `adv-internal` (`internal: true`, carries ICAP +
  name resolution between proxy/waf/dns) and `adv-edge` (attacker ↔ proxy ↔
  mock-upstream). No internet egress is required — the dns healthcheck resolves a
  local record, so the stack comes up fully offline.
- **Reachability.** Squid resolves destinations via dnsmasq and **denies
  IP-literal hosts**, so the mock upstream gets a static edge IP
  (`10.99.0.10`) + hostname `upstream.test`, injected into dnsmasq via
  [`dns-config/dnsmasq.d/zz-adversarial-upstream.conf`](dns-config/dnsmasq.d/zz-adversarial-upstream.conf).
  All corpus traffic targets `upstream.test` only.
- **Verdict signal.** A WAF block surfaces to the client as HTTP **403** — that
  is the matrix signal (Squid replaces the ICAP block body with its own error
  page, so the WAF's internal category is not observable client-side; the
  intended category/rule per case lives in [`corpus.json`](corpus.json)
  `desc`). `blockThreshold` is 10, so every malicious case uses a payload
  grounded in a real severity-10 rule.

## Corpus

[`corpus.json`](corpus.json) — one object per case:

| field | meaning |
|---|---|
| `kind` | `malicious` \| `benign` |
| `vector` | `url` \| `header` \| `body` \| `response` |
| `expect` | `block` \| `pass` (ground truth) |
| `gate` | `hard` (fails the run on a miss) \| `soft` (reported only) |

Coverage today: the 19 request-side WAF categories that block on a single
payload, `PROTOCOL_ANOMALY` (scanner signature in UA), two response-side rules
(`RESPONSE_XSS`, `RESPONSE_SECRET_LEAK`), plus benign FP-stress traffic. Two
`soft` cases document known-nuanced behaviour: `UNICODE_OBFUSCATION` (interacts
with NFKC normalization) and `FINANCIAL_DATA` (sub-threshold by design — a
single card is a corroborating signal, score 2 < 10, so it correctly passes).

Extend it "as attackers": add cases, re-run with `NO_BUILD=1`, watch FN/FP.

### Plane 2 — API attacker

[`api-corpus.json`](api-corpus.json) — hits the backend directly:

| field | meaning |
|---|---|
| `auth` | `none` \| `basic` \| `bearer_valid` \| `bearer_bad` \| `bearer_alg_none` \| `bearer_tampered` |
| `expect` | `unauthorized` (401/403) \| `ok` (2xx control) \| `ratelimited` (burst → 429) |
| `gate` | `hard` \| `soft` |

Covers: auth-bypass on protected endpoints (status, settings, audit-log,
database export/reset, change-password), forged JWTs (**alg=none** confusion,
mutated signature, garbage), **login SQL-injection**, wrong-password, per-IP
**rate-limit** enforcement, plus control cases proving legitimate Basic/JWT
access still works. A protected endpoint returning 2xx unauthenticated is a
**bypass** and fails the gate.

### Plane 3 — bench / latency

[`bench/bench.js`](bench/bench.js) — a k6 load test run twice: a **baseline**
(direct to the mock upstream) and a **proxied** run (through proxy + WAF/ICAP,
`HTTP_PROXY` set). Each request uses a unique cache-buster URL, so the WAF
safe-cache and Squid cache both miss and we measure real per-request inspection.
The report shows p50/p95/p99, throughput, and the **proxy + ICAP overhead**
(proxied − baseline). k6's thresholds are the gate — it exits non-zero on a
breach (tunable via env):

| Env | Default | Meaning |
|---|---|---|
| `P95_MS` | `800` | proxied p95 latency ceiling (ms) |
| `MAX_FAIL` | `0.05` | proxied error-rate ceiling |
| `VUS` / `DURATION` | `10` / `15s` | load shape |

### Plane 4 — resilience

No corpus — a scripted failure sequence in `run.sh`, probing through the proxy
from a throwaway container while it stops/starts services:

| Check | Asserts |
|---|---|
| `baseline` | benign → 200 while healthy |
| `waf-fail-closed` | WAF stopped → benign is **not** 200 (REQMOD `bypass=0` denies; a 200 would be a fail-**open** hole) |
| `waf-self-heal` | WAF restarted → benign 200 **and** malicious 403 (ruleset/ISTag intact) |
| `dns-self-heal` | dns recycled → traffic flows again (200) |

### Plane 5 — config-matrix

No corpus — a scripted sequence in `attacker/config-matrix.sh` that flips WAF
rule-category toggles via `POST /api/waf/categories/toggle` (the real
backend→WAF push path) and probes through the proxy. Each probe uses a unique
cache-buster so neither Squid nor the WAF safe-cache serves a stale verdict (a
category toggle also bumps the WAF ISTag).

| Check | Asserts |
|---|---|
| `baseline-*-blocked` | SQLi & XSS both blocked at default config |
| `*-disabled-passes` | disabling a category lets **that** attack through |
| `*-still-blocks-while-*-off` | a **different** category still blocks (selective) |
| `*-reenabled-blocks` | re-enabling restores blocking |

Covers WAF category toggles today. A **5b** would extend it to dns-driven
(blacklist/whitelist precedence, SafeSearch/YouTube DNS) and squid-driven
(egress default-deny, SSL-bump) settings — those need the backend to share the
config volume with dns/proxy and a reload step.

## Roadmap (later phases, see #200)

- Optional Phase 2b — templated scans (nuclei / ZAP baseline) layered on the
  same sandbox; tighten the bench thresholds once CI has a baseline.
