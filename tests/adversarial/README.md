# Adversarial e2e harness (proxy + WAF data plane, backend API)

Drives attacker-style traffic against the running product in an isolated
sandbox and gates on security regressions. Two planes:

- **Plane 1 — data-plane block-matrix.** Traffic **through the real forward
  proxy + WAF/ICAP**; measures block/allow correctness (FP/FN).
- **Plane 2 — API attacker.** Hits the **backend's auth boundary directly**
  (auth-bypass, forged/tampered JWTs, login SQLi, rate-limit).

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

## Roadmap (later phases, see #200)

- **Phase 3** — bench/latency (k6/vegeta): p50/p95, ICAP overhead, regression gate.
- **Phase 4** — resilience: kill/restart waf/dns hot; self-heal + fail-closed hold.
- Optional Phase 2b — templated scans (nuclei / ZAP baseline) layered on the
  same sandbox.
