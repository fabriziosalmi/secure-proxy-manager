# Adversarial e2e harness — Phase 1: data-plane block-matrix

Drives traffic **through the real forward proxy + WAF/ICAP** like a client /
attacker and measures block/allow correctness. This is the data-plane
counterpart to the UI Playwright suite and the API/UI-only
`docker-compose.test.yml` (which deliberately excludes proxy + WAF).

Tracks issue [#200](https://github.com/fabriziosalmi/secure-proxy-manager/issues/200).

```
attacker ──http_proxy──▶ proxy (Squid) ──ICAP──▶ waf   (REQMOD / RESPMOD)
                              │  resolves via dns (dnsmasq)
                              └──────────────▶ mock-upstream (controlled)
```

## Run

```bash
make adversarial          # or: bash tests/adversarial/run.sh
```

The run builds the sandbox, sends every corpus case through the proxy, prints a
**block-matrix + FP/FN report**, and tears the stack down. Exit code is the CI
gate: **non-zero if any hard-gate case is a false negative (malicious allowed)
or false positive (benign blocked)**.

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

## Roadmap (later phases, see #200)

- **Phase 2** — API attacker (JWT tampering, auth-bypass, IDOR) via nuclei / ZAP.
- **Phase 3** — bench/latency (k6/vegeta): p50/p95, ICAP overhead, regression gate.
- **Phase 4** — resilience: kill/restart waf/dns hot; self-heal + fail-closed hold.
