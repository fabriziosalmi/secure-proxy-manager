# Benchmarks

What has been measured on the current code, how to repeat it, and on what.
Figures from earlier releases (the v3.8.0 LAN throughput and latency runs) are
in the git history of this file; they were taken on a different build and
host and are not repeated here.

## WAF rule matching

Go benchmarks in `waf-go`. Measured on 2026-10-25, Apple M4, go1.27.2
darwin/arm64, three runs each (`-count 3`):

```bash
cd waf-go && go test -run '^$' -bench . -benchmem -count 3 ./...
```

| Benchmark | Input | Time per op | Memory per op |
|---|---|---|---|
| `BenchmarkMatchRules_Benign` | One benign URL against every request rule, pre-filter on | 37 to 41 µs | 2.4 KB, 12 allocs |
| `BenchmarkMatchRules_Benign_NoPrefilter` | The same URL with the pre-filter off | 152 to 153 µs | 0.1 KB, 3 allocs |
| `BenchmarkFalsePositiveCheck` | 100 generated benign inputs, normalised and matched | 36 to 37 µs | 2.9 KB, 22 allocs |
| `BenchmarkEvasionVariants` | Every evasion variant of one SQL injection payload, normalised and matched | 139 to 141 µs | 36.9 KB, 379 allocs |

The pre-filter skips rules whose required literals are absent from the input;
on this benign URL it cuts matching time by about three quarters.

## Access log queries on 1,000,000 rows

`TestLogFilters1M` in `backend-go/internal/handlers/logs_plan_test.go` seeds
1,000,000 rows and times `GET /api/logs` for each filter. Results and query
plans are in [docs/api/logs.md](docs/api/logs.md#get-log-entries); repeat with:

```bash
cd backend-go && SPM_LOGS_1M=1 go test -run TestLogFilters1M -v ./internal/handlers/
```

## dnsmasq memory for the domain blacklist

1,000,000 names of 31 characters, written as the backend writes them
(`0.0.0.0` and `::` per name), loaded by the dns image of this repository with
the compose limits (256 MiB, 0.5 CPU): dnsmasq resident memory 226 MiB,
unchanged after two `SIGHUP` reloads. Measured on 2026-10-25. This is why
`SPM_DNS_BLOCKLIST_MAX_DOMAINS` defaults to 1,000,000 (see
[docs/guide/blacklists.md](docs/guide/blacklists.md#size-limit)).

## Latency through the proxy

Not a fixed figure: the adversarial harness measures it on every CI run. Plane
3 of `make adversarial` runs k6 (`tests/adversarial/bench/bench.js`, 10 virtual
users for 15 s by default) once directly against a local mock upstream and once
through the proxy and the WAF, reports p50, p95, p99, throughput and the
overhead of the proxy path, and fails when the proxied p95 is 800 ms or more or
the error rate is 5% or more (`P95_MS`, `MAX_FAIL`). The report is written to
`tests/adversarial/report/bench-report.md`.

## Detection

The attack and false-positive cases are the adversarial corpus
(`tests/adversarial/corpus.json`, 41 cases), gated in CI; see
[tests/adversarial/README.md](tests/adversarial/README.md).

## Known limits

1. **Regex detection.** The rules are regular expressions with anomaly scoring;
   they do not parse SQL or HTML.
2. **HTTPS.** Request contents are inspected only with SSL bump on and the CA
   trusted by the client.
3. **Response bodies.** Text responses are inspected up to 1 MB; compressed
   ones are not inspected (`waf_respmod_uninspectable_total`). There is no
   antivirus scanning; executable content types are blocked by type.
4. **Threshold.** A single low- or medium-severity rule (score 2 or 4), or a custom rule
   (score 7), does not reach the default threshold of 10 on its own.
5. **Tar pit.** After more than three blocks of one client within 60 seconds,
   each further block is delayed by 10 seconds. The record is in memory and
   resets when the WAF restarts.
