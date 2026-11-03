# WAF coverage by context

What the WAF can detect depends on what Squid shows it. This page gives,
for each context, what each detector caught on public datasets, measured
with `wafeval` (`waf-go/tools/wafeval`) on the default engine (the
built-in rules, then the OWASP Core Rule Set at paranoia level 1), with no
policy, on the WAF at commit `2271967`. On every record without a TLS
server name its verdicts and signals are those measured at `bc7527c`, except
the real-traffic DGA row (see below).

## Contexts

| Context | What the WAF receives | What runs |
|---|---|---|
| HTTPS without SSL bump | `CONNECT host:port` and its headers | the SSRF rules on host and port, the DGA and typosquat checks, the per-client heuristics. The Core Rule Set does not run on a `CONNECT` |
| HTTPS with TLS server names on, without SSL bump | the same `CONNECT`, then a second time with the server name and the first bytes of the client's handshake | the same as without SSL bump; on the second pass, a signal when the server name is not the `CONNECT` host, and the SSRF rules and the DGA and typosquat checks on that name ([configuration](./configuration.md#tls-server-names-without-decrypting)) |
| Plain HTTP, or HTTPS with SSL bump | request line, headers, body | every request rule, the base64 pass, the DGA and typosquat checks, the heuristics, then the Core Rule Set |
| Responses (plain HTTP or SSL bump) | status, headers, body | the dangerous content types, the response rules, the PII counter |

A request to a LAN host (`localhost`, a private or link-local address) is not
inspected, and neither is its response: the router's, NAS's or printer's own
pages are not client traffic leaving the network.

## Blocked and signalled

Each row gives two numbers:

- **Blocked**: the share of records the WAF blocked (score 10 or more).
- **Signalled**: for each detector, the share of records on which it
  scored, blocked or not.

The DGA and typosquat checks score 6 and 5, so they never block on their
own; signalled is the only number that shows what they see. On benign rows,
signalled is the rate at which a detector fires on ordinary traffic. That
rate matters as soon as weak signals are added together.

A detector is a built-in rule category, a heuristic, the DGA or typosquat
check, or `CRS` for any Core Rule Set rule. A stage that does not run
because an earlier one already blocks signals nothing. The `CRS` share on a
row is therefore the share where the built-in rules had not already blocked.

## Client trajectories

Most signals that describe a client, rather than a request, score below the
block threshold. On its own, a typosquatted name, a check-in at regular
intervals or a secret in a request body is weak evidence. Several of them
from one client, in the order a compromised host produces them, are much
stronger. The WAF sends these signals to the backend, scored or matched in
Log only. Each category is sent at most once per client every 10 minutes.
The backend reads them as trajectories every minute.

Each signal belongs to one phase of what a compromised host does on the way
out:

| Phase | Signals |
|---|---|
| Arrival: it reached something meant to compromise it | `TYPOSQUATTING` |
| Contact: it called out the way an implant does | `DGA_DOMAIN`, `HEURISTIC_BEACONING`, `TLS_SNI_MISMATCH` |
| Action: it did what an implant does | `HEURISTIC_SHARDING`, `CRYPTO_TUNNEL`, `POST_EXPLOIT`, `DATA_EXFIL`, `CLOUD_SECRETS`, `DATA_LEAK_PREVENTION`, `FINANCIAL_DATA`, `HEURISTIC_ENTROPY`, `HEURISTIC_GHOSTING`, `RANSOMWARE` |

Classic web attacks, protocol anomalies and the Core Rule Set describe a
request, not the client, and are not part of a trajectory.

A client's signals make a trajectory when, within 24 hours, either rule
holds:

- **Order**: a signal of a later phase follows one of an earlier phase at an
  earlier instant, and at least one signal in the window is not
  probabilistic. Beaconing, sharding, entropy and ghosting are
  probabilistic: browsing produces them too. A device's periodic check-in
  followed by a news page with its ad hosts would otherwise read as contact
  then action, so two of them alone are not enough.
- **Breadth**: three distinct signals, in any phases.

Signals of one instant (one request) have no order between them.

Each client has at most one trajectory a day. Signals that arrive within the
24 hours after its first signal update it. A new trajectory is looked for
only after that.

Each trajectory raises one `waf_trajectory` alert (`warning`;
`notify_waf_trajectory` switches it off). The UI shows trajectories in two
places:

- Analytics, Client trajectories: each client with its stages, and the
  signals of that day in order;
- the Overview: a notice when there was one in the last 24 hours.

In GDPR mode a client is stored as its network, so the signals are not
stored and no trajectory is read.

## HTTPS without SSL bump

| Dataset | Label | Records | Blocked | Signalled |
|---|---|---|---|---|
| snsec-net/dga-detection-drift26dsn | attack (DGA) | 19,950 | 0 | DGA_DOMAIN 5.13% |
| fox-srt/cobaltstrike-beacon-corpus | attack (C2 hosts) | 19,775 | 0 | SSRF 0.69%, TYPOSQUATTING 0.10%, DGA_DOMAIN 0.01% |
| pirocheto/phishing-url | attack (phishing hosts) | 5,715 | 0 | SSRF 0.07%, TYPOSQUATTING 0.05%, DGA_DOMAIN 0.03% |
| Tranco top-million crawl, each host once | benign | 198,647 | 0 | SSRF 0.30%, DGA_DOMAIN 0.02%, TYPOSQUATTING 0.01% |
| snsec-net/dga-detection-drift26dsn | benign | 20,118 | 0 | TYPOSQUATTING 0.03%, DGA_DOMAIN 0.02% |
| pirocheto/phishing-url | benign | 5,715 | 0 | SSRF 0.02% |
| Real egress traffic of one small installation | benign | 182 | 0 | none |

Without SSL bump the WAF blocks none of these attacks:

- **DGA.** The DGA check signals one generated domain in twenty.
- **C2 and phishing hosts.** Their SSRF signal is SSRF-006 alone: a name
  under `amazonaws.com`, scored 4. It fires on 0.30% of the Tranco hosts
  too, so it does not tell a C2 host from an ordinary cloud host.
- **Real traffic.** On the real sample the DGA check used to signal 26 of
  the 182 names. All 26 were one probe name,
  `this-url-does-not-exist-<uuid>.invalid`, with a different UUID each
  time. `.invalid` is a special-use top-level domain that never resolves
  (RFC 6761). The DGA and typosquat checks now skip such names. No other
  row changed.

## HTTPS with TLS server names, without SSL bump

The second pass of each `CONNECT` is evaluated with the server name its
client asked for. Two kinds of record:

- **Same name:** every `CONNECT` above, with its own host as the server
  name. This is what a client sends when it hides nothing.
- **Evasion:** a `CONNECT` to a benign Tranco host with the attack host as
  the server name. This is what a client sends to get past a check on the
  `CONNECT` line.

`corpus/peek.py` writes both from the records above. The server name is
real, and the handshake bytes are the start of a real TLS 1.3 ClientHello.

| Dataset | Kind | Label | Records | Blocked | Signalled |
|---|---|---|---|---|---|
| snsec-net/dga-detection-drift26dsn | evasion | attack (DGA) | 19,950 | 5.13% | TLS_SNI_MISMATCH 100%, DGA_DOMAIN 5.13% |
| fox-srt/cobaltstrike-beacon-corpus | evasion | attack (C2 hosts) | 19,998 | 0.12% | TLS_SNI_MISMATCH 100%, SSRF 0.68%, TYPOSQUATTING 0.11%, DGA_DOMAIN 0.01% |
| pirocheto/phishing-url | evasion | attack (phishing hosts) | 5,715 | 0.09% | TLS_SNI_MISMATCH 100%, SSRF 0.07%, TYPOSQUATTING 0.05%, DGA_DOMAIN 0.03% |
| snsec-net/dga-detection-drift26dsn | same name | attack (DGA) | 19,950 | 0 | none |
| fox-srt/cobaltstrike-beacon-corpus | same name | attack (C2 hosts) | 19,775 | 0 | none |
| pirocheto/phishing-url | same name | attack (phishing hosts) | 5,715 | 0 | none |
| Tranco top-million crawl, each host once | same name | benign | 198,647 | 0 | none |
| snsec-net/dga-detection-drift26dsn | same name | benign | 20,118 | 0 | none |
| pirocheto/phishing-url | same name | benign | 5,715 | 0 | none |
| Real egress traffic of one small installation | same name | benign | 182 | 0 | none |

Results:

- **Evasion:** every evasion is signalled. One is blocked when the hidden
  name also fails a check of its own:
  - a generated name: mismatch 5 + DGA 6;
  - a lookalike: mismatch 5 + typosquat 5;
  - a metadata host: SSRF-001 alone.
- **Same name:** the second pass of a client that hides nothing signals
  nothing, on 270,102 records.
- **Not checked yet:** whether a host behind the hidden name is a known C2.
  The WAF does not have that detector.

## Plain HTTP or SSL bump: requests

| Dataset | Label | Records | Blocked | Signalled (largest shares) |
|---|---|---|---|---|
| SecureAI-SE/http-attack-requests | attack | 6,000 | 90.48% | DIRECTORY_TRAVERSAL 24.13%, SQL_INJECTION 17.22%, TEMPLATE_INJECTION 16.65%, SSRF 14.22%, XSS_ATTACKS 12.02%, CRS 10.73% |
| Mutations of the above (12 transforms: double encoding, case, comments, fullwidth letters, form, JSON and multipart bodies, parameter pollution, cookie, custom header, base64) | attack | 3,600 | 82.56% | DIRECTORY_TRAVERSAL 25.00%, TEMPLATE_INJECTION 15.28%, SQL_INJECTION 14.28%, SSRF 11.53%, XSS_ATTACKS 10.69%, CRS 8.17% |
| Adversarial suite (`tests/adversarial`) | attack | 29 | 27 of 29 | SQL_INJECTION 7, LOG4SHELL 2, XXE 2, one each in 17 other categories |
| b1nch3f/csic-dataset | attack | 24,668 | 27.24% | CRS 13.75%, SQL_INJECTION 11.52%, XSS_ATTACKS 6.14%, RANSOMWARE 1.46% |
| pirocheto/phishing-url | attack | 5,714 | 0.37% | CRS 1.80%, SQL_INJECTION 0.46% |
| Podric/prowl-secrets-corpus as uploads | attack (secret in a body) | 16,557 | 0.28% | DATA_EXFIL 0.33%, RANSOMWARE 0.21% |
| fox-srt/cobaltstrike-beacon-corpus | attack (beacon requests) | 19,734 | 0.08% | CRS 57.67%, SSRF 0.85%, TYPOSQUATTING 0.11% |
| Tranco top-million crawl | benign | 59,816 | 0.12% | SQL_INJECTION 0.72%, SSRF 0.33%, RANSOMWARE 0.16%, TYPOSQUATTING 0.15%, CRS 0.11% |
| b1nch3f/csic-dataset | benign | 72,000 | 0.008% | RANSOMWARE 1.69%, SQL_INJECTION 0.13% |
| Podric/prowl-secrets-corpus as uploads | benign | 8,046 | 0.01% | RANSOMWARE 0.40% |
| pirocheto/phishing-url | benign | 5,715 | 0 | SQL_INJECTION 0.44% |
| SecureAI-SE/http-attack-requests | benign | 1,000 | 0 | SQL_INJECTION 0.40% |
| Mutations | benign | 3,600 | 0 | none |
| Real egress traffic of one small installation | benign | 420 | 0 | none |

Most beacon requests make a Core Rule Set rule score, but under its block
threshold: 57.67% signalled, 0.08% blocked. The URIs and headers of a C2
profile are visible here, and nothing reads them as such.

## Plain HTTP or SSL bump: responses

| Dataset | Label | Records | Blocked | Signalled |
|---|---|---|---|---|
| Podric/prowl-secrets-corpus as downloads | attack (secret in a body) | 16,557 | 3.38% | RESPONSE_SECRET_LEAK 27.12% |
| Podric/prowl-secrets-corpus as downloads | benign | 8,046 | 0.05% | RESPONSE_SECRET_LEAK 3.00%, HEURISTIC_PII_LEAK 0.01% |
| Tranco top-million crawl, headers only | benign | 30,391 | 0 | none |

A response row names only the response's primary category.

## Not measured here

- **Per-client heuristics.** `wafeval` gives every record its own client
  address, so beaconing (H2) and destination sharding (H4) cannot fire.
  Their absence from the tables means "not measured", not "zero". Sequence
  validation (H7) is off by default and was off here.
- **Per-request heuristics.** Payload entropy (H1) and protocol ghosting
  (H6) were on and scored on none of these records.
- **Detectors the WAF does not have yet.** These rows do not exist:
  - C2 reputation;
  - destinations rare for a client;
  - NXDOMAIN bursts;
  - a fingerprint of the client's TLS handshake (JA4).

## Reproducing

The datasets are not in the repository. `waf-go/tools/wafeval/corpus/`
fetches the ones listed in `datasets.manifest.json`, at the pinned
revisions, and converts them to the `wafeval` record format. Some are under
non-commercial licences; this page reports counts only. Then:

```sh
cd waf-go/tools/wafeval
go run . -engine hybrid -no-latency -out report.json -md report.md <corpus files>
```

The report's `signals` and `signal_records` hold the signalled counts, per
dataset, context and label. `summary` holds the blocked counts.
