# Tests

The suites in this directory, what each needs, and how CI runs it. The Go unit
tests live next to the code (`go test ./...` in `backend-go/` and `waf-go/`),
and the UI unit tests in `ui/src` (`cd ui && npm test`).

| Path | What it tests | Needs | CI check |
|---|---|---|---|
| `e2e.sh` | A running deployment, client side and admin side | A running stack | none |
| `ci-e2e.sh` | Compose up of the full stack and the core path | Docker; a throwaway checkout | *E2E (compose up + smoke)* |
| `e2e/` | Playwright UI suite in a container | `docker-compose.test.yml` | *E2E UI (Playwright)* |
| `adversarial/` | Attacks through the real proxy and WAF, the API boundary, latency, settings, resilience | Docker | *Adversarial block-matrix (proxy + WAF)* |
| `python/` | The proxy watchdog, the cache statistics parser, the MCP server | `pytest` | *Python tests (watchdog)* |
| `shell/generate_squid_conf_test.sh` | The `squid.conf` the generator writes for fixture `/config` states, parsed by Squid | Docker | *Squid config generation* |
| `shell/squid_acl_matrix_test.sh` | The access policy: real Squid, WAF and dnsmasq, clients on three networks | Docker | *Squid config generation* |
| `shell/restore_test.sh` | `scripts/restore.sh` refuses a corrupt backup and keeps `data/` | `sqlite3` | *Restore drill (backup verification)* |
| `shell/ui_tls_entrypoint_test.sh` | The `web` container starts with a certificate in every TLS mode | Docker | *Docker build (all images)* |
| `mock-lists/` | Fixture lists served to the test stack | | |

## e2e.sh: against a running stack

```bash
docker compose up -d                       # the stack must already run
./tests/e2e.sh <host> <user> <password>    # host defaults to localhost
```

It talks to `https://<host>:8443` and to the proxy at `<host>:3128`. It adds
and removes list entries and changes settings, so use a test instance.

## ci-e2e.sh: the CI smoke test

```bash
bash tests/ci-e2e.sh      # from the repository root
```

It writes its own `.env` (overwriting yours), makes `config/` and `data/`
world-writable, changes the owner of `logs/`, runs
`docker compose up -d --build`, waits for the five services, checks proxy
egress, blocking, the log pipeline and the audit log, and on exit runs
`docker compose down -v --remove-orphans` and deletes `.env`. **Never run it
in a checkout that holds a real deployment.**

## e2e/: Playwright

```bash
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner
docker compose -f docker-compose.test.yml down -v
```

The test stack runs the backend, the `web` container, a mock list server and
the Playwright runner; the proxy and the WAF are not part of it.

## adversarial/

```bash
make adversarial          # or: bash tests/adversarial/run.sh
```

See [adversarial/README.md](adversarial/README.md).

## python/

```bash
pytest tests/python -q
```

CI creates a writable `/config` before running it and installs the MCP
server's dependencies (`mcp`, `httpx`) into the pytest environment.

## shell/

```bash
bash tests/shell/generate_squid_conf_test.sh
bash tests/shell/squid_acl_matrix_test.sh
bash tests/shell/restore_test.sh
bash tests/shell/ui_tls_entrypoint_test.sh
```

The first, second and fourth build or use the proxy, WAF, dns and web images;
`restore_test.sh` runs `scripts/restore.sh` in a sandbox with a stub `docker`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full list of CI gates.
