# Contributing to Secure Proxy Manager

Contributions are welcome: bug fixes, features, documentation and tests.

## Quick Setup

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
cp .env.example .env          # set BASIC_AUTH_PASSWORD and INTERNAL_ALERT_TOKEN
docker compose up -d --build  # build and start every service
./tests/e2e.sh localhost admin your-password   # end-to-end checks against it
```

## Tech Stack

| Component | Technology | Directory |
|-----------|-----------|-----------|
| Backend | Go (module `go 1.26`; CI and images build with 1.27), chi, zerolog, modernc.org/sqlite | `backend-go/` |
| WAF | Go ICAP server, regex rules and heuristics | `waf-go/` |
| Frontend | React 19, Vite, TypeScript, Tailwind CSS | `ui/` |
| Proxy | Squid 7 (`squid-openssl` from Ubuntu 26.04) | `proxy/` |
| DNS | dnsmasq on Alpine | `dns/` |
| MCP server | Python, `mcp` and `httpx` | `mcp/` |
| Infra | Docker Compose, nginx | `docker-compose.yml`, `deploy/`, `ui/` |

## Development Workflow

### Backend (Go)

```bash
cd backend-go
go build ./...
go test -race ./...         # CI also requires 60% total coverage
go vet ./...
```

### WAF (Go)

```bash
cd waf-go
go build ./...
go test -race ./...         # CI also requires 70% total coverage
go test -run '^$' -bench . -benchmem ./...   # benchmarks, see BENCHMARKS.md
```

### Frontend (React/TypeScript)

```bash
cd ui
npm ci
npm test                    # Vitest
npm run lint                # ESLint
npm run build               # tsc -b and vite build
npx tsc --noEmit            # type check only
```

### Full stack (Docker)

```bash
docker compose build web backend waf proxy dns
docker compose up -d
docker compose logs -f backend
```

## Coding Standards

### Go
- `gofmt` formatting; `golangci-lint` (configuration in `.golangci.yml`) gates CI
- Handle every error; do not discard it
- SQL: parameterized queries only, never interpolate user input
- Prefer passing dependencies over package-level mutable state

### TypeScript/React
- Strict mode (`"strict": true` in `ui/tsconfig.app.json`)
- Shared types in `ui/src/types.ts`; no `any` in business logic
- Functional components with hooks
- `@tanstack/react-query` for API data
- Tailwind CSS for styling

### Text
- No em dash or en dash in `ui/src`, `docs/` or any Markdown file:
  `scripts/check-no-dashes.sh` fails the build on one.

### Commit Messages

Conventional Commits with a scope, and a subject that states the resulting
behaviour:

```
feat(blacklists): an import past the domain limit is refused whole
fix(proxy): the egress rule is inserted before the first localnet allow
docs(api): the WebSocket page documents the spm.v1 subprotocol
chore(release): v3.14.3
```

## Reproducing the CI gates locally

Each of these runs in a required check. Running them before opening a pull
request saves a round trip:

| Command | Gate |
|---|---|
| `cd ui && npm run lint && npm test && npm run build` | UI lint, tests, build |
| `cd backend-go && go build ./... && go vet ./... && golangci-lint run` | Go build, vet, lint |
| `cd backend-go && go test -race ./...` | Backend tests and the 60% coverage floor |
| `cd waf-go && go test -race ./...` | WAF tests and the 70% coverage floor |
| `shellcheck --severity=warning proxy/*.sh deploy/*.sh scripts/*.sh tests/*.sh tests/shell/*.sh` | Shell lint |
| `ruff check proxy/ mcp/` | Python lint |
| `pytest tests/python -q` | Python tests (watchdog, cache statistics, MCP server) |
| `bash tests/shell/restore_test.sh` | Restore drill |
| `docker compose -f docker-compose.yml config -q` | Compose validation |
| `cd backend-go && gosec -severity medium -confidence medium ./...` | Security scanning (backend half) |
| `bash tests/shell/generate_squid_conf_test.sh` and `bash tests/shell/squid_acl_matrix_test.sh` | Squid config generation and access policy |
| `make adversarial` | Adversarial harness (all five planes) |
| `bash scripts/check-version-sync.sh`, `scripts/check-waf-keys.sh`, `scripts/check-image-pins.sh`, `scripts/check-no-dashes.sh` | Version sync job |
| `bash scripts/check-config-contract.sh` | `/config` file names agree across Go, Python and shell |

The other required checks need to build and start whole stacks or download
scanners: the image build, the compose-up smoke test (`tests/ci-e2e.sh`), the
Playwright suite (`docker-compose.test.yml`), Trivy and the licence inventory.

`scripts/pre-commit-validate.sh` runs the TypeScript check, ESLint, `go vet`,
the Go tests and the UI build in one go.

`scripts/local-ci.sh [worktree] [log_dir]` runs all 26 required CI gates
locally, in a linked worktree only (`git worktree add`), (including the Docker stack suites, Playwright and Trivy) and writes a
summary table to `<log_dir>/results.txt`; see [tests/README.md](tests/README.md)
for prerequisites and details.

## End-to-end tests

`tests/e2e.sh` drives a running deployment; it does not start one. Run
`docker compose up -d` first.

```bash
./tests/e2e.sh <host> <user> <password>   # host defaults to localhost
./tests/e2e.sh localhost admin mypassword
./tests/e2e.sh 10.0.0.5 admin mypassword  # a remote deployment
```

It uses `https://<host>:8443` and the proxy at `<host>:3128`, in three parts:
client-side (proxy connectivity, WAF attack and false-positive cases, protocol
hardening, latency), admin-side (authentication, analytics endpoints, list
changes, settings, database) and advanced (persistence, body validation, WAF
evasion, concurrency, error handling). It changes lists and settings, so point
it at a test instance.

`tests/ci-e2e.sh` is different: it writes its own `.env`, starts the stack,
and on exit deletes `.env` and runs `docker compose down -v`. Run it only in a
throwaway checkout. See [tests/README.md](tests/README.md) for every suite.

## Pull Request Process

1. Fork the repository and create a branch.
2. Make the change, with commit messages as above.
3. Run the gates that apply to what you changed (table above).
4. Open a pull request saying what changed and why.

### What blocks a merge

`main` requires a pull request and every check listed in
`.github/branch-protection.json`. The file is applied to GitHub and can be
compared with it:

```bash
scripts/branch-protection.sh verify   # diff the live protection against the file
scripts/branch-protection.sh apply    # push the file's state to GitHub (needs admin rights)
```

Two checks run but do **not** gate: *Verify popular list URLs* reaches
third-party hosts, where an upstream outage would block every unrelated
merge, and the CodeQL *Analyze* jobs are managed by GitHub. Their findings
still show in the job log and in the Security tab. The URL check
(`scripts/check-list-urls.sh`) reports a host that never answers as a warning
and fails only on a status other than 200, so a red run there is a list that
moved or vanished.

`apply` cannot set one field: GitHub's branch-protection API accepts
`allow_force_pushes: false` and leaves it as it was. `verify` compares it, so
the gap shows as drift; fix that one under **Settings > Branches > main**.

`strict` is on, so a pull request must be up to date with `main` before it
merges.

## Reporting Issues

- Use [GitHub Issues](https://github.com/fabriziosalmi/secure-proxy-manager/issues)
- Include steps to reproduce, expected and actual behaviour, and logs
- For security issues use [Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new) (private)

## Community

- [GitHub Discussions](https://github.com/fabriziosalmi/secure-proxy-manager/discussions) for questions and ideas
- A running backend lists its routes at `GET /api/docs` (authenticated); the
  [API reference](docs/api/reference.md) describes them

## License

MIT (see [LICENSE](LICENSE))
