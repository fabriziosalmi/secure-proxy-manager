# Contributing to Secure Proxy Manager

Thank you for your interest! We welcome contributions — bug fixes, features, documentation, and testing.

## Quick Setup

```bash
git clone https://github.com/fabriziosalmi/secure-proxy-manager.git
cd secure-proxy-manager
cp .env.example .env          # edit credentials
docker compose up -d --build  # start all services
./tests/e2e.sh localhost admin your-password  # run tests
```

## Tech Stack

| Component | Technology | Directory |
|-----------|-----------|-----------|
| Backend | Go 1.24 (chi, zerolog, modernc/sqlite) | `backend-go/` |
| WAF Engine | Go (ICAP server, regex + heuristics) | `waf-go/` |
| Frontend | React 19, Vite, TypeScript, Tailwind CSS | `ui/` |
| Proxy | Squid 5.x | `proxy/` |
| DNS | dnsmasq | `dns/` |
| Infra | Docker Compose, Nginx | `docker-compose.yml`, `ui/` |

## Development Workflow

### Backend (Go)

```bash
cd backend-go
go build ./...              # compile
go test -race ./...         # unit tests — CI gates on these AND on 60% coverage
go vet ./...                # static analysis
```

### WAF Engine (Go)

```bash
cd waf-go
go build ./...
go test -v -race ./...      # unit + fuzz tests
```

### Frontend (React/TypeScript)

```bash
cd ui
npm ci                      # install deps
npm test                    # Vitest suites — CI gates on these
npm run lint                # ESLint — CI gates on this
npm run build               # build (includes tsc check)
npx tsc --noEmit            # type check only
```

### Lint (both Go modules)

```bash
golangci-lint run           # from backend-go/ or waf-go/ — CI gates on this
shellcheck --severity=warning proxy/*.sh deploy/*.sh scripts/*.sh tests/*.sh
```

### Full Stack (Docker)

```bash
docker compose build --no-cache web backend waf
docker compose up -d
docker compose logs -f backend  # watch Go backend logs
```

## Coding Standards

### Go
- `gofmt` formatting (enforced by editor)
- Error handling: always check and handle errors, no `_ = err`
- Naming: `camelCase` for unexported, `PascalCase` for exported
- No global mutable state — use dependency injection
- SQL: parameterized queries only, never interpolate user input

### TypeScript/React
- Strict mode (`"strict": true` in tsconfig)
- Typed interfaces in `ui/src/types.ts` — no `any` in business logic
- Functional components with hooks
- `@tanstack/react-query` for all API calls
- Tailwind CSS for styling — no inline styles

### Commit Messages
```
feat: short description (#issue)
fix: short description
docs: short description
chore: short description
```

## Reproducing the CI gates locally

Everything below blocks a merge. Running them before opening a PR avoids a
round trip:

| Command | Gate |
|---|---|
| `cd ui && npm run lint && npm test && npm run build` | UI lint, tests, build |
| `cd backend-go && go build ./... && go vet ./... && golangci-lint run` | Go build, vet, lint |
| `cd backend-go && go test -race ./...` | Backend tests + 60% coverage floor |
| `cd waf-go && go test -race ./...` | WAF tests + 70% coverage floor |
| `shellcheck --severity=warning proxy/*.sh deploy/*.sh scripts/*.sh tests/*.sh` | Shell lint |
| `bash tests/shell/generate_squid_conf_test.sh` | Squid config generation |
| `make adversarial` | Adversarial block-matrix (the suite README leads with) |
| `bash scripts/check-version-sync.sh` | Version consistency |

## E2E Testing

**Prerequisite:** the stack must already be running and reachable — this drives
a live deployment, it does not start one. `docker compose up -d` first.

```bash
# Run full suite (104 checks) against a running stack
./tests/e2e.sh <host> <user> <password>   # host defaults to localhost

# Example
./tests/e2e.sh localhost admin mypassword
./tests/e2e.sh 10.0.0.5 admin mypassword   # a remote deployment
```

The test suite covers:
- **Part A**: Client-side (proxy connectivity, 17 WAF attack vectors, 7 false positives, protocol hardening, latency)
- **Part B**: Admin-side (auth, 9 analytics endpoints, CRUD, settings, toggles, database)
- **Part C**: Advanced (settings persistence, body validation, WAF evasion, concurrent stress, error handling)

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes with clear commit messages
3. Ensure `go build ./...` passes for Go changes
4. Ensure `npm run build` passes for frontend changes
5. Run E2E tests if possible
6. Open a PR with description of what and why

### What blocks a merge

`main` requires a pull request and 17 green checks. The list is not a
convention — it is `.github/branch-protection.json`, applied to GitHub and
checkable against it:

```bash
scripts/branch-protection.sh verify   # diff the live protection against the file
scripts/branch-protection.sh apply    # push the file's state to GitHub (needs admin:repo)
```

Everything in that list is deterministic and derived from the code, so a red
check means the PR broke something. Two checks run but deliberately do **not**
gate: *Verify popular list URLs* reaches third-party hosts, where an upstream
outage would block every unrelated merge, and the CodeQL *Analyze* jobs are
GitHub-managed, where a change to the analysed language set would leave a
required check pending forever. Their findings still surface — in the job log
and in the Security tab.

`apply` restores everything except one field: GitHub's branch-protection API
accepts `allow_force_pushes: false` and silently leaves it enabled. `verify`
compares it, so the gap shows up as drift; fix that one under
**Settings → Branches → main**.

`strict` is on, so a PR must be up to date with `main` before it merges. If
Dependabot churn makes that painful, that is the one setting to relax; the
required-check list is not.

## Reporting Issues

- Use [GitHub Issues](https://github.com/fabriziosalmi/secure-proxy-manager/issues)
- Include: steps to reproduce, expected vs actual behavior, logs
- For security issues: use [Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new) (private)

## Community

- [GitHub Discussions](https://github.com/fabriziosalmi/secure-proxy-manager/discussions) for questions and ideas
- [API Documentation](https://your-host:8443/api/docs) for integration reference

## License

MIT — see [LICENSE](LICENSE)
