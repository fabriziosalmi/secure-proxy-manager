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
go test -race ./...         # run tests (if any)
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
npm run build               # build (includes tsc check)
npx tsc --noEmit            # type check only
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

## E2E Testing

```bash
# Run full suite (104 checks)
./tests/e2e.sh <host> <user> <password>

# Example
./tests/e2e.sh localhost admin mypassword
./tests/e2e.sh 192.168.1.100 fab secretkey
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

## Reporting Issues

- Use [GitHub Issues](https://github.com/fabriziosalmi/secure-proxy-manager/issues)
- Include: steps to reproduce, expected vs actual behavior, logs
- For security issues: use [Security Advisories](https://github.com/fabriziosalmi/secure-proxy-manager/security/advisories/new) (private)

## Community

- [GitHub Discussions](https://github.com/fabriziosalmi/secure-proxy-manager/discussions) for questions and ideas
- [API Documentation](https://your-host:8443/api/docs) for integration reference

## License

MIT — see [LICENSE](LICENSE)
