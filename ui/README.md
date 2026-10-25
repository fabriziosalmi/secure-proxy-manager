# Secure Proxy Manager UI

The web UI: React 19, TypeScript, Vite, Tailwind CSS and
`@tanstack/react-query`. In the stack it is built by `ui/Dockerfile` and
served by nginx in the `web` container, which also proxies `/api/` to the
backend (`ui/nginx.conf.template`, `ui/docker-entrypoint.sh`).

## Commands

```bash
npm ci
npm run dev        # Vite dev server; /api is proxied to http://localhost:5001
npm run build      # tsc -b, then vite build into dist/
npm run lint       # ESLint
npm test           # Vitest (jsdom), src/**/*.test.ts(x)
npm run test:e2e   # Playwright, tests-e2e/, against BASE_URL (default http://localhost:5173)
npm run preview    # serve the production build
```

`npm run dev` needs a backend on `http://localhost:5001`, for example the
stack started with `docker compose up -d` from the repository root.

## Layout

| Path | Contents |
|---|---|
| `src/pages/` | One file per page: Dashboard, Analytics, Logs (Access logs), Clients, Blacklists, EgressAllowlist, Settings, Audit, Login |
| `src/components/layout/nav.ts` | The sidebar: its groups, items and order |
| `src/components/settings/` | The Settings sections and their shared parts |
| `src/lib/settingsMeta.ts` | The Settings sections, the keys each saves and how each takes effect |
| `src/lib/` | API client, queries, formatting and validation helpers |
| `src/types.ts` | Shared types |

Text in `src/` must not contain an em dash or an en dash;
`scripts/check-no-dashes.sh` enforces it in CI.
