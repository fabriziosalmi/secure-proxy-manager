# Security

## Authentication

The web UI and API accept two authentication schemes interchangeably on every protected endpoint:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`. Credentials are validated against the bcrypt hash stored in the database (with a fallback to the `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` environment values during initial bootstrap).
- **JWT bearer.** `Authorization: Bearer <token>`. Tokens are signed with HS256 using `SECRET_KEY` and carry the claims `sub`, `iat`, `exp`, `jti` (unique per token), `pv` (a fingerprint of the current password hash) and `type` (`access` or `refresh`); refresh tokens also carry `auth_time`, the time of the login they descend from. Refresh tokens are rejected on protected endpoints. Changing the password changes `pv`, so every token issued before the change stops validating.

`POST /api/auth/login` accepts a JSON body `{username, password}` and returns both an access token and a refresh token. `POST /api/auth/refresh` exchanges a refresh token for a fresh pair; a refresh token is single-use, and a chain of refreshes ends seven days after the login. `POST /api/logout` blacklists the presented JWT and, when the body carries `{"refresh_token": ...}`, that refresh token too (the blacklist is persisted in the `jwt_blacklist` table so it survives restarts). `POST /api/change-password` ends every earlier session and returns a fresh pair for the caller.

Passwords are stored using bcrypt.

## Rate limiting

Two layers of rate limiting are applied:

- **Failed login per client IP.** When `MAX_LOGIN_ATTEMPTS` failures (default `5`) occur within `RATE_LIMIT_WINDOW_SECONDS` (default `300`), further attempts return HTTP 429 with `Retry-After: 1` until the window expires. The lockout list can be inspected at `GET /api/security/rate-limits` and cleared per-IP at `DELETE /api/security/rate-limits/{ip}`.
- **Global per-IP token bucket.** All requests are rate-limited at 20 requests per second sustained, with a 60-request burst. Requests over the limit receive HTTP 429.

When the request originates from a private or loopback address, the client IP is extracted from `X-Forwarded-For`; otherwise the direct `RemoteAddr` is used.

## WebSocket authentication

Browsers cannot send custom headers during a WebSocket handshake, so the log streaming endpoint uses a single-use token:

1. The client calls `GET /api/ws-token` with Basic or JWT authentication.
2. The backend issues a random token (32 bytes from `crypto/rand`, hex), valid for two minutes, single-use.
3. The client connects to `wss://<host>/api/ws/logs` and offers the token as the subprotocol `spm-ws-token.<token>`, next to `spm.v1`, which the server selects. The token never appears in a URL, so it stays out of access logs, history and Referer headers; a token in the query string is refused.
4. The token is consumed on the first connection. A second handshake with the same token is rejected.

## SSRF protection

Endpoints that fetch a remote URL (`POST /api/blacklists/import`, `POST /api/ip-blacklist/import`, `POST /api/domain-blacklist/import`) perform DNS resolution before opening the connection and reject any host that resolves to:

- Loopback (`127.0.0.0/8`, `::1`)
- Private RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Unspecified, multicast, or reserved ranges
- The unspecified address `0.0.0.0/8`

The HTTP client used for the download pins to the IP that was resolved during the safety check, so a hostname cannot rebind to a private address between resolution and connection. Imports are capped at 32 MB.

## CORS

The backend only accepts cross-origin requests from origins listed in `CORS_ALLOWED_ORIGINS`. The default is `https://localhost:8443`. Add additional origins as needed:

```bash
# .env
CORS_ALLOWED_ORIGINS=https://localhost:8443,https://proxy.example.com
```

A wildcard (`*`) is stripped at load time and is not accepted.

## Direct-IP blocking

Squid is configured to reject requests to raw IP addresses by default, preventing clients from bypassing the domain blacklist by addressing destinations directly. Add trusted destinations to the **IP whitelist** (`/config/ip_whitelist.txt`, also editable via the UI) to allow specific exceptions; whitelisted IPs are evaluated before the deny rule.

## Default-deny egress

The domain and IP blacklists and direct-IP blocking are deny-lists: a client may reach any destination that is not explicitly forbidden. Default-deny egress inverts this for environments that require a strict, allow-only outbound policy. When enabled, the proxy refuses all outbound egress from local clients except destinations on an explicit allowlist; every other destination is denied with an HTTP 403. Restricting outbound traffic to an approved set of endpoints reduces the exfiltration and lateral-movement surface and supports sovereign or strictly scoped egress policies: for example, allowing an application behind the proxy to reach only a CA/ACME server, a package mirror, and an internal API, and nothing else.

This mode is **off by default**. With the `egress_default_deny` setting set to `false` (the default), behaviour is unchanged and clients may reach any destination not on a blacklist. Enabling it only restricts egress; it does not affect any other rule.

To enable it:

1. Turn on the **Default-deny egress** toggle on the **Settings** page (shown next to SSL inspection). This flips the `egress_default_deny` setting, which can also be set through the bulk settings API (`POST /api/settings`).
2. Populate the **Egress Allowlist** page with the destinations clients are permitted to reach. Each entry is either an IP/CIDR or a domain; the type is auto-classified on add (a value that parses as an IP or CIDR is stored as `cidr`, otherwise as `domain`). Entries can be added, deleted, searched, and paginated from the UI or managed through the API.

A local client is allowed only if the destination matches the IP allowlist **or** the domain allowlist; anything else is refused.

### Egress allowlist API

The allowlist endpoints use the same authentication as the rest of the API (HTTP Basic or JWT bearer):

| Method   | Path                              | Description |
| -------- | --------------------------------- | ----------- |
| `GET`    | `/api/egress-allowlist`           | List entries (paginated). |
| `POST`   | `/api/egress-allowlist`           | Add one entry. Body `{"entry": "<ip\|cidr\|domain>", "description": "<optional>"}`. The type is auto-classified. Returns 400 (`entry must be an IP, CIDR, or domain`) for empty or invalid input, 400 (`entry already in allowlist`) for a duplicate, and 200 (`{"status":"success","message":"Entry added to egress allowlist"}`) on success. |
| `DELETE` | `/api/egress-allowlist/{id}`      | Remove one entry by ID. |
| `POST`   | `/api/egress-allowlist/bulk-delete` | Remove entries by a list of IDs. |
| `DELETE` | `/api/egress-allowlist/clear-all` | Remove all entries. |

The `egress_default_deny` toggle itself is set through the bulk settings endpoint, not through this group.

## Database export redaction

`GET /api/database/export` returns a full JSON dump of the database. Any column literally named `password`, `secret`, or `token` (across every exported table) is replaced with the string `***REDACTED***` before serialisation. Sensitive settings stored under those column names are therefore never present in the export.

Setting values that are encrypted at rest (those persisted in `settings` whose key contains `password`, `secret`, `token`, or `webhook`) are encrypted on write using AES with `ENCRYPTION_KEY`; their plaintext values are never returned through the export.

## Backend API binding

The backend container exposes port `5000` internally; the host binding is:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

The API is therefore only reachable from the host machine. All external access goes through the `web` reverse proxy on ports `80`, `443`, `8011`, or `8443`.

## HTTPS for the web UI

The shipped `web` service can either:

- Generate a self-signed certificate and serve HTTPS on `:443` and `:8443` directly, or
- Serve a certificate you mount at `/etc/nginx/ssl/server.crt` and `/etc/nginx/ssl/server.key`.

The shipped image does not include certbot, so it does not obtain Let's Encrypt certificates itself.

If you prefer to terminate TLS on an external reverse proxy (Caddy, Traefik, an upstream Nginx), point it at the HTTPS port `8443` (the upstream certificate is the self-signed one unless you mount your own). Port `8011` answers every path except `/health`, `/wpad.dat` and ACME challenges with a redirect to `https://<host>:8443`, so a reverse proxy pointed at it gets redirects, not the UI:

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:8443;
        # The upstream certificate is SPM's self-signed one unless you mounted
        # your own; trust it explicitly with proxy_ssl_trusted_certificate
        # instead if you can.
        proxy_ssl_verify off;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Transparent proxy {#transparent-proxy}

Transparent (intercepting) proxying is not supported. Squid listens on 3128
as an explicit forward proxy only: there is no `intercept` port, so traffic
redirected to it with iptables is not served, and there is no setting for it in
the UI. Configure clients explicitly, with the PAC file, or with WPAD (see
Settings → Overview → Connect a device).

## Changing the admin password

From the UI: **Settings → Admin and backup → Change Password**. From the API:

```bash
curl -X POST https://localhost:8443/api/change-password \
  -H "Content-Type: application/json" \
  -u USER:CURRENT_PASSWORD \
  -d '{"current_password": "current", "new_password": "new_strong_password"}'
```

The new password is hashed with bcrypt on the server and replaces the existing hash atomically.
