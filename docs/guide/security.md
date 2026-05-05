# Security

## Authentication

The web UI and API accept two authentication schemes interchangeably on every protected endpoint:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`. Credentials are validated against the bcrypt hash stored in the database (with a fallback to the `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` environment values during initial bootstrap).
- **JWT bearer.** `Authorization: Bearer <token>`. Tokens are signed with HS256 using `SECRET_KEY` and carry the claims `sub`, `iat`, `exp`, and `type` (`access` or `refresh`). Refresh tokens are rejected on protected endpoints.

`POST /api/auth/login` accepts a JSON body `{username, password}` and returns both an access token and a refresh token. `POST /api/auth/refresh` exchanges a refresh token for a fresh pair. `POST /api/logout` blacklists the presented JWT (the blacklist is persisted in the `jwt_blacklist` table so it survives restarts).

Passwords are stored using bcrypt. Legacy werkzeug-format hashes (`pbkdf2:sha256:...`) are detected and re-hashed as bcrypt on the first successful login.

## Rate limiting

Two layers of rate limiting are applied:

- **Failed login per client IP.** When `MAX_LOGIN_ATTEMPTS` failures (default `5`) occur within `RATE_LIMIT_WINDOW_SECONDS` (default `300`), further attempts return HTTP 429 with `Retry-After: 1` until the window expires. The lockout list can be inspected at `GET /api/security/rate-limits` and cleared per-IP at `DELETE /api/security/rate-limits/{ip}`.
- **Global per-IP token bucket.** All requests are rate-limited at 20 requests per second sustained, with a 60-request burst. Requests over the limit receive HTTP 429.

When the request originates from a private or loopback address, the client IP is extracted from `X-Forwarded-For`; otherwise the direct `RemoteAddr` is used.

## WebSocket authentication

Browsers cannot send custom headers during a WebSocket handshake, so the log streaming endpoint uses a single-use token:

1. The client calls `GET /api/ws-token` with Basic or JWT authentication.
2. The backend issues a `secrets.token_urlsafe(32)` token, valid for two minutes, single-use.
3. The client connects to `wss://<host>/api/ws/logs?token=<token>`.
4. The token is consumed on the first connection. A second handshake with the same token is rejected.

## SSRF protection

Endpoints that fetch a remote URL — `POST /api/blacklists/import`, `POST /api/ip-blacklist/import`, `POST /api/domain-blacklist/import` — perform DNS resolution before opening the connection and reject any host that resolves to:

- Loopback (`127.0.0.0/8`, `::1`)
- Private RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Unspecified, multicast, or reserved ranges
- The unspecified address `0.0.0.0/8`

The HTTP client used for the download pins to the IP that was resolved during the safety check, so a hostname cannot rebind to a private address between resolution and connection. Imports are capped at 200 MB.

## CORS

The backend only accepts cross-origin requests from origins listed in `CORS_ALLOWED_ORIGINS`. The default is `https://localhost:8443`. Add additional origins as needed:

```bash
# .env
CORS_ALLOWED_ORIGINS=https://localhost:8443,https://proxy.example.com
```

A wildcard (`*`) is stripped at load time and is not accepted.

## Direct-IP blocking

Squid is configured to reject requests to raw IP addresses by default, preventing clients from bypassing the domain blacklist by addressing destinations directly. Add trusted destinations to the **IP whitelist** (`/config/ip_whitelist.txt`, also editable via the UI) to allow specific exceptions; whitelisted IPs are evaluated before the deny rule.

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
- Provision a real certificate via Let's Encrypt when both `LETSENCRYPT_DOMAIN` and `LETSENCRYPT_EMAIL` are set.

If you prefer to terminate TLS on an external reverse proxy (Caddy, Traefik, an upstream Nginx), point it at the unencrypted port `8011`:

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8011;
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

To intercept client traffic without manual proxy configuration on each device, redirect ports 80 and 443 to the proxy on the gateway:

```bash
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80  -j REDIRECT --to-port 3128
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 3128
```

Then enable transparent mode in **Settings → Advanced → Transparent Mode**.

## Changing the admin password

From the UI: **Settings → Security → Change Password**. From the API:

```bash
curl -X POST https://localhost:8443/api/change-password \
  -H "Content-Type: application/json" \
  -u USER:CURRENT_PASSWORD \
  -d '{"current_password": "current", "new_password": "new_strong_password"}'
```

The new password is hashed with bcrypt on the server and replaces the existing hash atomically.
