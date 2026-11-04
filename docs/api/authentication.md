# Authentication

Every protected endpoint accepts any of these:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`.
- **JWT bearer.** `Authorization: Bearer <access_token>`.
- **API token.** `Authorization: Bearer spm_<id>_<secret>`, for scripts and
  tools; see [API tokens](#api-tokens).
- **Session cookie (the dashboard).** `spm_session`, set by a login that sends
  `X-SPM-Session: cookie`. It holds an access token and is `HttpOnly` (script
  in the page cannot read it), `SameSite=Strict`, `Path=/api`, `Secure` when
  the request came over https, and expires with the token. An `Authorization`
  header, when present, is used instead of the cookie.

A request authenticated by the cookie alone that changes state (any method
but `GET`, `HEAD` and `OPTIONS`) must also carry `X-Requested-With: spm` and,
if the browser sends an `Origin`, one that is the dashboard's host over https
or listed in `CORS_ALLOWED_ORIGINS`; otherwise it answers `403`
(`cross-site request refused`). Requests with an `Authorization` header are
not affected. Cross-origin, `X-Requested-With` needs a CORS preflight, which
is answered only for those origins.

No authentication is needed for `POST /api/auth/login`,
`POST /api/auth/refresh`, `GET /api/health`, `GET /api/ready`, `GET /health`,
`GET /livez`, `GET /readyz` and `GET /metrics`. A failed check answers `401`
with a `WWW-Authenticate: Bearer` header.

```bash
# Basic (-k: the certificate is self-signed unless you mounted your own)
curl -k -u admin:PASS https://localhost:8443/api/status

# JWT, after POST /api/auth/login
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/status

# API token, created under Settings > Admin and backup
curl -k -H "Authorization: Bearer spm_..." https://localhost:8443/api/status
```

## API tokens

A script, a monitoring system or the MCP server can authenticate with a token
of its own instead of the admin password. Each token has a name, a scope and
an expiry, and can be revoked alone.

- **Scope.** A `read` token may call `GET` and `HEAD` routes. A `write` token
  may call any method. A read token can read the access log and stream it
  (`GET /api/ws-token`); when GDPR mode is on, client addresses are masked as
  for the dashboard.
- **Refused to every token.** The token routes themselves (a token cannot
  create or revoke tokens), `/api/change-password`, `/api/logout`,
  `/api/auth/*`, `GET /api/database/export`, `POST /api/database/reset`,
  `GET /api/maintenance/backup-config`, `POST /api/maintenance/restore-config`,
  `/api/internal/*` and `/debug/pprof/*`. A token on a route its scope does
  not allow answers `403`.
- **Expiry.** 90 days unless the request gives `expires_in_days` (1 to 3650),
  or `no_expiry: true` for a token that works until it is revoked. An expired
  or revoked token answers `401`.
- **Storage.** The value is shown once, in the answer that creates it. The
  backend keeps only the SHA-256 of its secret (256 random bits) and compares
  in constant time.
- **Audit.** Changes made with a token are recorded under the user
  `token:<name>`, and the token's `last_used_at` is updated at most once a
  minute.
- **Failed attempts.** A wrong token counts against the client address like a
  wrong password (see [Rate limiting](#rate-limiting)).

Only the admin, authenticated by password, session or JWT, can manage
tokens: in the dashboard under Settings > Admin and backup > API tokens, or
with these routes.

```
GET /api/tokens
```

Every token, revoked and expired ones included, newest first. No value is
returned: it is not stored.

```json
{
  "status": "success",
  "data": [
    {
      "id": "3f9a1c0b7d2e",
      "name": "grafana",
      "scope": "read",
      "created_by": "admin",
      "created_at": "2026-11-04T09:00:00Z",
      "expires_at": "2027-02-02T09:00:00Z",
      "last_used_at": "2026-11-04T09:12:00Z",
      "revoked_at": null
    }
  ],
  "meta": { "total": 1, "limit": 1, "offset": 0 }
}
```

```
POST /api/tokens
```

```json
{ "name": "grafana", "scope": "read", "expires_in_days": 90 }
```

`name` is 1 to 64 letters, digits, spaces, dots, underscores or hyphens,
starting with a letter or digit, and unique among the tokens not revoked
(`409` otherwise). `scope` is `read` or `write`. Give `expires_in_days` or
`no_expiry`, not both. The answer is `201` with `Cache-Control: no-store`:

```json
{
  "status": "success",
  "message": "Copy the token now: it is not shown again.",
  "data": {
    "token": "spm_3f9a1c0b7d2e_...",
    "id": "3f9a1c0b7d2e",
    "name": "grafana",
    "scope": "read",
    "created_at": "2026-11-04T09:00:00Z",
    "expires_at": "2027-02-02T09:00:00Z"
  }
}
```

```
DELETE /api/tokens/{id}
```

Revokes the token: it is refused from the next request. A token already
revoked, or an unknown id, answers `404`. The name of a revoked token can be
given to a new one.

## Endpoints

### Login

```
POST /api/auth/login
```

```json
{
  "username": "admin",
  "password": "your_password"
}
```

Both fields are required, at most 128 characters each.

**Response:**

```json
{
  "status": "success",
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "Bearer"
}
```

With the header `X-SPM-Session: cookie` (what the dashboard sends), the
token goes into the `spm_session` cookie instead, no refresh token is issued,
and the answer carries no token:

```json
{ "status": "success", "username": "admin", "expires_at": 1793145676 }
```

`expires_at` is in Unix seconds. The dashboard session lasts
`JWT_EXPIRE_DURATION`; then the dashboard shows the sign-in screen.

Wrong credentials answer `401` (`incorrect username or password`). Both tokens
are HS256, signed with `SECRET_KEY`, with a `type` claim of `access` or
`refresh`. An access token lasts `JWT_EXPIRE_DURATION` (default `8h`; the
shipped compose files do not pass this variable, so it is 8 hours unless you
add it). A refresh token expires seven days after the login it descends from.
Refresh tokens are refused on protected endpoints.

### Refresh

```
POST /api/auth/refresh
```

```json
{ "refresh_token": "eyJhbGciOi..." }
```

Returns a new access and refresh pair, in the login's shape. The refresh token
sent is consumed: a second use answers `401` (`refresh token already used`),
and the new refresh token keeps the original login time, so a chain of
refreshes ends seven days after the login.

### Logout

```
POST /api/logout
```

Revokes the bearer token that authenticated the request, or the session
cookie's token, and then clears the cookie. An optional body
`{"refresh_token": "..."}` revokes that refresh token too, when it belongs to
the same user. Revocations are stored in the database and survive a restart.
Called with Basic authentication and no body, it revokes nothing. If a
revocation cannot be stored, the answer is `500` saying the token may remain
valid until it expires.

### Change password

```
POST /api/change-password
```

```json
{
  "current_password": "current",
  "new_password": "new-strong-passw0rd"
}
```

The new password needs at least 8 characters, a digit and a character that is
neither a letter nor a digit. A wrong `current_password` answers `400`. On
success every token issued before the change stops validating, and the answer
carries a new `access_token` and `refresh_token` for the caller. A caller
authenticated by the session cookie gets a new cookie and `expires_at`
instead, with no token in the body.

### Session

```
GET /api/session
```

```json
{ "status": "success", "data": { "username": "admin", "via": "cookie", "expires_at": 1793145676 } }
```

Who is signed in, how (`cookie`, `bearer`, `basic` or `token`) and, for a
token, when it expires in Unix seconds (`null` for Basic and for an API token
without expiry). With an API token, `username` is `token:<name>` and `scope`
is the token's (`read` or `write`), so a tool can tell what it may do. The dashboard calls it at start,
since it cannot read its own `HttpOnly` cookie. Without credentials it answers
`401`.

### WebSocket token

```
GET /api/ws-token
```

```json
{ "status": "success", "token": "abc123..." }
```

A single-use token for the log feed, valid for two minutes. See
[WebSocket](/api/websocket).

### Health

```
GET /api/health
```

```json
{ "status": "healthy", "version": "3.27.0", "commit": "...", "runtime": "go" }
```

`GET /health` and `GET /livez` answer `{"status": "healthy"}` without touching
the database. `GET /readyz` and `GET /api/ready` answer
`{"status": "ready"}`, or `503` with `{"status": "unready", "reason": ...}`
when the database does not answer within 2 seconds.

## Rate limiting

Basic authentication attempts, including logins, and API token attempts are
counted per client address before the credential is checked and refunded
when it is right. With `MAX_LOGIN_ATTEMPTS` (default 5) counted attempts
within `RATE_LIMIT_WINDOW_SECONDS` (default 300), further attempts are refused
with `too many failed attempts, try again later` until older attempts leave
the window: a login answers `429`, any other request `401`. Separately, every request is limited to 20 per second per client
address with a burst of 60, answered with `429` and `Retry-After: 1`.
