# Authentication

Every protected endpoint accepts either scheme:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`.
- **JWT bearer.** `Authorization: Bearer <access_token>`.

No authentication is needed for `POST /api/auth/login`,
`POST /api/auth/refresh`, `GET /api/health`, `GET /api/ready`, `GET /health`,
`GET /livez`, `GET /readyz` and `GET /metrics`. A failed check answers `401`
with a `WWW-Authenticate: Bearer` header.

```bash
# Basic (-k: the certificate is self-signed unless you mounted your own)
curl -k -u admin:PASS https://localhost:8443/api/status

# JWT, after POST /api/auth/login
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/status
```

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

Revokes the bearer token that authenticated the request. An optional body
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
carries a new `access_token` and `refresh_token` for the caller.

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
{ "status": "healthy", "version": "3.14.3", "commit": "...", "runtime": "go" }
```

`GET /health` and `GET /livez` answer `{"status": "healthy"}` without touching
the database. `GET /readyz` and `GET /api/ready` answer
`{"status": "ready"}`, or `503` with `{"status": "unready", "reason": ...}`
when the database does not answer within 2 seconds.

## Rate limiting

Basic authentication attempts, including logins, are counted per client
address before the password is checked and refunded when it is right. With
`MAX_LOGIN_ATTEMPTS` (default 5) counted attempts within
`RATE_LIMIT_WINDOW_SECONDS` (default 300), further attempts answer `429`
(`too many failed attempts, try again later`) until older attempts leave the
window. Separately, every request is limited to 20 per second per client
address with a burst of 60, answered with `429` and `Retry-After: 1`.
