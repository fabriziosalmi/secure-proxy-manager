# Authentication

Every protected endpoint accepts either of two authentication schemes:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`.
- **JWT bearer.** `Authorization: Bearer <access_token>`.

The two `/health` endpoints are public; everything else under `/api` is authenticated.

```bash
# Basic
curl -u USER:PASS https://localhost:8443/api/...

# JWT (after calling /api/auth/login)
curl -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/...
```

## Endpoints

### Login

```
POST /api/auth/login
```

Validates credentials and returns a JWT pair.

**Request body:**

```json
{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**

```json
{
  "status": "success",
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "Bearer"
}
```

The access token's lifetime is configurable via the `JWT_EXPIRE_DURATION` environment variable (default `8h`); refresh tokens are valid for seven days. Both tokens are HS256-signed with `SECRET_KEY` and carry a `type` claim of `access` or `refresh`. Refresh tokens are rejected on protected endpoints.

### Refresh

```
POST /api/auth/refresh
```

Exchanges a valid refresh token for a fresh access/refresh pair. The refresh token is sent in the request body:

```json
{ "refresh_token": "eyJhbGciOi..." }
```

### Logout

```
POST /api/logout
```

Adds the JWT used to authenticate the request to the persistent revocation list. Subsequent use of the same token is rejected. Basic-auth callers may also call this endpoint, but it is a no-op for them.

### Change password

```
POST /api/change-password
```

**Request body:**

```json
{
  "current_password": "current",
  "new_password": "new_password"
}
```

The new password is bcrypt-hashed and replaces the current hash atomically.

### WebSocket token

```
GET /api/ws-token
```

Returns a single-use token for the log-streaming WebSocket. The token is valid for two minutes and consumed on first connection.

**Response:**

```json
{ "status": "success", "token": "abc123..." }
```

See the [WebSocket documentation](/api/websocket) for the full handshake.

### Health

```
GET /health
GET /api/health
```

No authentication required. Returns service status, version, and any pending update or CVE indicators:

```json
{ "status": "healthy", "version": "3.4.4" }
```

## Rate limiting

Failed authentication attempts are rate-limited per client IP: `MAX_LOGIN_ATTEMPTS` failures (default `5`) within `RATE_LIMIT_WINDOW_SECONDS` (default `300`) trigger HTTP 429 with a `Retry-After` header until the window expires. A separate global token-bucket limiter caps every IP at 20 requests per second sustained, with a 60-request burst.
