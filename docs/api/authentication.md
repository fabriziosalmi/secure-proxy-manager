# Authentication

## HTTP Basic Auth

All API endpoints require HTTP Basic Authentication.

```bash
curl -u YOUR_USER:YOUR_PASS http://localhost:8011/api/...
# or
curl -H "Authorization: Basic $(echo -n YOUR_USER:YOUR_PASS | base64)" http://localhost:8011/api/...
```

## Endpoints

### Login

```
POST /api/login
```

Validates credentials. Returns 200 on success.

**Request body:**
```json
{
  "username": "your_username",
  "password": "your_password"
}
```

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

## WebSocket token

WebSocket connections cannot carry HTTP headers, so a single-use token is used.

### Get a WebSocket token

```
GET /api/ws-token
```

Requires Basic Auth. Returns a token valid for 2 minutes, single-use.

**Response:**
```json
{
  "token": "abc123..."
}
```

Use the token to connect to the WebSocket endpoint:

```
ws://HOST:5001/api/ws/logs?token=abc123...
```

See the [WebSocket documentation](/api/websocket) for details.

## Rate limiting

Failed authentication attempts are rate-limited per client IP: 5 failures within 5 minutes triggers an HTTP 429 response with a `Retry-After` indication.
