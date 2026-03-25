# WebSocket API

The log streaming endpoint uses a WebSocket connection. Because browsers cannot send HTTP headers during a WebSocket handshake, a one-time token is used for authentication.

## Connection flow

1. Fetch a token via `GET /api/ws-token` (HTTP Basic Auth required)
2. Connect to the WebSocket endpoint with the token as a query parameter
3. Receive log entries as JSON messages in real time
4. Send `ping` periodically to keep the connection alive; server responds with `pong`

## Step 1 — Fetch a token

```
GET /api/ws-token
Authorization: Basic <base64(user:pass)>
```

**Response:**
```json
{
  "token": "xK9z2..."
}
```

The token is valid for **2 minutes** and can only be used **once**.

## Step 2 — Connect

Connect directly to the backend port (5001), not through the UI proxy:

```
ws://HOST:5001/api/ws/logs?token=xK9z2...
```

The token is consumed on connection. A second connection attempt with the same token returns code `4003`.

## Step 3 — Receive messages

Each message is a JSON object representing a single log entry:

```json
{
  "id": 1234,
  "timestamp": "2026-03-25T14:32:10",
  "client_ip": "192.168.1.10",
  "method": "CONNECT",
  "destination": "example.com:443",
  "status": "200 Connection established",
  "bytes": 4096
}
```

The `pong` string (in response to a `ping` keep-alive) is the only non-JSON message.

## Close codes

| Code | Meaning |
|---|---|
| `4001` | Token not provided |
| `4003` | Token invalid, expired, or already used |

## JavaScript example

```javascript
async function connectLogs(user, pass) {
  const base64 = btoa(`${user}:${pass}`);
  const { data } = await fetch('/api/ws-token', {
    headers: { Authorization: `Basic ${base64}` }
  }).then(r => r.json());

  const ws = new WebSocket(
    `ws://${window.location.hostname}:5001/api/ws/logs?token=${encodeURIComponent(data.token)}`
  );

  ws.onmessage = (event) => {
    if (event.data === 'pong') return;
    const log = JSON.parse(event.data);
    console.log(log);
  };

  setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send('ping');
  }, 30000);

  return ws;
}
```

::: info Reverse proxy note
The WebSocket connection goes directly to port 5001, bypassing the UI proxy at port 8011. If you run behind a reverse proxy, ensure port 5001 is also proxied with WebSocket upgrade support (`Upgrade: websocket`, `Connection: Upgrade`).
:::
