# WebSocket API

The log stream is delivered over a WebSocket connection. Because browsers cannot send custom HTTP headers during the WebSocket handshake, a single-use token is exchanged first.

## Connection flow

1. `GET /api/ws-token` (HTTP Basic or JWT) — fetch a single-use token.
2. Open a WebSocket to `/api/ws/logs?token=<token>` on the same origin as the UI.
3. Receive log entries as JSON messages.
4. Send the literal string `ping` periodically to keep the connection alive; the server replies with the literal string `pong`.

## Step 1 — Fetch a token

```
GET /api/ws-token
Authorization: Basic <base64(user:pass)>
```

```json
{ "status": "success", "token": "xK9z2..." }
```

The token is valid for **two minutes** and is consumed on first use.

## Step 2 — Connect

The browser SPA opens the WebSocket on the same origin it was loaded from, so the URL takes the form:

```
wss://<your-host>/api/ws/logs?token=xK9z2...
```

The `web` service proxies the upgrade to the backend on the internal network. If you are connecting from a script running on the host (and only on the host), you can also reach the backend directly at `ws://127.0.0.1:5001/api/ws/logs?token=...`; the backend port is bound to `127.0.0.1` only.

A second connection using the same token is rejected with close code `4003`.

## Step 3 — Receive messages

Each message is a JSON object representing a log entry:

```json
{
  "id": 1234,
  "timestamp": "2026-03-25 14:32:10",
  "client_ip": "192.168.1.10",
  "method": "CONNECT",
  "destination": "example.com:443",
  "status": "200 Connection established",
  "bytes": 4096
}
```

The literal string `pong` (sent in response to a `ping` keep-alive) is the only non-JSON message.

## Close codes

| Code | Meaning |
|---|---|
| `4001` | Token not provided |
| `4003` | Token invalid, expired, or already used |

## JavaScript example

```javascript
async function connectLogs() {
  // Same-origin: cookies / Basic auth handled by the browser.
  const tokenResp = await fetch('/api/ws-token', { credentials: 'include' });
  const { token } = await tokenResp.json();

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url   = `${proto}//${location.host}/api/ws/logs?token=${encodeURIComponent(token)}`;
  const ws    = new WebSocket(url);

  ws.onmessage = (event) => {
    if (event.data === 'pong') return;
    const log = JSON.parse(event.data);
    console.log(log);
  };

  setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send('ping');
  }, 30_000);

  return ws;
}
```

::: info Reverse-proxy note
If you front the UI with your own reverse proxy, ensure the WebSocket upgrade is forwarded: set `Upgrade: websocket` and `Connection: Upgrade`, and use HTTP/1.1.
:::
