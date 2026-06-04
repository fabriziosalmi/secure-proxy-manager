# WebSocket API

The log stream is delivered over a WebSocket connection. Because browsers cannot send custom HTTP headers during the WebSocket handshake, a single-use token is exchanged first.

## Connection flow

1. `GET /api/ws-token` (HTTP Basic or JWT) — fetch a single-use token.
2. Open a WebSocket to `/api/ws/logs?token=<token>` on the same origin as the UI.
3. Receive log entries as JSON messages.

The connection is kept alive by the **server**, which sends WebSocket protocol-level ping control frames roughly every 80 s; browsers answer them automatically. No application-level heartbeat is required — clients do not need to send anything after connecting.

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

The token is single-use, so a second connection attempt with the same token is rejected with **HTTP 401** during the handshake, before the WebSocket upgrade completes (see [Authentication failures](#authentication-failures) below).

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

Every application message is a JSON log entry — there are no sentinel/text messages to filter out.

## Authentication failures

The token is validated **before** the WebSocket upgrade, so authentication problems surface as ordinary HTTP responses on the handshake request rather than as WebSocket close codes:

| Condition | Response |
|---|---|
| `token` query parameter missing | `HTTP 401` — `missing token` |
| token invalid, expired, or already used (single-use) | `HTTP 401` — `invalid or expired token` |

Once the upgrade succeeds, the connection follows standard WebSocket lifecycle close codes (`1000` normal, `1001` going away, `1006` abnormal). The server closes idle connections that stop answering protocol pings after ~90 s.

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
    const log = JSON.parse(event.data);
    console.log(log);
  };

  // No keep-alive code needed: the server sends protocol-level pings and the
  // browser answers them automatically.
  return ws;
}
```

::: info Reverse-proxy note
If you front the UI with your own reverse proxy, ensure the WebSocket upgrade is forwarded: set `Upgrade: websocket` and `Connection: Upgrade`, and use HTTP/1.1.
:::
