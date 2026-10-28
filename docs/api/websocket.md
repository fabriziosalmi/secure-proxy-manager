# WebSocket API

The live log feed is a WebSocket. Browsers cannot send an `Authorization`
header with the handshake, so a single-use token is fetched first.

## Connection flow

1. `GET /api/ws-token` (HTTP Basic or JWT): fetch a single-use token.
2. Open a WebSocket to `/api/ws/logs` on the same origin as the UI, offering
   the subprotocols `spm.v1` and `spm-ws-token.<token>`.
3. Receive log rows as JSON messages.

The server sends a WebSocket ping control frame about every 81 seconds and
closes a connection that has not answered within 90 seconds. Browsers answer
pings on their own; a client sends nothing after connecting, and anything it
sends is discarded.

## Step 1: fetch a token

```
GET /api/ws-token
Authorization: Basic <base64(user:pass)>
```

```json
{ "status": "success", "token": "xK9z2..." }
```

The token is valid for **two minutes** and is consumed by the first handshake
that presents it.

## Step 2: connect

The token is not part of the URL. It is offered as a subprotocol next to the
fixed `spm.v1`, which is the one the server selects (a browser closes the
connection when it offers subprotocols and the server selects none):

```js
new WebSocket('wss://<your-host>/api/ws/logs', ['spm.v1', 'spm-ws-token.xK9z2...'])
```

The `web` service forwards the upgrade to the backend. From the host itself you
can also connect to the backend directly at `ws://127.0.0.1:5001/api/ws/logs`
with the same two subprotocols.

The handshake is refused when its `Origin` header is set and is neither listed
in `CORS_ALLOWED_ORIGINS` nor on the host name the request was sent to.

## Step 3: receive messages

Each message is one row just stored in the access log:

```json
{
  "id": 1234,
  "timestamp": "2026-03-25 14:32:10",
  "unix_timestamp": 1774449130,
  "source_ip": "192.168.1.10",
  "method": "CONNECT",
  "destination": "example.com:443",
  "status": "TCP_TUNNEL/200",
  "bytes": 4096,
  "elapsed_ms": 12,
  "blocked": 0,
  "event_id": "",
  "reason": "none",
  "reason_label": "Not blocked",
  "internal": false,
  "kind": "Private network address",
  "resolved_ip": "93.184.216.34"
}
```

`id`, `reason`, `reason_label`, `internal`, `kind` and `resolved_ip` mean what they mean in
`GET /api/logs` (see [Logs](./logs.md)); `blocked` is `0` or `1` here. The feed
carries every row, the stack's own traffic included: a client that shows the
log with filters applies them to each message. With `gdpr_mode` on, `source_ip`
is masked to `/24` for IPv4 (`192.168.1.x`) and `/64` for IPv6
(`2001:db8:1:2::x`), as it is in `GET /api/logs`; `internal` and `kind` are
worked out from the real address before masking.

The same connection also carries events with a `type` field, such as
`{"type": "login_failure", "data": {...}}` for a failed sign-in. A client that
wants only log rows skips any message with a `type`.

## Authentication failures

The token is checked **before** the upgrade, so a failure is an ordinary HTTP
response to the handshake:

| Condition | Response |
|---|---|
| No `spm-ws-token.<token>` subprotocol offered | `401`, `missing token` |
| Token unknown, expired or already used | `401`, `invalid or expired token` |

A token in the query string is not read: the handshake answers `401`,
`missing token`.

## JavaScript example

```javascript
async function connectLogs(authHeader) {
  const tokenResp = await fetch('/api/ws-token', { headers: { Authorization: authHeader } });
  const { token } = await tokenResp.json();

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url   = `${proto}//${location.host}/api/ws/logs`;
  // The token travels as a subprotocol, never in the URL; spm.v1 is the one
  // the server selects, which the browser requires.
  const ws    = new WebSocket(url, ['spm.v1', `spm-ws-token.${token}`]);

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type) return; // an event, not a log row
    console.log(msg);
  };
  return ws;
}
```

::: info Reverse-proxy note
If you put your own reverse proxy in front of the UI, forward the WebSocket
upgrade: HTTP/1.1 with `Upgrade: websocket` and `Connection: Upgrade`.
:::
