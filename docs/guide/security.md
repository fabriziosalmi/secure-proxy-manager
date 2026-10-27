# Security

## Authentication

Every protected endpoint accepts either scheme:

- **HTTP Basic.** `Authorization: Basic base64(user:pass)`, checked against the
  bcrypt hash stored in the database. Only when no hash is stored yet (first
  start, before the user row exists) is the password compared with
  `BASIC_AUTH_PASSWORD`.
- **JWT bearer.** `Authorization: Bearer <token>`. Tokens are HS256, signed
  with `SECRET_KEY`, and carry `sub`, `iat`, `exp`, `jti`, `pv` (a fingerprint
  of the current password hash) and `type` (`access` or `refresh`); refresh
  tokens also carry `auth_time`, the time of the login they descend from.
  Refresh tokens are refused on protected endpoints. Changing the password
  changes `pv`, so every token issued before the change stops validating.

`POST /api/auth/login` takes `{username, password}` and returns an access token
and a refresh token. `POST /api/auth/refresh` exchanges a refresh token for a
new pair; a refresh token works once, and a chain of refreshes ends seven days
after the login. `POST /api/logout` revokes the bearer token of the request
and, when the body carries `{"refresh_token": ...}` for the same user, that
refresh token too; revocations are stored in the `jwt_blacklist` table and
survive a restart. `POST /api/change-password` ends every earlier session and
returns a new pair for the caller.

## Rate limiting

- **Failed logins per client address.** Every Basic authentication attempt
  (including `POST /api/auth/login`) is counted before the password is checked
  and refunded when it succeeds. With `MAX_LOGIN_ATTEMPTS` (default 5) counted
  attempts in the last `RATE_LIMIT_WINDOW_SECONDS` (default 300), further
  attempts get HTTP 429 until older ones leave the window. The current counts
  are at `GET /api/security/rate-limits`; `DELETE /api/security/rate-limits/{ip}`
  clears one address.
- **All requests per client address.** A token bucket of 20 requests per
  second with a burst of 60; over it, HTTP 429 with `Retry-After: 1`. nginx
  also limits `/api/` to 20 requests per second with a burst of 40.

The client address is the first `X-Forwarded-For` entry when the request comes
from a private or loopback address (nginx sets it to the real client),
otherwise the connection's address.

## WebSocket authentication

Browsers cannot send an `Authorization` header with a WebSocket handshake, so
the log feed uses a single-use token:

1. The client calls `GET /api/ws-token` with Basic or JWT authentication.
2. The backend returns a random token (32 bytes from `crypto/rand`, hex),
   valid for two minutes.
3. The client connects to `wss://<host>/api/ws/logs` offering two
   subprotocols, `spm.v1` and `spm-ws-token.<token>`; the server selects
   `spm.v1`. The token is never in the URL.
4. The token is consumed by the first handshake that presents it.

The handshake is also refused when its `Origin` is neither in
`CORS_ALLOWED_ORIGINS` nor the host the page was served from.

## SSRF protection

`POST /api/blacklists/import` with a `url`, the automatic refresh and the
default country feeds fetch remote content. The host is resolved first and the
request is refused if any address is private (RFC 1918, IPv6 unique-local),
loopback, link-local, multicast, unspecified, in `0.0.0.0/8` or in the CGNAT
range `100.64.0.0/10`. The HTTP client checks the addresses again when it
dials, so a name that changes its answer between the check and the connection
is still refused, and repeats the check on each of at most five redirects.
Downloads are limited to 32 MB.

## CORS

The backend names an origin in `Access-Control-Allow-Origin` only when it is in
`CORS_ALLOWED_ORIGINS` (default `https://localhost:8443`) or is the request's
own host. `*` is dropped when the variable is read.

```bash
# .env
CORS_ALLOWED_ORIGINS=https://localhost:8443,https://proxy.example.com
```

## Direct-IP blocking

Squid always refuses URLs and `CONNECT` targets that are a literal IPv4 or IPv6
address, so a client cannot skip the domain lists by using an address. Allowed
IPs and LAN destinations (`10.0.0.0/8`, `192.168.0.0/16`) are allowed before
that rule.

## Proxy login

With Require proxy login on (Settings > Clients and access > Login,
`enable_proxy_auth`), a client signs in to the proxy with HTTP Basic before it
can browse; without valid credentials Squid answers `407 Proxy Authentication
Required`. localhost is exempt, for the proxy container's own probes.

The credentials are the proxy's own, `proxy_auth_username` and
`proxy_auth_password`, set on the same page. Devices enter them in their proxy
settings. They are not the dashboard login: the admin password never reaches
the proxy container, and changing it does not change them.

- The password is a write-only secret (see
  [Secrets at rest](#secrets-at-rest-and-in-exports)).
- The backend writes `config/proxy_users.htpasswd`: one line with the username
  and a bcrypt hash of the password, replaced atomically, mode `0640`, group
  `proxy` (gid 13). Squid's `basic_ncsa_auth` helper, which runs as the proxy
  user, reads it through that group, so a new password works at once, before
  the proxy reloads. The backend has no capabilities; it may set the group
  because both compose files add gid 13 to it (`group_add`). The proxy's
  generator also sets `root:proxy` on every run. Turning login off, or
  removing a credential, removes the file.
- A backend run without `group_add: ["13"]` (an older or edited compose file)
  cannot set the group and logs a warning saying so: until the proxy reloads,
  which the backend asks for right after the write, a credential Squid has
  not cached yet gets `407`; Squid keeps running.
- Login cannot be saved on without both credentials (`400`). If the proxy
  still finds login on with no user in the password file, as an install
  upgraded with login on and no stored credentials does, it refuses every
  client except localhost with `403` (block reason `proxy_auth_unset`), logs a
  warning, and the dashboard shows "Proxy login is on but no proxy credentials
  are set: every client is refused until you set them" until credentials are
  set or login is turned off.
- An operator who passes `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` to the
  proxy container by hand (no shipped compose file does) still gets the
  password file created from them when none exists. Credentials set in
  Settings replace that file.

## Default-deny egress

The blocked lists and direct-IP blocking are deny-lists: a client reaches any
destination that is not forbidden. Default-deny egress inverts this: local
clients reach only the destinations on the egress allowlist, LAN destinations
and Allowed IPs, and everything else gets HTTP 403 from Squid.

It is **off by default** (`egress_default_deny` is `false`). Turn it on in
Settings > Filtering > Only allowlisted destinations, and manage the
destinations on the Egress allowlist page. The API is described in
[Lists](./blacklists.md#destination-allowlist-default-deny-egress) and
[the egress allowlist API](/api/blacklists#egress-allowlist).

If the proxy cannot insert its egress rule where it belongs, it replaces the
rule that allows local clients with a deny, so the failure blocks traffic
rather than letting it through.

## Secrets at rest and in exports

The alert channel settings (`webhook_url`, `webhook_bearer_token`,
`gotify_url`, `gotify_token`, `teams_webhook_url`, `telegram_bot_token`,
`telegram_chat_id`, `ntfy_url`, `ntfy_topic`) and the proxy login password
(`proxy_auth_password`) are encrypted with AES-256-GCM
under `ENCRYPTION_KEY`, or under the key the backend generates in
`data/.enc_key` when that is unset. `GET /api/settings` never returns their
values.

`GET /api/database/export` writes every column named `password`, `secret` or
`token` as `***REDACTED***` (the admin password hash is one). The alert channel
secrets are in the `setting_value` column, so the export carries them in their
encrypted form (`enc::...`), not in clear. The configuration backup
(`GET /api/maintenance/backup-config`) does the same.

## Backend API binding

The backend listens on port 5000 inside its container and is published as:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

It is reachable from the host only. From the network, the API is reached
through the `web` service on ports 443 and 8443.

## HTTPS for the web UI

The `web` service serves a certificate you mount at
`/etc/nginx/ssl/server.crt` and `/etc/nginx/ssl/server.key`, or generates a
self-signed one at start. The image has no certbot, so it does not obtain Let's
Encrypt certificates itself.

To terminate TLS on your own reverse proxy (Caddy, Traefik, nginx), point it at
port 8443. Port 8011 redirects everything except `/health`, `/wpad.dat` and
ACME challenge paths to `https://<host>:8443`, so a reverse proxy pointed at it
gets redirects, not the UI. Forward the WebSocket upgrade for `/api/ws/`:

```nginx
server {
    listen 443 ssl http2;
    server_name proxy.example.com;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        proxy_pass https://127.0.0.1:8443;
        # The upstream certificate is SPM's self-signed one unless you mounted
        # your own; trust it with proxy_ssl_trusted_certificate if you can.
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

Transparent (intercepting) proxying is not supported. Squid listens on 3128 as
an explicit forward proxy only: there is no `intercept` port, so traffic
redirected to it with iptables is not served, and there is no setting for it in
the UI. Configure clients explicitly or with the PAC file (Settings > Overview >
Connect a device).

## Changing the admin password

In the UI: **Settings > Admin and backup > Admin password**. Through the API:

```bash
curl -k -X POST https://localhost:8443/api/change-password \
  -H "Content-Type: application/json" \
  -u admin:CURRENT_PASSWORD \
  -d '{"current_password": "CURRENT_PASSWORD", "new_password": "new-strong-passw0rd"}'
```

The new password must have at least 8 characters, a digit and a character that
is neither a letter nor a digit. It is stored as a bcrypt hash.
