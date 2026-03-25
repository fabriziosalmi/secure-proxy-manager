# Security

## Authentication

The web UI and API use HTTP Basic Authentication. Credentials are set via `BASIC_AUTH_USERNAME` and `BASIC_AUTH_PASSWORD` in `.env`.

Passwords are stored in the SQLite database using bcrypt. Legacy werkzeug hashes (`pbkdf2:sha256:...`) are supported for migration: if a stored hash is in werkzeug format, the supplied password is compared against the environment variable directly, then the hash is re-stored as bcrypt on first successful login.

### Rate limiting

Authentication attempts are rate-limited per client IP:

- 5 failed attempts within a 5-minute window trigger an HTTP 429 response
- The lockout clears automatically after the window expires

## WebSocket Authentication

The browser cannot send HTTP headers during a WebSocket handshake. The log streaming endpoint uses a one-time token instead:

1. Client fetches `GET /api/ws-token` (authenticated via Basic Auth)
2. Server generates a `secrets.token_urlsafe(32)` token valid for 2 minutes, single-use
3. Client connects to `ws://host:5001/api/ws/logs?token=<token>`
4. Server consumes the token on first use — replay is not possible

## SSRF Protection

Import endpoints (`/api/blacklists/import`) that accept a URL perform DNS resolution and reject destinations that resolve to:

- Loopback addresses (`127.0.0.0/8`, `::1`)
- Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fd00::/8`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Reserved/unspecified/multicast ranges

This prevents an attacker from using the import endpoint to scan or access internal network services.

## CORS

The backend API only accepts requests from origins listed in `CORS_ALLOWED_ORIGINS`. Default: `http://localhost:8011,http://web:8011`.

To allow access from an additional origin:

```bash
# In .env
CORS_ALLOWED_ORIGINS=http://localhost:8011,http://web:8011,https://proxy.yourdomain.com
```

## Direct IP Block

Squid is configured to reject requests to raw IP addresses by default. This prevents clients from bypassing domain filtering by using IP addresses directly.

To allow access to specific IP destinations (e.g., LAN NAS), add them to the **IP Whitelist** in the web UI. Whitelisted IPs are evaluated before the deny rules.

## Database Export Redaction

`GET /api/database/export` redacts these settings fields before returning the export:

- `gotify_token`
- `telegram_bot_token`
- `webhook_url`
- `teams_webhook_url`
- `siem_host`
- `siem_port`

All are replaced with `***REDACTED***`.

## Backend API Binding

By default, the backend container exposes port 5001 bound to `127.0.0.1` only:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

This means the backend API is not reachable from other machines on the network. All external access goes through the UI proxy on port 8011.

## HTTPS for the Web UI

For production deployments, put a TLS-terminating reverse proxy in front of port 8011:

**Nginx example:**
```nginx
server {
    listen 443 ssl;
    server_name proxy.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/proxy.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8011;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

## Transparent Proxy Setup {#transparent-proxy}

To intercept traffic without client configuration:

```bash
# On the gateway machine
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 3128
```

Enable transparent mode in **Settings → Advanced → Transparent Mode**.

## Changing the Admin Password

Use the **Settings → Security → Change Password** section in the web UI, or via API:

```bash
curl -X POST http://localhost:8011/api/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n USER:CURRENT_PASS | base64)" \
  -d '{"current_password": "current", "new_password": "new_strong_password"}'
```
