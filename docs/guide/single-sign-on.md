# Single sign-on (OpenID Connect)

Admins can sign in to the dashboard with an OpenID Connect provider
(Authentik, Keycloak, Dex, Entra ID, Google and others) instead of the local
admin password. SPM uses the authorization code flow with PKCE and checks the
ID token itself. The decision record is in
[issue #592](https://github.com/fabriziosalmi/secure-proxy-manager/issues/592).

- **Everyone let in is an admin.** SPM has no roles; the allow-list decides
  who may sign in at all.
- **The local admin stays.** By default the password sign-in keeps working
  next to the provider, so a broken provider does not lock you out.
  `OIDC_PASSWORD_LOGIN=false` takes it off the dashboard and keeps it on the
  server, as break-glass: see [Turning the password off](#turning-the-password-off).
- **Sessions last one hour** by default (`OIDC_SESSION_DURATION`), and are not
  renewed: someone removed at the provider is out at the end of the session.
  Changing who may sign in, or switching OIDC off, ends every OIDC session at
  once.
- **The audit log names the person:** `oidc:<email>`.

## At the provider

Register SPM as a confidential client (with a client secret) and give it:

- the redirect URL `https://<dashboard host>:8443/api/auth/oidc/callback`,
  the address you open the dashboard at, with `/api/auth/oidc/callback`;
- the scopes `openid` and `email` (SPM asks for `openid email profile` by
  default);
- if you let people in by group, a claim with the groups (`groups` by
  default).

The provider must send the person's email in the ID token. When it also
sends `email_verified: false`, SPM refuses the sign-in.

## In `.env`

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER` | The provider's issuer URL, `https://`, as its discovery document (`/.well-known/openid-configuration`) gives it. Empty: OIDC is off. |
| `OIDC_CLIENT_ID` | The client id. |
| `OIDC_CLIENT_SECRET` | The client secret. |
| `OIDC_REDIRECT_URL` | The redirect URL registered at the provider. |
| `OIDC_ALLOWED_EMAILS` | Emails that may sign in, comma-separated. |
| `OIDC_ALLOWED_GROUPS` | Groups whose members may sign in, comma-separated. At least one of the two lists is required: nobody is let in by default. |
| `OIDC_GROUPS_CLAIM` | The claim that holds the groups (default `groups`). |
| `OIDC_SCOPES` | Space- or comma-separated (default `openid email profile`). |
| `OIDC_SESSION_DURATION` | How long a sign-in lasts, `5m` to `24h` (default `1h`). |
| `OIDC_LABEL` | The name on the sign-in button (default "single sign-on"). |
| `OIDC_PASSWORD_LOGIN` | `false`: the dashboard refuses the admin password (default `true`). Needs `OIDC_ISSUER`. |

Then restart the backend:

```bash
docker compose up -d backend
```

With `OIDC_ISSUER` set, the backend refuses to start when the rest is wrong
or missing, and its log says which variable. The sign-in page then shows
**Sign in with** and the label.

The backend reaches the provider at `OIDC_ISSUER` from its container, and
checks its certificate. For a provider whose certificate comes from your own
CA, mount the CA certificate into the backend and point `SSL_CERT_FILE` at it,
in a `compose.override.yml`:

```yaml
services:
  backend:
    volumes:
      - ./my-ca.pem:/certs/my-ca.pem:ro
    environment:
      - SSL_CERT_FILE=/certs/my-ca.pem
```

## When a sign-in fails

The browser comes back to the sign-in page with the reason, and the audit log
records `login_failed` with it:

| Reason | What happened |
|---|---|
| `state` | The sign-in expired (after ten minutes) or was finished in another browser. |
| `provider` | The provider refused the sign-in. |
| `exchange`, `token` | The provider's answer could not be verified: the code was already used, or the ID token has the wrong issuer, audience, nonce or expiry. |
| `not_allowed` | The person is in neither allow-list. |
| `unverified_email` | The provider says the email is not verified. |
| `no_email` | The ID token has no email: the client needs the `email` scope. |
| `unavailable` | The provider could not be reached. |

## Signing out

**Sign out** ends the SPM session. When the provider's discovery document
advertises an `end_session_endpoint`, the browser is then sent there, so the
person is signed out at the provider too, and comes back to the dashboard.
Register `https://<dashboard host>:8443/` as a post-logout redirect URL at the
provider for that. Dex does not advertise one.

## Turning the password off

With `OIDC_PASSWORD_LOGIN=false`, the sign-in page offers only the provider,
and the backend refuses the admin password in every form when the request
came through the dashboard:

- `POST /api/auth/login` answers `403` before the password is checked, so
  these attempts do not count toward the lockout. The audit log records
  `login_failed` with `password_off`, once per client address within
  `RATE_LIMIT_WINDOW_SECONDS`.
- Basic authentication answers `401`, and so do the access tokens and session
  cookies a password sign-in issued. A refresh answers `403`.

People signed in with the provider, and API tokens, are not affected. A
session the admin opened through the dashboard before the change is refused
from its next request.

The backend tells the dashboard apart by its headers, not by the client's
address. nginx sets `X-Forwarded-For` and `X-Real-IP` on every request it
passes to `/api/`, replacing what the client sent, so no client of the
dashboard arrives without them. The address would not do: a browser on the
server itself reaches nginx from the Docker gateway's address, and with some
Docker setups clients on the network do too.

### Break-glass

The backend's own port, `127.0.0.1:5001` in the shipped compose files, is not
behind nginx, so the password works there. It answers only on the server:

```bash
# On the server, or through a tunnel: ssh -L 5001:127.0.0.1:5001 <server>
curl -u admin:PASS http://127.0.0.1:5001/api/status
```

That port serves the API, not the dashboard, and a session signed in there is
refused through the dashboard. To get the dashboard back with the password,
set `OIDC_PASSWORD_LOGIN=true` in `.env` and restart the backend:

```bash
docker compose up -d backend
```

What else reaches the backend without nginx, and can still use the password:

- containers on SPM's Docker network (`backend:5000`);
- a reverse proxy of your own in front of the backend's port, unless it sets
  `X-Forwarded-For`;
- with Docker before 28.0, hosts on the same network segment as the server,
  which can reach ports published on `127.0.0.1`
  ([Docker's documentation](https://docs.docker.com/engine/network/port-publishing/)).

## Example: Dex

This configuration, with test host names in place of these, was run end to
end against the backend: a sign-in, a person not in the allow-list, the
session, a replayed callback and sign-out. Replace the host names, the secret
and the password hash.

`dex.yaml`:

```yaml
issuer: https://dex.example.com:5556/dex
storage:
  type: memory
web:
  https: 0.0.0.0:5556
  tlsCert: /certs/dex.pem
  tlsKey: /certs/dex.key
oauth2:
  skipApprovalScreen: true
staticClients:
  - id: secure-proxy-manager
    secret: a-long-random-secret
    name: Secure Proxy Manager
    redirectURIs:
      - https://spm.example.com:8443/api/auth/oidc/callback
enablePasswordDB: true
staticPasswords:
  - email: alice@example.com
    hash: "<bcrypt hash of the password>"
    username: alice
    userID: 08a8684b-db88-4b73-90a9-3cd1661f5466
```

`.env`:

```bash
OIDC_ISSUER=https://dex.example.com:5556/dex
OIDC_CLIENT_ID=secure-proxy-manager
OIDC_CLIENT_SECRET=a-long-random-secret
OIDC_REDIRECT_URL=https://spm.example.com:8443/api/auth/oidc/callback
OIDC_ALLOWED_EMAILS=alice@example.com
OIDC_LABEL=Dex
```

Dex's static users carry no groups; use `OIDC_ALLOWED_EMAILS` with them, or a
Dex connector that provides groups.
