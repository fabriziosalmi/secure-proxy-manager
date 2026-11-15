# Command line (spm)

`spm` calls the management API from a terminal with an
[API token](/api/authentication#api-tokens). It knows the operations of its own
release from the OpenAPI document it is built with, and it pins the certificate
of a server whose certificate no public authority signed, such as the
self-signed one the `web` service makes.

## Build it

From a checkout of the release you run:

```bash
cd backend-go
go build -o spm ./cmd/spm
./spm version
```

## Sign in

Create a token in Settings > Admin and backup > API tokens (`read` to look,
`write` to change), then:

```bash
spm login --url https://HOST:8443 --token spm_...
```

When the server's certificate is not signed by an authority the system
trusts, `spm login` shows its subject, issuer, dates and SHA-256 fingerprint,
and pins it only after you answer `y`. Compare the fingerprint with the
server's own:

```bash
docker compose exec web openssl x509 -in /etc/nginx/ssl/server.crt -noout -fingerprint -sha256
```

To pin without the question, give the fingerprint you expect with
`--fingerprint`; a different one is refused and nothing is saved. A server
that shows another certificate later is refused (exit status 3) until you run
`spm login` again. The certificate stays the same across restarts and
upgrades, because it is kept in the `web-tls` volume.

`spm login` checks the token with `GET /api/session` and saves the address,
the token and the fingerprint to `spm/config.json` in your config directory
(`SPM_CONFIG` to choose another file), with mode 0600 in a directory of mode
0700. `spm` refuses to read a config file that other users can read.

## Use it

```bash
spm status                    # the server's version and state
spm status --json
spm api --list                # every operation, with the token scope it needs
spm api GET /api/ip-blacklist?search=203.0.113
spm api POST /api/ip-blacklist -d '{"ip":"203.0.113.9","description":"scanner"}'
spm api POST /api/blacklists/import -d @list.json
spm api DELETE /api/ip-blacklist/42 --dry-run
```

`spm api` sends one operation of the API as `GET /api/openapi.json` describes
it. A method and path that are no operation of its release, a body that is not
JSON, or a body sent to an operation that reads none, is refused before
anything is sent. `--dry-run` prints the request and sends nothing.

Every command takes `--url` and `--token` (or `SPM_URL` and `SPM_TOKEN`), which
take precedence over the config file, and `--insecure`, which does not check
the certificate at all.

## Exit status

| Status | Meaning |
|---|---|
| 0 | The API answered 2xx |
| 1 | The API answered 4xx (refused, not found, a token whose scope does not allow it), or you declined to pin the certificate |
| 2 | The command line or the config file is wrong; nothing was sent |
| 3 | The server could not be reached, its certificate is not the pinned one, or it answered 5xx |

When the server speaks another API version than the `spm` build
(`X-API-Version`), `spm` says so on standard error.
