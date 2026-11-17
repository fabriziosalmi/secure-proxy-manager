# Command line (spm)

`spm` calls the management API from a terminal with an
[API token](/api/authentication#api-tokens). It knows the operations of its own
release from the OpenAPI document it is built with, and it pins the certificate
of a server whose certificate no public authority signed, such as the
self-signed one the `web` service makes.

## Get it

- **In the backend container**, with nothing to install:
  `docker compose exec backend spm status --url http://127.0.0.1:5000 --token spm_...`
  (inside the container the backend answers on plain HTTP, so there is no
  certificate to pin).
- **A release binary**, for Linux, macOS and Windows on amd64 and arm64
  (Windows amd64 only), attached to each release from 3.39.0 as
  `spm_vX.Y.Z_<os>_<arch>`, with `SHA256SUMS` and its keyless signature. Verify
  them as [SECURITY.md](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/SECURITY.md#verifying-the-spm-binaries)
  shows, then make the binary executable.
- **From a checkout**: `cd backend-go && go build -o spm ./cmd/spm`.

`spm version` names the release, the API version and the commit it was built
from.

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

Without `--token` or `SPM_TOKEN`, `spm login` reuses the token saved for the
same address, so signing in again to pin a new certificate does not ask for
it, and asks for one for any other address: the token saved for one server is
never sent to another. When the server refuses a saved token (revoked or
expired), nothing is saved; give a new one with `--token`.

## The dashboard's lists and pages

The commands carry the names the dashboard shows:

| Command | Page | Verbs |
|---|---|---|
| `spm blocked-ips`, `spm blocked-domains` | Blacklists | `list [--search] [--limit]`, `add VALUE [--note]`, `remove VALUE`, `clear --yes`, `import FILE`, `export`, `sources` |
| `spm ip-exceptions`, `spm domain-exceptions` | Blacklists | the same |
| `spm allowlist` | Default-deny allowlist | `list`, `add VALUE [--subdomains] [--note]`, `remove VALUE`, `clear --yes` |
| `spm history` | Configuration history | `list`, `take [--note]`, `diff ID`, `restore ID --yes` |
| `spm sign-in-limits` | Admin and backup | `list`, `clear IP` |
| `spm settings` | Settings | `get [NAME]`, `set NAME VALUE` |
| `spm logs` | Access logs | `[--blocked] [--search TEXT] [--limit N]` |

```bash
spm blocked-ips add 203.0.113.7 --note "scanner"
spm blocked-domains import blocklist.txt
spm allowlist add debian.org --subdomains
spm history diff 12 && spm history restore 12 --yes
spm logs --blocked --limit 50
```

`remove` takes the entry itself, not its id. An entry written exactly as you
give it is the one removed: with both `example.com` and `.example.com` (the
domain and its subdomains) on the allowlist, `remove example.com` removes
`example.com`. Without an exact entry, `remove example.com` takes
`.example.com` when it is the only such entry, and refuses (exit status 1,
nothing removed) when more than one entry matches that way. `clear` and
`history restore` do nothing without `--yes`. Every command prints a table, or the API's data with
`--json`. In `GET /api/openapi.json`, `x-spm-surfaces` marks `cli` the
operations these commands call; a test holds the two to each other.

## Any operation

```bash
spm status                    # the server's version and state
spm status --json
spm api --list                # every operation, with the token scope it needs
spm api GET '/api/ip-blacklist?search=203.0.113'
spm api POST /api/ip-blacklist -d '{"ip":"203.0.113.9","description":"scanner"}'
spm api POST /api/blacklists/import -d @list.json
spm api DELETE /api/ip-blacklist/42 --dry-run
```

`spm api` sends one operation of the API as `GET /api/openapi.json` describes
it. A method and path that are no operation of its release, a body that is not
JSON, or a body sent to an operation that reads none, is refused before
anything is sent. `--dry-run` prints the request and sends nothing.

To ask the server what an operation that removes or resets something would
do, without doing it, add `?dry_run=true` to its path:

```bash
spm api POST '/api/logs/clear-old?days=30&dry_run=true'
spm api DELETE '/api/ip-blacklist/sources/7?dry_run=true'
```

The answer says what would go (`removed`, `kept`, ...) and nothing changes; the
API reference lists the 21 operations that take it. A server before 3.40.0
ignores `dry_run` and would run the call, so `spm api` first reads the
server's `GET /api/openapi.json` and sends nothing, with exit status 1, when
the operation does not declare it. `spm blocked-ips clear` without `--yes`
asks a server that declares it how many entries would go, and says so.

Every command takes `--url` and `--token` (or `SPM_URL` and `SPM_TOKEN`), which
take precedence over the config file, and `--insecure`, which does not check
the certificate at all. `spm login` refuses `--insecure` for an https address
(exit status 2, nothing sent): it would pin nothing, and every later command,
which checks the certificate, would refuse the server. To pin without the
question, give `--fingerprint` instead.

## Exit status

| Status | Meaning |
|---|---|
| 0 | The API answered 2xx |
| 1 | The API answered 4xx (refused, not found, a token whose scope does not allow it), or you declined to pin the certificate |
| 2 | The command line or the config file is wrong; nothing was sent |
| 3 | The server could not be reached, its certificate is not the pinned one, it answered 5xx, or it answered a redirect |

`spm` does not follow a redirect. The `web` service's plain HTTP ports (80 and
8011) answer every `/api/` path with a redirect to `https://HOST:8443`, and a
`POST` or `DELETE` that followed it would arrive there as a `GET`, so
`spm` names the address it was redirected to, sends nothing there, and exits
with status 3. Give that address with `--url`.

When the server speaks another API version than the `spm` build
(`X-API-Version`), `spm` says so on standard error.
