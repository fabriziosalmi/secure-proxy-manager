# Examples

## [import_blacklists.md](import_blacklists.md)

Importing lists through the API: domains and IP ranges from a URL or pasted
content, the accepted formats, the response, and country blocks.

## test_import.sh

`test_import.sh` predates the current API: it calls the retired endpoints
`POST /api/domain-blacklist/import` and `POST /api/ip-blacklist/import`, which
answer `410 Gone`, over `http://localhost:8011`, which redirects to HTTPS. Use
the commands in [import_blacklists.md](import_blacklists.md) instead.

## More

- [API reference](../docs/api/reference.md)
- [Lists guide](../docs/guide/blacklists.md)
- [Open an issue](https://github.com/fabriziosalmi/secure-proxy-manager/issues)
  to ask for an example

New examples are welcome; test them against a running stack and follow
[CONTRIBUTING.md](../CONTRIBUTING.md).
