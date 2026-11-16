# spm-mcp: MCP server for Secure Proxy Manager

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
part of the [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager)
management API as tools, so an assistant or agent can query traffic and
analytics, read the WAF categories and the domain blacklist, and, when you
allow it, change them. It speaks MCP over the stdio transport and
authenticates to the backend API with an SPM API token.

## Tools

The tools come from the server. At the first request the MCP client makes,
spm-mcp reads the OpenAPI document of the backend (`GET /api/openapi.json`)
and offers one tool for each operation the backend marks for MCP
(`x-spm-mcp-name`): the tool's description is the operation's summary, and its
arguments are the operation's path parameters, query parameters and request
body fields, with the API's own schemas. A tool the server does not have is
never offered. spm-mcp 0.5.0 needs Secure Proxy Manager 3.41.0 or later; an
older server names no tool, and spm-mcp says so instead of offering none.

Secure Proxy Manager 3.41.0 names 13 tools. From 3.42.0 the server names
the tools below; a test writes this table from the server's
registry, so it is the list the server publishes. Reading tools come first.
Every other operation of the API is kept from MCP: the ones no token may call
(tokens, password, backup and restore, database export and reset), and the
ones that would switch off a protection if a model obeyed a crafted log row
(settings, WAF exceptions and policy, configuration restore).

<!-- tools:start -->
| Tool | API call | Offered | Notes |
|---|---|---|---|
| `spm_audit_log` | `GET /api/audit-log` | always | untrusted |
| `spm_blocked_by_day` | `GET /api/analytics/blocked-by-day` | always | untrusted |
| `spm_blocked_domain_sources` | `GET /api/domain-blacklist/sources` | always | untrusted |
| `spm_blocked_ip_sources` | `GET /api/ip-blacklist/sources` | always | untrusted |
| `spm_cache_by_day` | `GET /api/analytics/cache-by-day` | always | untrusted |
| `spm_cache_stats` | `GET /api/cache/statistics` | always |  |
| `spm_check_ca` | `GET /api/maintenance/check-cert-security` | always |  |
| `spm_client_details` | `GET /api/clients/{ip}/details` | always | untrusted |
| `spm_client_setup` | `GET /api/client-setup` | always |  |
| `spm_dashboard` | `GET /api/dashboard/summary` | always | untrusted |
| `spm_database_size` | `GET /api/database/size` | always |  |
| `spm_database_stats` | `GET /api/database/stats` | always |  |
| `spm_diff_config_snapshot` | `GET /api/config/snapshots/{id}/diff` | always |  |
| `spm_domain_exception_sources` | `GET /api/domain-whitelist/sources` | always | untrusted |
| `spm_file_extensions` | `GET /api/analytics/file-extensions` | always | untrusted |
| `spm_get_client_group` | `GET /api/client-groups/{id}` | always |  |
| `spm_get_waf_trajectory` | `GET /api/waf/trajectories/{id}` | always | untrusted |
| `spm_health` | `GET /api/health` | always |  |
| `spm_ip_exception_sources` | `GET /api/ip-whitelist/sources` | always | untrusted |
| `spm_list_blocked_domain_presets` | `GET /api/domain-blacklist/presets` | always |  |
| `spm_list_blocked_ips` | `GET /api/ip-blacklist` | always | untrusted |
| `spm_list_client_groups` | `GET /api/client-groups` | always |  |
| `spm_list_config_snapshots` | `GET /api/config/snapshots` | always |  |
| `spm_list_domain_blocklist` | `GET /api/domain-blacklist` | always | untrusted |
| `spm_list_domain_exception_presets` | `GET /api/domain-whitelist/presets` | always |  |
| `spm_list_domain_exceptions` | `GET /api/domain-whitelist` | always | untrusted |
| `spm_list_egress_allowlist` | `GET /api/egress-allowlist` | always | untrusted |
| `spm_list_egress_providers` | `GET /api/egress-providers` | always |  |
| `spm_list_enforcement` | `GET /api/blacklists/enforcement` | always |  |
| `spm_list_ip_exceptions` | `GET /api/ip-whitelist` | always | untrusted |
| `spm_list_settings` | `GET /api/settings` | always |  |
| `spm_list_waf_trajectories` | `GET /api/waf/trajectories` | always | untrusted |
| `spm_log_stats` | `GET /api/logs/stats` | always | untrusted |
| `spm_network_details` | `GET /api/clients/{ip}/{prefix}/details` | always | untrusted |
| `spm_notification_status` | `GET /api/notifications/status` | always |  |
| `spm_protection_coverage` | `GET /api/analytics/coverage` | always |  |
| `spm_recent_logs` | `GET /api/logs` | always | untrusted |
| `spm_shadow_it` | `GET /api/analytics/shadow-it` | always | untrusted |
| `spm_signin_rate_limits` | `GET /api/security/rate-limits` | always | untrusted |
| `spm_squid_cves` | `GET /api/security/cve` | always | untrusted |
| `spm_status` | `GET /api/status` | always |  |
| `spm_top_clients` | `GET /api/clients/statistics` | always | untrusted |
| `spm_top_domains` | `GET /api/analytics/top-destinations` | always | untrusted |
| `spm_traffic_timeline` | `GET /api/logs/timeline` | always | untrusted |
| `spm_user_agents` | `GET /api/analytics/user-agents` | always | untrusted |
| `spm_waf_categories` | `GET /api/waf/categories` | always |  |
| `spm_waf_event` | `GET /api/waf/events/{id}` | always | untrusted |
| `spm_waf_heuristics` | `GET /api/waf/heuristics` | always |  |
| `spm_waf_policy` | `GET /api/waf/policy` | always |  |
| `spm_waf_stats` | `GET /api/waf/stats` | always |  |
| `spm_waf_status` | `GET /api/waf/status` | always |  |
| `spm_add_domain_exception` | `POST /api/domain-whitelist` | with `SPM_MCP_READONLY=false` |  |
| `spm_add_domain_exception_preset` | `POST /api/domain-whitelist/presets/{preset}` | with `SPM_MCP_READONLY=false` |  |
| `spm_add_egress_url_provider` | `POST /api/egress-providers/url` | with `SPM_MCP_READONLY=false` |  |
| `spm_add_ip_exception` | `POST /api/ip-whitelist` | with `SPM_MCP_READONLY=false` |  |
| `spm_allow_egress` | `POST /api/egress-allowlist` | with `SPM_MCP_READONLY=false` |  |
| `spm_apply_held_egress_update` | `POST /api/egress-providers/{name}/apply-held` | with `SPM_MCP_READONLY=false` |  |
| `spm_block_countries` | `POST /api/blacklists/import-geo` | with `SPM_MCP_READONLY=false` |  |
| `spm_block_domain` | `POST /api/domain-blacklist` | with `SPM_MCP_READONLY=false` |  |
| `spm_block_domain_preset` | `POST /api/domain-blacklist/presets/{preset}` | with `SPM_MCP_READONLY=false` |  |
| `spm_block_ip` | `POST /api/ip-blacklist` | with `SPM_MCP_READONLY=false` |  |
| `spm_clear_blocked_domains` | `DELETE /api/domain-blacklist/clear-all` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_blocked_ips` | `DELETE /api/ip-blacklist/clear-all` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_cache` | `POST /api/maintenance/clear-cache` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_domain_exceptions` | `DELETE /api/domain-whitelist/clear-all` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_egress_allowlist` | `DELETE /api/egress-allowlist/clear-all` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_ip_exceptions` | `DELETE /api/ip-whitelist/clear-all` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_logs` | `POST /api/logs/clear` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_clear_old_logs` | `POST /api/logs/clear-old` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_create_client_group` | `POST /api/client-groups` | with `SPM_MCP_READONLY=false` |  |
| `spm_delete_client_group` | `DELETE /api/client-groups/{id}` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_import_blocklist` | `POST /api/blacklists/import` | with `SPM_MCP_READONLY=false` |  |
| `spm_import_domain_exceptions` | `POST /api/domain-whitelist/import` | with `SPM_MCP_READONLY=false` |  |
| `spm_import_ip_exceptions` | `POST /api/ip-whitelist/import` | with `SPM_MCP_READONLY=false` |  |
| `spm_refresh_egress_provider` | `POST /api/egress-providers/{name}/refresh` | with `SPM_MCP_READONLY=false` |  |
| `spm_reload_config` | `POST /api/maintenance/reload-config` | with `SPM_MCP_READONLY=false` |  |
| `spm_reload_dns` | `POST /api/maintenance/reload-dns` | with `SPM_MCP_READONLY=false` |  |
| `spm_remove_blocked_domain_source` | `DELETE /api/domain-blacklist/sources/{id}` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_blocked_ip_source` | `DELETE /api/ip-blacklist/sources/{id}` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_domain_exception` | `DELETE /api/domain-whitelist/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_remove_domain_exception_source` | `DELETE /api/domain-whitelist/sources/{id}` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_domain_exceptions` | `POST /api/domain-whitelist/bulk-delete` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_egress_entries` | `POST /api/egress-allowlist/bulk-delete` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_egress_entry` | `DELETE /api/egress-allowlist/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_remove_egress_url_provider` | `DELETE /api/egress-providers/url/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_remove_ip_exception` | `DELETE /api/ip-whitelist/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_remove_ip_exception_source` | `DELETE /api/ip-whitelist/sources/{id}` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_remove_ip_exceptions` | `POST /api/ip-whitelist/bulk-delete` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_replace_client_group` | `PUT /api/client-groups/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_reset_counters` | `POST /api/counters/reset` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_scope_blocked_domain_source` | `PUT /api/domain-blacklist/sources/{id}/scope` | with `SPM_MCP_READONLY=false` |  |
| `spm_scope_blocked_ip_source` | `PUT /api/ip-blacklist/sources/{id}/scope` | with `SPM_MCP_READONLY=false` |  |
| `spm_set_egress_provider` | `PUT /api/egress-providers/{name}` | with `SPM_MCP_READONLY=false` |  |
| `spm_take_config_snapshot` | `POST /api/config/snapshots` | with `SPM_MCP_READONLY=false` |  |
| `spm_test_log_forward` | `POST /api/log-forward/test` | with `SPM_MCP_READONLY=false` |  |
| `spm_test_notifications` | `POST /api/notifications/test` | with `SPM_MCP_READONLY=false` |  |
| `spm_test_waf_rule` | `POST /api/waf/test-rule` | with `SPM_MCP_READONLY=false` | untrusted |
| `spm_toggle_waf_category` | `POST /api/waf/categories/toggle` | with `SPM_MCP_READONLY=false` |  |
| `spm_unblock_domain` | `DELETE /api/domain-blacklist/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_unblock_domains` | `POST /api/domain-blacklist/bulk-delete` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
| `spm_unblock_ip` | `DELETE /api/ip-blacklist/{id}` | with `SPM_MCP_READONLY=false` |  |
| `spm_unblock_ips` | `POST /api/ip-blacklist/bulk-delete` | with `SPM_MCP_READONLY=false` | preview unless `confirm: true` |
<!-- tools:end -->

**The server is read-only by default.** The read tools return traffic data
that anyone whose requests cross the proxy can shape (URLs, domains, user
agents), so text in a log row can try to instruct the model; with the mutating
tools available, an auto-approved call could disable a WAF category or open
egress. The output of every operation the backend marks `x-spm-untrusted`
("untrusted" in the table) is wrapped in
`{"untrusted_data_notice": ..., "data": ...}`, and every tool carries MCP
annotations: `readOnlyHint` for a GET, `destructiveHint` for every write,
`idempotentHint` for a GET or a PUT. An operation that takes `dry_run` answers
what it would do unless the call says `confirm: true`. If you enable the
mutating tools, do not auto-approve them.

## Authenticate with a token

`SPM_TOKEN` needs spm-mcp 0.4.0 or later and Secure Proxy Manager 3.28.0
or later; with older versions, use `SPM_USERNAME` and `SPM_PASSWORD`.

Create a token in the dashboard under **Settings > Admin and backup > API
tokens** (or `POST /api/tokens`) and give it to the server as `SPM_TOKEN`.
A `read` token is enough for the default read-only server. The mutating tools
need both `SPM_MCP_READONLY=false` and a `write` token: with a token, the
server asks `GET /api/session` for its scope at start and registers them only
when the answer is `write`. A read token, or an answer it cannot read,
registers none and says so on stderr.

A token is limited to its scope, never reaches the token, password, backup
or database export routes, can be revoked alone, and the audit log records
its changes as `token:<name>`. See the
[authentication API](https://github.com/fabriziosalmi/secure-proxy-manager/blob/main/docs/api/authentication.md#api-tokens).

`SPM_USERNAME` and `SPM_PASSWORD` still work when `SPM_TOKEN` is not set, with
a warning on stderr. They are deprecated and will be removed in the next
release.

## Configure

| Env | Default | Meaning |
|---|---|---|
| `SPM_URL` | `http://localhost:5001` | SPM backend API base URL |
| `SPM_TOKEN` | empty | SPM API token, sent as `Authorization: Bearer` |
| `SPM_USERNAME` | `admin` | Deprecated: admin user (Basic auth), used only without `SPM_TOKEN` |
| `SPM_PASSWORD` | empty | Deprecated: admin password, used only without `SPM_TOKEN` |
| `SPM_VERIFY` | `true` | `false` to skip TLS verification for a self-signed HTTPS URL |
| `SPM_MCP_READONLY` | `true` | `false`, `0` or `no` to also register the mutating tools |

`http://localhost:5001` is the backend's host-only port, so the default works
on the machine that runs the stack. From elsewhere, use
`https://<host>:8443` with `SPM_VERIFY=false` (or a trusted certificate).

## Run

With [uv](https://docs.astral.sh/uv/), from PyPI:

```bash
SPM_URL=http://localhost:5001 SPM_TOKEN=spm_... uvx spm-mcp
```

From this directory of a clone:

```bash
SPM_URL=http://localhost:5001 SPM_TOKEN=spm_... uvx --from . spm-mcp
```

In an MCP client configuration (for example Claude Desktop):

```json
{
  "mcpServers": {
    "secure-proxy-manager": {
      "command": "uvx",
      "args": ["spm-mcp"],
      "env": {
        "SPM_URL": "http://localhost:5001",
        "SPM_TOKEN": "spm_..."
      }
    }
  }
}
```

The `Dockerfile` here builds an image that runs the server over stdio as a
non-root user; the shipped compose files do not include it.

Requires Python 3.11 or later. MIT-licensed, part of Secure Proxy Manager.
