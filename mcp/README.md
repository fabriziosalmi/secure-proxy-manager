# spm-mcp: MCP server for Secure Proxy Manager

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
part of the [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager)
management API as tools, so an assistant or agent can query traffic and
analytics, read the WAF categories and the domain blacklist, and, when you
allow it, change them. It talks to the backend API with HTTP Basic
authentication over the stdio transport.

## Tools

| Tool | API call | Registered |
|---|---|---|
| `spm_status` | `GET /api/status` | always |
| `spm_dashboard` | `GET /api/dashboard/summary` | always |
| `spm_top_domains` | `GET /api/analytics/top-domains` | always |
| `spm_shadow_it` | `GET /api/analytics/shadow-it` | always |
| `spm_user_agents` | `GET /api/analytics/user-agents` | always |
| `spm_recent_logs` | `GET /api/logs?limit=<n>` (default 50) | always |
| `spm_waf_categories` | `GET /api/waf/categories` | always |
| `spm_list_domain_blocklist` | `GET /api/domain-blacklist` | always |
| `spm_block_domain` | `POST /api/domain-blacklist` | only with `SPM_MCP_READONLY=false` |
| `spm_unblock_domain` | `DELETE /api/domain-blacklist/{id}` | only with `SPM_MCP_READONLY=false` |
| `spm_toggle_waf_category` | `POST /api/waf/categories/toggle` | only with `SPM_MCP_READONLY=false` |
| `spm_allow_egress` | `POST /api/egress-allowlist` | only with `SPM_MCP_READONLY=false` |
| `spm_reload_config` | `POST /api/maintenance/reload-config` | only with `SPM_MCP_READONLY=false` |

**The server is read-only by default.** The read tools return traffic data
that anyone whose requests cross the proxy can shape (URLs, domains, user
agents), so text in a log row can try to instruct the model; with the mutating
tools available, an auto-approved call could disable a WAF category or open
egress. The output of `spm_dashboard`, `spm_top_domains`, `spm_shadow_it`,
`spm_user_agents` and `spm_recent_logs` is wrapped in
`{"untrusted_data_notice": ..., "data": ...}`, and every tool carries MCP
annotations (`readOnlyHint`, `destructiveHint`) for the client's approval
prompt. If you enable the mutating tools, do not auto-approve them.

## Configure

| Env | Default | Meaning |
|---|---|---|
| `SPM_URL` | `http://localhost:5001` | SPM backend API base URL |
| `SPM_USERNAME` | `admin` | SPM admin user (Basic auth) |
| `SPM_PASSWORD` | empty | SPM admin password |
| `SPM_VERIFY` | `true` | `false` to skip TLS verification for a self-signed HTTPS URL |
| `SPM_MCP_READONLY` | `true` | `false`, `0` or `no` to also register the mutating tools |

`http://localhost:5001` is the backend's host-only port, so the default works
on the machine that runs the stack. From elsewhere, use
`https://<host>:8443` with `SPM_VERIFY=false` (or a trusted certificate).

## Run

With [uv](https://docs.astral.sh/uv/), from PyPI:

```bash
SPM_URL=http://localhost:5001 SPM_USERNAME=admin SPM_PASSWORD=... uvx spm-mcp
```

From this directory of a clone:

```bash
SPM_URL=http://localhost:5001 SPM_USERNAME=admin SPM_PASSWORD=... \
  uvx --from . spm-mcp
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
        "SPM_USERNAME": "admin",
        "SPM_PASSWORD": "your-password"
      }
    }
  }
}
```

The `Dockerfile` here builds an image that runs the server over stdio as a
non-root user; the shipped compose files do not include it.

Requires Python 3.11 or later. MIT-licensed, part of Secure Proxy Manager.
