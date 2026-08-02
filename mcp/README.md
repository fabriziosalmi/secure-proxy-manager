# spm-mcp — MCP server for Secure Proxy Manager

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
the [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager)
management API as tools — so an assistant/agent (e.g. Claude) can **inspect and
drive your self-hosted Secure Web Gateway**: query traffic and analytics, manage
block/allow lists, toggle WAF rule categories, and reload config.

## Tools

| Tool | What it does |
|---|---|
| `spm_status`, `spm_dashboard` | health + summary totals |
| `spm_top_domains`, `spm_shadow_it`, `spm_user_agents` | analytics (incl. shadow-IT / agent egress) |
| `spm_recent_logs` | recent proxy access-log rows |
| `spm_security_score` | posture score |
| `spm_waf_categories`, `spm_list_domain_blocklist` | current WAF/list state |
| `spm_block_domain`, `spm_unblock_domain` | **mutate** the domain blocklist |
| `spm_toggle_waf_category` | **mutate** — enable/disable a WAF category at runtime |
| `spm_allow_egress` | **mutate** — add to the egress allowlist |
| `spm_reload_config` | **mutate** — apply pending changes |

Read tools are safe; mutating tools change live proxy behaviour and are named
with an explicit verb. Approve mutating tool calls deliberately.

## Configure

| Env | Default | Meaning |
|---|---|---|
| `SPM_URL` | `http://localhost:5001` | SPM backend API base URL |
| `SPM_USERNAME` | `admin` | SPM admin user (Basic auth) |
| `SPM_PASSWORD` | — | SPM admin password |
| `SPM_VERIFY` | `true` | `false` to skip TLS verify for self-signed HTTPS |

## Run

With [uv](https://docs.astral.sh/uv/) (no install):

```bash
SPM_URL=http://localhost:5001 SPM_USERNAME=admin SPM_PASSWORD=... \
  uvx --from . spm-mcp
```

Or in Claude Desktop / any MCP client — add to the MCP servers config:

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

Or as a container (see `Dockerfile`) — an optional `mcp` service can be added to
the stack's compose profile.

MIT-licensed, part of Secure Proxy Manager.
