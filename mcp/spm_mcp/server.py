"""spm-mcp — Model Context Protocol server for Secure Proxy Manager.

Exposes the SPM management API as MCP tools so an assistant/agent (e.g. Claude)
can inspect and drive the proxy + WAF + DNS stack: query traffic and analytics,
manage block/allow lists, toggle WAF rule categories, and reload config.

Configuration (env):
  SPM_URL       Base URL of the SPM backend API (default http://localhost:5001)
  SPM_USERNAME  Basic-auth username (the SPM admin user)
  SPM_PASSWORD  Basic-auth password
  SPM_VERIFY    "false" to skip TLS verification for self-signed HTTPS (default true)

Read tools are safe. Mutating tools (block/unblock/toggle/allow/reload) change
live proxy behaviour and are named with an explicit verb so the model — and the
human approving tool calls — can tell them apart.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server import MCPServer

SPM_URL = os.environ.get("SPM_URL", "http://localhost:5001").rstrip("/")
SPM_USERNAME = os.environ.get("SPM_USERNAME", "admin")
SPM_PASSWORD = os.environ.get("SPM_PASSWORD", "")
SPM_VERIFY = os.environ.get("SPM_VERIFY", "true").lower() != "false"

mcp = MCPServer("secure-proxy-manager")

_client = httpx.Client(
    base_url=SPM_URL,
    auth=httpx.BasicAuth(SPM_USERNAME, SPM_PASSWORD),
    verify=SPM_VERIFY,
    timeout=20.0,
    headers={"Accept": "application/json"},
)


def _req(method: str, path: str, **kw: Any) -> Any:
    """Call the SPM API and return parsed JSON (or text), raising a readable error."""
    try:
        r = _client.request(method, path, **kw)
    except httpx.HTTPError as e:  # network/DNS/TLS
        return {"error": f"request failed: {e}", "hint": f"is SPM_URL={SPM_URL} reachable?"}
    if r.status_code == 401:
        return {"error": "unauthorized (401)", "hint": "check SPM_USERNAME / SPM_PASSWORD"}
    if r.status_code >= 400:
        return {"error": f"HTTP {r.status_code}", "body": r.text[:1000]}
    ctype = r.headers.get("content-type", "")
    return r.json() if "application/json" in ctype else r.text


# ── Read / observe ───────────────────────────────────────────────────────────

@mcp.tool()
def spm_status() -> Any:
    """Proxy/WAF status and version (health of the running stack)."""
    return _req("GET", "/api/status")


@mcp.tool()
def spm_dashboard() -> Any:
    """Dashboard summary: totals for requests, blocks, clients, top talkers."""
    return _req("GET", "/api/dashboard/summary")


@mcp.tool()
def spm_top_domains(limit: int = 20) -> Any:
    """Most-requested destination domains through the proxy."""
    return _req("GET", "/api/analytics/top-domains", params={"limit": limit})


@mcp.tool()
def spm_shadow_it() -> Any:
    """Shadow-IT view: apps/services clients reach that may be unsanctioned
    (a good lens for shadow-AI / agent egress)."""
    return _req("GET", "/api/analytics/shadow-it")


@mcp.tool()
def spm_user_agents() -> Any:
    """Breakdown of client User-Agents seen egressing (browsers vs libraries/agents)."""
    return _req("GET", "/api/analytics/user-agents")


@mcp.tool()
def spm_recent_logs(limit: int = 50) -> Any:
    """Most recent proxy access-log rows (destination, status, client, blocked flag)."""
    return _req("GET", "/api/logs", params={"limit": limit})


@mcp.tool()
def spm_security_score() -> Any:
    """Composite security posture score for the deployment."""
    return _req("GET", "/api/security/score")


@mcp.tool()
def spm_waf_categories() -> Any:
    """List the WAF rule categories and whether each is enabled."""
    return _req("GET", "/api/waf/categories")


@mcp.tool()
def spm_list_domain_blocklist() -> Any:
    """The domain blocklist (domains sinkholed/denied at the proxy/DNS layer)."""
    return _req("GET", "/api/domain-blacklist")


# ── Mutate (changes live proxy behaviour) ────────────────────────────────────

@mcp.tool()
def spm_block_domain(domain: str) -> Any:
    """BLOCK a domain (adds it to the domain blocklist). Changes live behaviour."""
    return _req("POST", "/api/domain-blacklist", json={"domain": domain})


@mcp.tool()
def spm_unblock_domain(entry_id: int) -> Any:
    """UNBLOCK a domain by its blocklist entry id (from spm_list_domain_blocklist)."""
    return _req("DELETE", f"/api/domain-blacklist/{entry_id}")


@mcp.tool()
def spm_toggle_waf_category(category: str, enabled: bool) -> Any:
    """ENABLE/DISABLE a WAF rule category at runtime (e.g. SQL_INJECTION, XSS_ATTACKS).
    Disabling a category lets that attack class through — use with care."""
    return _req("POST", "/api/waf/categories/toggle",
                json={"category": category, "enabled": enabled})


@mcp.tool()
def spm_allow_egress(entry: str, description: str = "via mcp") -> Any:
    """ALLOW a destination on the egress allowlist (relevant under default-deny egress)."""
    return _req("POST", "/api/egress-allowlist",
                json={"entry": entry, "description": description})


@mcp.tool()
def spm_reload_config() -> Any:
    """Regenerate the proxy ACLs and signal a reload (apply pending list/setting changes)."""
    return _req("POST", "/api/maintenance/reload-config", json={})


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
