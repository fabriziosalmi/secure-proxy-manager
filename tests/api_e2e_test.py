#!/usr/bin/env python3
"""
API E2E test suite — Secure Proxy Manager
Authenticates via JWT (/api/auth/login) and exercises every major endpoint.

Usage:
  python3 tests/api_e2e_test.py

Environment variables:
  API_URL    Base URL of the backend (default: http://localhost:5001/api)
  API_USER   Username (default: admin)
  API_PASS   Password (default: admin)
"""
import requests
import sys
import os
from rich.console import Console

console = Console()
BASE_URL  = os.environ.get("API_URL",  "http://localhost:5001/api")
API_USER  = os.environ.get("API_USER", "admin")
API_PASS  = os.environ.get("API_PASS", "admin")

# ── Auth ──────────────────────────────────────────────────────────────────────

def get_jwt_token() -> str:
    """Obtain a JWT bearer token from /api/auth/login."""
    res = requests.post(f"{BASE_URL}/auth/login",
                        json={"username": API_USER, "password": API_PASS},
                        timeout=10)
    if res.status_code != 200:
        console.print(f"[red]Login failed ({res.status_code}): {res.text}[/red]")
        sys.exit(1)
    token = res.json().get("token", "")
    if not token:
        console.print("[red]Login response missing 'token' field[/red]")
        sys.exit(1)
    return token


AUTH_HEADERS: dict[str, str] = {}   # populated in run_tests()

# ── Helpers ───────────────────────────────────────────────────────────────────

def test_endpoint(name: str, method: str, url: str,
                  expected_status: int = 200, **kwargs) -> bool:
    console.print(f"Testing [bold blue]{name}[/bold blue] ({method} {url})...", end=" ")
    try:
        fn = {"GET": requests.get, "POST": requests.post,
              "DELETE": requests.delete, "PUT": requests.put}[method]
        res = fn(f"{BASE_URL}{url}", headers=AUTH_HEADERS, timeout=10, **kwargs)

        # 400 "already exists" is acceptable for idempotent POST tests
        already_exists = res.status_code == 400 and "already" in res.text.lower()
        if res.status_code == expected_status or (method == "POST" and already_exists):
            label = "[yellow]PASS (already exists)[/yellow]" if already_exists \
                    else f"[green]PASS ({res.status_code})[/green]"
            console.print(label)
            return True
        else:
            console.print(f"[red]FAIL (expected {expected_status}, got {res.status_code})[/red]")
            console.print(res.text[:300])
            return False
    except requests.RequestException as exc:
        console.print(f"[red]ERROR: {exc}[/red]")
        return False


# ── Test cases ────────────────────────────────────────────────────────────────

def run_tests() -> None:
    global AUTH_HEADERS

    console.print("\n[bold cyan]Secure Proxy Manager — API E2E Test Suite[/bold cyan]\n")

    # Authenticate
    console.print("[bold]Authenticating via JWT...[/bold] ", end="")
    token = get_jwt_token()
    AUTH_HEADERS = {"Authorization": f"Bearer {token}"}
    console.print(f"[green]OK (token: {token[:20]}...)[/green]\n")

    ok = True

    # ── Health ─────────────────────────────────────────────────────────────
    ok &= test_endpoint("Health (legacy)",  "GET", "/health")
    ok &= test_endpoint("Health (API)",     "GET", "/health")

    # ── Settings ───────────────────────────────────────────────────────────
    ok &= test_endpoint("Get Settings",     "GET", "/settings")

    # ── IP Blacklist ────────────────────────────────────────────────────────
    ok &= test_endpoint("List IP Blacklist", "GET", "/ip-blacklist")
    ok &= test_endpoint("Add IP Blacklist",  "POST", "/ip-blacklist",
                        json={"ip": "1.2.3.4", "description": "api-test"})

    # ── Domain Blacklist ────────────────────────────────────────────────────
    ok &= test_endpoint("List Domain Blacklist", "GET", "/domain-blacklist")
    ok &= test_endpoint("Add Domain Blacklist",  "POST", "/domain-blacklist",
                        json={"domain": "api-test.example.com", "description": "api-test"})

    # ── IP Whitelist ────────────────────────────────────────────────────────
    ok &= test_endpoint("List IP Whitelist", "GET", "/ip-whitelist")
    ok &= test_endpoint("Add IP Whitelist",  "POST", "/ip-whitelist",
                        json={"ip": "10.10.10.0/24", "description": "api-test"})

    # ── Bulk import ─────────────────────────────────────────────────────────
    ok &= test_endpoint("Bulk Import IPs", "POST", "/blacklists/import",
                        json={"type": "ip",
                              "content": "192.0.2.10\n192.0.2.11\n# comment"})
    ok &= test_endpoint("Bulk Import Domains", "POST", "/blacklists/import",
                        json={"type": "domain",
                              "content": "bulk-test.example.com\nbulk-test2.example.com"})

    # ── Logs ────────────────────────────────────────────────────────────────
    ok &= test_endpoint("List Logs",       "GET", "/logs?limit=5")
    ok &= test_endpoint("Log Stats",       "GET", "/logs/stats")
    ok &= test_endpoint("Log Timeline",    "GET", "/logs/timeline")

    # ── Analytics / Security ────────────────────────────────────────────────
    ok &= test_endpoint("Cache Statistics", "GET", "/cache/statistics")
    ok &= test_endpoint("Security Score",   "GET", "/security/score")

    # ── Database ────────────────────────────────────────────────────────────
    ok &= test_endpoint("DB Export (backup)", "GET", "/database/export")

    # ── WS token ────────────────────────────────────────────────────────────
    ok &= test_endpoint("WebSocket Token", "GET", "/ws-token")

    # ── Summary ─────────────────────────────────────────────────────────────
    print()
    if ok:
        console.print("[bold green]✅ ALL API TESTS PASSED[/bold green]")
        sys.exit(0)
    else:
        console.print("[bold red]❌ SOME API TESTS FAILED[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
