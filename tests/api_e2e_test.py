#!/usr/bin/env python3
import requests
import json
import sys
import time
import os
from rich.console import Console

console = Console()
BASE_URL = os.environ.get("API_URL", "http://localhost:5001/api")
AUTH_USER = os.environ.get("API_USER", "admin")
AUTH_PASS = os.environ.get("API_PASS", "admin")
AUTH = (AUTH_USER, AUTH_PASS)

def test_endpoint(name, method, url, expected_status=200, **kwargs):
    console.print(f"Testing [bold blue]{name}[/bold blue] ({method} {url})...", end=" ")
    try:
        if method == 'GET':
            res = requests.get(f"{BASE_URL}{url}", auth=AUTH, timeout=5, **kwargs)
        elif method == 'POST':
            res = requests.post(f"{BASE_URL}{url}", auth=AUTH, timeout=5, **kwargs)
        elif method == 'DELETE':
            res = requests.delete(f"{BASE_URL}{url}", auth=AUTH, timeout=5, **kwargs)
        else:
            console.print("[red]Unsupported method[/red]")
            return False

        if res.status_code == expected_status:
            console.print(f"[green]SUCCESS ({res.status_code})[/green]")
            return True
        else:
            console.print(f"[red]FAILED (Expected {expected_status}, got {res.status_code})[/red]")
            console.print(res.text)
            return False
    except Exception as e:
        console.print(f"[red]ERROR: {e}[/red]")
        return False

def run_tests():
    console.print("\n[bold cyan]Starting API E2E Surgical Tests[/bold cyan]\n")
    success = True
    
    # 1. Test Health
    success &= test_endpoint("Health Check", "GET", "/health")
    
    # 2. Test Settings
    success &= test_endpoint("Get Settings", "GET", "/settings")
    
    # 3. Test IP Blacklist
    success &= test_endpoint("Get IP Blacklist", "GET", "/ip-blacklist")
    success &= test_endpoint("Add IP Blacklist", "POST", "/ip-blacklist", json={"ip": "1.2.3.4", "description": "Test IP"})
    
    # 4. Test Domain Blacklist
    success &= test_endpoint("Get Domain Blacklist", "GET", "/domain-blacklist")
    success &= test_endpoint("Add Domain Blacklist", "POST", "/domain-blacklist", json={"domain": "test-domain.com", "description": "Test Domain"})
    
    # 5. Test Whitelist
    success &= test_endpoint("Get IP Whitelist", "GET", "/ip-whitelist")
    success &= test_endpoint("Add IP Whitelist", "POST", "/ip-whitelist", json={"ip": "10.10.10.0/24", "description": "Test Whitelist"})
    
    # 6. Test Logs
    success &= test_endpoint("Get Logs", "GET", "/logs?limit=5")
    success &= test_endpoint("Get Log Stats", "GET", "/logs/stats")
    success &= test_endpoint("Get Log Timeline", "GET", "/logs/timeline")
    
    # 7. Test Cache Stats
    success &= test_endpoint("Get Cache Stats", "GET", "/cache/statistics")
    
    # 8. Test Security Score
    success &= test_endpoint("Get Security Score", "GET", "/security/score")

    if success:
        console.print("\n[bold green]✅ ALL API TESTS PASSED![/bold green]")
        sys.exit(0)
    else:
        console.print("\n[bold red]❌ SOME API TESTS FAILED![/bold red]")
        sys.exit(1)

if __name__ == '__main__':
    run_tests()
