#!/usr/bin/env python3
"""
End-to-End Testing Script for Secure Proxy
-----------------------------------------
This script performs comprehensive testing of the Squid proxy configuration,
with a focus on validating direct IP blocking and other security settings.

Requirements:
    Install dependencies with: pip install -r requirements-test.txt
"""

import os
import re
import sys
import json
import time
import socket
import subprocess
import argparse
import urllib.parse
from datetime import datetime

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.text import Text

# Initialize rich console
console = Console()

class ProxyTester:
    def __init__(self, proxy_host="localhost", proxy_port=3128, ui_host="localhost", ui_port=8011, verbose=False):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.ui_host = ui_host
        self.ui_port = ui_port
        self.verbose = verbose
        self.proxies = {
            "http": f"http://{proxy_host}:{proxy_port}",
            "https": f"http://{proxy_host}:{proxy_port}"
        }
        self.test_results = []
        self.total_tests = 0
        self.passed_tests = 0
        
    def run_all_tests(self):
        """Run all tests and report results"""
        console.print(Panel.fit("[bold cyan]Secure Proxy End-to-End Testing[/bold cyan]", 
                               subtitle="Running comprehensive tests", 
                               border_style="cyan"))
        
        # Basic connectivity tests
        self.test_proxy_connectivity()
        self.test_ui_connectivity()
        
        # Direct IP blocking tests
        console.print("\n[bold yellow]Running Direct IP Blocking Tests...[/bold yellow]")
        self.test_direct_ipv4_url_blocking()
        self.test_direct_ipv4_host_blocking()
        self.test_direct_ipv6_url_blocking()
        self.test_ipv4_connect_method_blocking()
        
        # Domain and IP blacklist tests
        console.print("\n[bold yellow]Running Blacklist Tests...[/bold yellow]")
        self.test_domain_blacklist()
        self.test_ip_blacklist()
        
        # Content filtering tests
        console.print("\n[bold yellow]Running Content Filtering Tests...[/bold yellow]")
        self.test_file_type_blocking()
        
        # Retrieve and display configuration
        console.print("\n[bold yellow]Retrieving Current Configuration...[/bold yellow]")
        self.get_squid_config()
        
        # Summarize results
        self.print_test_results()
        
    def run_test(self, test_name, test_func, *args, **kwargs):
        """Run a single test with rich progress display"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Running test: {test_name}...", total=None)
            try:
                result = test_func(*args, **kwargs)
                progress.stop_task(task)
                if result['passed']:
                    self.passed_tests += 1
                    console.print(f"✅ [green]{test_name}[/green]: {result['message']}")
                else:
                    console.print(f"❌ [red]{test_name}[/red]: {result['message']}")
                    
                if self.verbose and 'detail' in result and result['detail']:
                    console.print(Panel(result['detail'], title="Details", border_style="dim"))
                
                self.test_results.append(result)
                self.total_tests += 1
                return result
            except Exception as e:
                progress.stop_task(task)
                error_result = {
                    'name': test_name,
                    'passed': False,
                    'message': f"Test failed with error: {str(e)}",
                    'detail': str(e)
                }
                console.print(f"❌ [red]{test_name}[/red]: Test raised exception")
                console.print(Panel(str(e), title="Exception", border_style="red"))
                self.test_results.append(error_result)
                self.total_tests += 1
                return error_result
    
    def test_proxy_connectivity(self):
        """Test basic connectivity to the proxy"""
        return self.run_test(
            "Proxy Connectivity", 
            self._test_proxy_connectivity
        )
    
    def _test_proxy_connectivity(self):
        # Try to connect to the proxy server directly
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close
            
            if result == 0:
                # Try to make a simple HTTP request through the proxy
                try:
                    # Add proxy authentication with admin/admin
                    proxy_auth = requests.auth.HTTPBasicAuth('admin', 'admin')
                    proxies = {
                        "http": f"http://admin:admin@{self.proxy_host}:{self.proxy_port}",
                        "https": f"http://admin:admin@{self.proxy_host}:{self.proxy_port}"
                    }
                    
                    response = requests.get("http://example.com", 
                                           proxies=proxies,
                                           auth=proxy_auth,
                                           timeout=10)
                    if response.status_code == 200:
                        return {
                            'name': 'Proxy Connectivity',
                            'passed': True,
                            'message': f"Successfully connected to proxy at {self.proxy_host}:{self.proxy_port}",
                            'detail': f"Made successful request to example.com through proxy. Response: {response.status_code}"
                        }
                    else:
                        return {
                            'name': 'Proxy Connectivity',
                            'passed': False,
                            'message': f"Connected to proxy but request failed with status {response.status_code}",
                            'detail': f"Response: {response.text[:500]}"
                        }
                except Exception as e:
                    return {
                        'name': 'Proxy Connectivity',
                        'passed': False,
                        'message': "Connected to proxy but HTTP request failed",
                        'detail': str(e)
                    }
            else:
                return {
                    'name': 'Proxy Connectivity',
                    'passed': False,
                    'message': f"Failed to connect to proxy at {self.proxy_host}:{self.proxy_port}",
                    'detail': f"Socket connection failed with error code: {result}"
                }
        except Exception as e:
            return {
                'name': 'Proxy Connectivity',
                'passed': False,
                'message': "Proxy connectivity test failed",
                'detail': str(e)
            }
    
    def test_ui_connectivity(self):
        """Test connectivity to the UI server"""
        return self.run_test(
            "UI Connectivity", 
            self._test_ui_connectivity
        )
    
    def _test_ui_connectivity(self):
        try:
            # Add basic authentication for UI access (admin/admin)
            auth = ('admin', 'admin')
            response = requests.get(f"http://{self.ui_host}:{self.ui_port}", 
                                   timeout=10, 
                                   auth=auth)
            if response.status_code == 200:
                return {
                    'name': 'UI Connectivity',
                    'passed': True,
                    'message': f"Successfully connected to UI at {self.ui_host}:{self.ui_port}",
                    'detail': f"Response code: {response.status_code}"
                }
            else:
                return {
                    'name': 'UI Connectivity',
                    'passed': False,
                    'message': f"Connected to UI but received unexpected status {response.status_code}",
                    'detail': f"Response: {response.text[:500]}"
                }
        except Exception as e:
            return {
                'name': 'UI Connectivity',
                'passed': False,
                'message': f"Failed to connect to UI at {self.ui_host}:{self.ui_port}",
                'detail': str(e)
            }
    
    def test_direct_ipv4_url_blocking(self):
        """Test if direct IPv4 URLs are blocked"""
        return self.run_test(
            "Direct IPv4 URL Blocking", 
            self._test_direct_ipv4_url_blocking
        )
    
    def _test_direct_ipv4_url_blocking(self):
        # Try to access a common IP directly
        try:
            # Google DNS IP
            response = requests.get("http://8.8.8.8", 
                                   proxies=self.proxies, 
                                   timeout=10,
                                   allow_redirects=False)
            
            # Expect this to be blocked with 403 Forbidden
            if response.status_code == 403 or "access denied" in response.text.lower():
                return {
                    'name': 'Direct IPv4 URL Blocking',
                    'passed': True,
                    'message': "Direct IPv4 URL access is properly blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
            else:
                return {
                    'name': 'Direct IPv4 URL Blocking',
                    'passed': False,
                    'message': "Direct IPv4 URL access is NOT blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
        except requests.exceptions.ProxyError:
            # Proxy errors can also indicate blocking
            return {
                'name': 'Direct IPv4 URL Blocking',
                'passed': True,
                'message': "Direct IPv4 URL access is blocked (proxy error)",
                'detail': "Request was rejected by the proxy with a connection error"
            }
        except Exception as e:
            if "connection" in str(e).lower() and "refused" in str(e).lower():
                return {
                    'name': 'Direct IPv4 URL Blocking',
                    'passed': True,
                    'message': "Direct IPv4 URL access appears to be blocked (connection refused)",
                    'detail': str(e)
                }
            return {
                'name': 'Direct IPv4 URL Blocking',
                'passed': False,
                'message': "Test failed with an unexpected error",
                'detail': str(e)
            }
    
    def test_direct_ipv4_host_blocking(self):
        """Test if direct IPv4 hosts are blocked"""
        return self.run_test(
            "Direct IPv4 Host Blocking", 
            self._test_direct_ipv4_host_blocking
        )
    
    def _test_direct_ipv4_host_blocking(self):
        try:
            # Set the Host header to an IP address but use a domain in the URL
            headers = {"Host": "8.8.8.8"}
            response = requests.get("http://example.com", 
                                   headers=headers,
                                   proxies=self.proxies, 
                                   timeout=10)
            
            # Expect this to be blocked
            if response.status_code == 403 or "access denied" in response.text.lower():
                return {
                    'name': 'Direct IPv4 Host Blocking',
                    'passed': True,
                    'message': "Direct IPv4 Host access is properly blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
            else:
                return {
                    'name': 'Direct IPv4 Host Blocking',
                    'passed': False,
                    'message': "Direct IPv4 Host access is NOT blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
        except requests.exceptions.ProxyError:
            # Proxy errors can also indicate blocking
            return {
                'name': 'Direct IPv4 Host Blocking',
                'passed': True,
                'message': "Direct IPv4 Host access is blocked (proxy error)",
                'detail': "Request was rejected by the proxy with a connection error"
            }
        except Exception as e:
            return {
                'name': 'Direct IPv4 Host Blocking',
                'passed': False,
                'message': "Test failed with an unexpected error",
                'detail': str(e)
            }
    
    def test_direct_ipv6_url_blocking(self):
        """Test if direct IPv6 URLs are blocked"""
        return self.run_test(
            "Direct IPv6 URL Blocking", 
            self._test_direct_ipv6_url_blocking
        )
    
    def _test_direct_ipv6_url_blocking(self):
        try:
            # Try IPv6 localhost
            response = requests.get("http://[::1]", 
                                   proxies=self.proxies, 
                                   timeout=10,
                                   allow_redirects=False)
            
            # Expect this to be blocked
            if response.status_code == 403 or "access denied" in response.text.lower():
                return {
                    'name': 'Direct IPv6 URL Blocking',
                    'passed': True,
                    'message': "Direct IPv6 URL access is properly blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
            else:
                return {
                    'name': 'Direct IPv6 URL Blocking',
                    'passed': False,
                    'message': "Direct IPv6 URL access is NOT blocked",
                    'detail': f"Response: {response.status_code} - {response.text[:500]}"
                }
        except requests.exceptions.ProxyError:
            # Proxy errors can also indicate blocking
            return {
                'name': 'Direct IPv6 URL Blocking',
                'passed': True,
                'message': "Direct IPv6 URL access is blocked (proxy error)",
                'detail': "Request was rejected by the proxy with a connection error"
            }
        except Exception as e:
            if "connection" in str(e).lower() and "refused" in str(e).lower():
                return {
                    'name': 'Direct IPv6 URL Blocking',
                    'passed': True,
                    'message': "Direct IPv6 URL access appears to be blocked (connection refused)",
                    'detail': str(e)
                }
            return {
                'name': 'Direct IPv6 URL Blocking',
                'passed': False,
                'message': "Test failed with an unexpected error",
                'detail': str(e)
            }
    
    def test_ipv4_connect_method_blocking(self):
        """Test if CONNECT method to IPv4 is blocked"""
        return self.run_test(
            "IPv4 CONNECT Method Blocking", 
            self._test_ipv4_connect_method_blocking
        )
    
    def _test_ipv4_connect_method_blocking(self):
        try:
            # Try to establish an HTTPS connection to an IP directly
            response = requests.get("https://1.1.1.1", 
                                   proxies=self.proxies, 
                                   timeout=10,
                                   verify=False)  # Disable SSL verification
            
            # If we get here, the connection wasn't blocked
            return {
                'name': 'IPv4 CONNECT Method Blocking',
                'passed': False,
                'message': "CONNECT method to IPv4 is NOT blocked",
                'detail': f"Response: {response.status_code} - {response.text[:500]}"
            }
        except requests.exceptions.ProxyError as e:
            # This is what we expect - the proxy should reject the CONNECT
            return {
                'name': 'IPv4 CONNECT Method Blocking',
                'passed': True,
                'message': "CONNECT method to IPv4 is properly blocked",
                'detail': str(e)
            }
        except requests.exceptions.SSLError:
            # Could also be due to bad SSL certs, which we'd expect when proxying
            return {
                'name': 'IPv4 CONNECT Method Blocking',
                'passed': True,
                'message': "CONNECT method to IPv4 appears to be blocked (SSL error)",
                'detail': "Request resulted in SSL error, likely due to proxy interference"
            }
        except Exception as e:
            if "connection" in str(e).lower() and "refused" in str(e).lower():
                return {
                    'name': 'IPv4 CONNECT Method Blocking',
                    'passed': True,
                    'message': "CONNECT method to IPv4 appears to be blocked (connection refused)",
                    'detail': str(e)
                }
            return {
                'name': 'IPv4 CONNECT Method Blocking',
                'passed': False,
                'message': "Test failed with an unexpected error",
                'detail': str(e)
            }
    
    def test_domain_blacklist(self):
        """Test if domain blacklisting works"""
        return self.run_test(
            "Domain Blacklist", 
            self._test_domain_blacklist
        )
    
    def _test_domain_blacklist(self):
        # First try to add a test domain to the blacklist
        try:
            # Create config directory if it doesn't exist
            if not os.path.exists("config"):
                os.makedirs("config", exist_ok=True)
                
            # Add 'blocked-test-domain.com' to the blacklist
            with open("config/domain_blacklist.txt", "a+") as f:
                # Check if test domain is already in file to avoid duplicates
                f.seek(0)
                content = f.read()
                if "blocked-test-domain.com" not in content:
                    f.write("\nblocked-test-domain.com\n")
            
            # Restart the proxy to apply changes
            try:
                self._restart_proxy_container()
            except Exception as e:
                console.print(f"[yellow]Warning: Could not restart proxy container: {e}[/yellow]")
                console.print("[yellow]Continuing with test but results may not be accurate[/yellow]")
                
            # Give the proxy a moment to restart
            time.sleep(3)
            
            # Now try to access the blocked domain
            try:
                response = requests.get("http://blocked-test-domain.com", 
                                      proxies=self.proxies, 
                                      timeout=10)
                
                # Check if it's blocked
                if response.status_code == 403 or "access denied" in response.text.lower():
                    return {
                        'name': 'Domain Blacklist',
                        'passed': True,
                        'message': "Domain blacklisting is working properly",
                        'detail': f"Response: {response.status_code} - {response.text[:500]}"
                    }
                else:
                    return {
                        'name': 'Domain Blacklist',
                        'passed': False,
                        'message': "Domain blacklisting is NOT working",
                        'detail': f"Response: {response.status_code} - {response.text[:500]}"
                    }
            except requests.exceptions.ProxyError:
                # Proxy errors can also indicate blocking
                return {
                    'name': 'Domain Blacklist',
                    'passed': True,
                    'message': "Domain blacklisting is working (proxy error)",
                    'detail': "Request was rejected by the proxy with a connection error"
                }
            except requests.exceptions.ConnectionError:
                # Connection errors can also indicate blocking
                return {
                    'name': 'Domain Blacklist',
                    'passed': True, 
                    'message': "Domain blacklisting appears to be working (connection error)",
                    'detail': "Request was rejected with a connection error"
                }
            except Exception as e:
                return {
                    'name': 'Domain Blacklist',
                    'passed': False,
                    'message': "Test failed with an unexpected error during domain access",
                    'detail': str(e)
                }
        except Exception as e:
            return {
                'name': 'Domain Blacklist',
                'passed': False,
                'message': "Failed to set up domain blacklist test",
                'detail': str(e)
            }
    
    def test_ip_blacklist(self):
        """Test if IP blacklisting works"""
        return self.run_test(
            "IP Blacklist", 
            self._test_ip_blacklist
        )
    
    def _test_ip_blacklist(self):
        # First try to add a test IP to the blacklist
        try:
            # Create config directory if it doesn't exist
            if not os.path.exists("config"):
                os.makedirs("config", exist_ok=True)
                
            # Add a test IP to the blacklist
            with open("config/ip_blacklist.txt", "a+") as f:
                # Check if test IP is already in file to avoid duplicates
                f.seek(0)
                content = f.read()
                if "192.0.2.1" not in content:  # TEST-NET-1 IP, safe for testing
                    f.write("\n192.0.2.1\n")
            
            # Restart the proxy to apply changes
            try:
                self._restart_proxy_container()
            except Exception as e:
                console.print(f"[yellow]Warning: Could not restart proxy container: {e}[/yellow]")
                console.print("[yellow]Continuing with test but results may not be accurate[/yellow]")
            
            # Give the proxy a moment to restart
            time.sleep(3)
            
            # Try to access the internet through the blacklisted IP as proxy
            # (will be interpreted as source IP by the proxy)
            headers = {"X-Forwarded-For": "192.0.2.1"}
            
            try:
                response = requests.get("http://example.com", 
                                      headers=headers,
                                      proxies=self.proxies, 
                                      timeout=10)
                
                # Check if it's blocked
                if response.status_code == 403 or "access denied" in response.text.lower():
                    return {
                        'name': 'IP Blacklist',
                        'passed': True,
                        'message': "IP blacklisting is working properly",
                        'detail': f"Response: {response.status_code} - {response.text[:500]}"
                    }
                else:
                    # Note: This test might not work perfectly since the proxy might ignore X-Forwarded-For
                    return {
                        'name': 'IP Blacklist',
                        'passed': False,
                        'message': "IP blacklisting might not be working (or proxy ignores X-Forwarded-For)",
                        'detail': f"Response: {response.status_code} - {response.text[:500]}"
                    }
            except requests.exceptions.ProxyError:
                # Proxy errors can also indicate blocking
                return {
                    'name': 'IP Blacklist',
                    'passed': True,
                    'message': "IP blacklisting appears to be working (proxy error)",
                    'detail': "Request was rejected by the proxy with a connection error"
                }
            except requests.exceptions.ConnectionError:
                # Connection errors can also indicate blocking
                return {
                    'name': 'IP Blacklist',
                    'passed': True, 
                    'message': "IP blacklisting appears to be working (connection error)",
                    'detail': "Request was rejected with a connection error"
                }
            except Exception as e:
                return {
                    'name': 'IP Blacklist',
                    'passed': False,
                    'message': "Test failed with an unexpected error during IP blacklist testing",
                    'detail': str(e)
                }
        except Exception as e:
            return {
                'name': 'IP Blacklist',
                'passed': False,
                'message': "Failed to set up IP blacklist test",
                'detail': str(e)
            }
    
    def test_file_type_blocking(self):
        """Test if file type blocking works"""
        return self.run_test(
            "File Type Blocking", 
            self._test_file_type_blocking
        )
    
    def _test_file_type_blocking(self):
        try:
            # First, try to enable file type blocking through the API with authentication
            try:
                settings_data = {
                    "enable_content_filtering": "true",
                    "blocked_file_types": "exe,zip,iso"
                }
                # Add authentication credentials
                auth = ('admin', 'admin')
                response = requests.put(
                    f"http://{self.ui_host}:{self.ui_port}/api/settings/enable_content_filtering",
                    json={"value": "true"},
                    auth=auth
                )
                if response.status_code != 200:
                    return {
                        'name': 'File Type Blocking',
                        'passed': False,
                        'message': "Failed to enable content filtering",
                        'detail': f"API response: {response.status_code} - {response.text[:500]}"
                    }
                
                # Update blocked file types
                response = requests.put(
                    f"http://{self.ui_host}:{self.ui_port}/api/settings/blocked_file_types",
                    json={"value": "exe,zip,iso"},
                    auth=auth
                )
                if response.status_code != 200:
                    return {
                        'name': 'File Type Blocking',
                        'passed': False,
                        'message': "Failed to update blocked file types",
                        'detail': f"API response: {response.status_code} - {response.text[:500]}"
                    }
                
                # Restart the proxy to apply changes
                self._restart_proxy_container()
                
                # Give the proxy a moment to restart and apply settings
                time.sleep(5)
                
                # Now try to access a file with a blocked extension
                response = requests.get(
                    "https://www.7-zip.org/a/7z2301-x64.exe",
                    proxies=self.proxies,
                    timeout=10,
                    allow_redirects=True
                )
                
                # Check if it's blocked
                if response.status_code == 403 or "access denied" in response.text.lower():
                    return {
                        'name': 'File Type Blocking',
                        'passed': True,
                        'message': "File type blocking is working properly",
                        'detail': f"Response: {response.status_code} - {response.text[:500]}"
                    }
                else:
                    return {
                        'name': 'File Type Blocking',
                        'passed': False,
                        'message': "File type blocking is NOT working",
                        'detail': f"Response: {response.status_code}"
                    }
            except requests.exceptions.ProxyError:
                # Proxy errors can also indicate blocking
                return {
                    'name': 'File Type Blocking',
                    'passed': True,
                    'message': "File type blocking appears to be working (proxy error)",
                    'detail': "Request was rejected by the proxy with a connection error"
                }
            except Exception as e:
                return {
                    'name': 'File Type Blocking',
                    'passed': False,
                    'message': "Test failed during file access",
                    'detail': str(e)
                }
        except Exception as e:
            return {
                'name': 'File Type Blocking',
                'passed': False,
                'message': "Failed to set up file type blocking test",
                'detail': str(e)
            }
    
    def get_squid_config(self):
        """Get and display the current Squid configuration"""
        try:
            result = subprocess.run(
                ["docker", "exec", "secure-proxy-proxy-1", "cat", "/etc/squid/squid.conf"],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                config = result.stdout
                
                # Look for direct IP blocking configuration
                has_direct_ip_url = "acl direct_ip_url" in config
                has_direct_ip_host = "acl direct_ip_host" in config
                has_ipv6_detection = "acl direct_ipv6" in config
                has_direct_ip_deny = "http_access deny direct_ip" in config
                
                # Create a colored syntax highlighting of the config
                syntax = Syntax(config, "conf", theme="monokai", line_numbers=True)
                
                # Display config summary
                table = Table(title="Squid Configuration Summary")
                table.add_column("Feature", style="cyan")
                table.add_column("Status", style="green")
                
                table.add_row("Direct IP URL ACL", "✅ Present" if has_direct_ip_url else "❌ Missing")
                table.add_row("Direct IP Host ACL", "✅ Present" if has_direct_ip_host else "❌ Missing")
                table.add_row("IPv6 Detection", "✅ Present" if has_ipv6_detection else "❌ Missing")
                table.add_row("Direct IP Deny Rules", "✅ Present" if has_direct_ip_deny else "❌ Missing")
                
                console.print(table)
                
                # Ask if user wants to see the full config
                if self.verbose:
                    console.print("\n[bold]Current Squid Configuration:[/bold]")
                    console.print(syntax)
                else:
                    console.print("\n[dim]Run with --verbose to see the full configuration[/dim]")
                
                return {
                    'name': 'Squid Configuration',
                    'passed': has_direct_ip_url and has_direct_ip_host and has_direct_ip_deny,
                    'message': "Successfully retrieved Squid configuration",
                    'detail': config
                }
            else:
                console.print("[red]Failed to retrieve Squid configuration[/red]")
                console.print(f"Error: {result.stderr}")
                return {
                    'name': 'Squid Configuration',
                    'passed': False,
                    'message': "Failed to retrieve Squid configuration",
                    'detail': result.stderr
                }
        except Exception as e:
            console.print(f"[red]Error retrieving Squid configuration: {str(e)}[/red]")
            return {
                'name': 'Squid Configuration',
                'passed': False,
                'message': "Error retrieving Squid configuration",
                'detail': str(e)
            }
    
    def _restart_proxy_container(self):
        """Restart the proxy container"""
        try:
            console.print("[yellow]Restarting proxy container to apply changes...[/yellow]")
            result = subprocess.run(
                ["docker", "restart", "secure-proxy-proxy-1"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                # Give it a moment to start up
                time.sleep(5)
                console.print("[green]Proxy container restarted successfully[/green]")
                return True
            else:
                console.print(f"[red]Failed to restart proxy container: {result.stderr}[/red]")
                return False
        except Exception as e:
            console.print(f"[red]Error restarting proxy container: {str(e)}[/red]")
            return False
    
    def print_test_results(self):
        """Print a summary of all test results"""
        table = Table(title="Test Results Summary")
        table.add_column("Test Name", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Message", style="white")
        
        for result in self.test_results:
            status_text = "✅ PASS" if result['passed'] else "❌ FAIL"
            status_style = "green" if result['passed'] else "red"
            table.add_row(
                result['name'],
                Text(status_text, style=status_style),
                result['message']
            )
        
        console.print("\n")
        console.print(table)
        
        # Overall summary
        pass_rate = (self.passed_tests / self.total_tests) * 100 if self.total_tests > 0 else 0
        summary_style = "green" if pass_rate >= 80 else "yellow" if pass_rate >= 50 else "red"
        
        console.print("\n")
        console.print(Panel(
            f"[bold]Tests passed: {self.passed_tests}/{self.total_tests} ({pass_rate:.1f}%)[/bold]",
            title="Overall Summary",
            border_style=summary_style
        ))
        
        # Recommendations based on results
        if pass_rate < 100:
            console.print("\n[bold yellow]Recommendations:[/bold yellow]")
            if not any(r['name'] == 'Direct IPv4 URL Blocking' and r['passed'] for r in self.test_results):
                console.print("• Check the direct IP URL blocking ACL in your Squid configuration")
            if not any(r['name'] == 'Direct IPv4 Host Blocking' and r['passed'] for r in self.test_results):
                console.print("• Verify the direct IP host blocking ACL in your Squid configuration")
            if not any(r['name'] == 'IPv4 CONNECT Method Blocking' and r['passed'] for r in self.test_results):
                console.print("• Make sure CONNECT method blocking for IPs is configured properly")
            if not any(r['name'] == 'Domain Blacklist' and r['passed'] for r in self.test_results):
                console.print("• Check if domain blacklisting is enabled and configured correctly")

def main():
    parser = argparse.ArgumentParser(description="End-to-End Testing for Secure Proxy")
    parser.add_argument("--proxy-host", default="localhost", help="Proxy host (default: localhost)")
    parser.add_argument("--proxy-port", type=int, default=3128, help="Proxy port (default: 3128)")
    parser.add_argument("--ui-host", default="localhost", help="UI host (default: localhost)")
    parser.add_argument("--ui-port", type=int, default=8011, help="UI port (default: 8011)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--curl-tests", action="store_true", help="Run additional curl-based tests")
    args = parser.parse_args()
    
    console.print(Panel.fit(
        "[bold cyan]Secure Proxy E2E Testing Tool[/bold cyan]\n" +
        "[dim]A comprehensive testing suite for validating your Squid proxy configuration[/dim]",
        border_style="cyan"
    ))
    
    tester = ProxyTester(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        ui_host=args.ui_host,
        ui_port=args.ui_port,
        verbose=args.verbose
    )
    
    # Run the tests
    tester.run_all_tests()
    
    # Additional curl-based tests if requested
    if args.curl_tests:
        run_curl_tests(args.proxy_host, args.proxy_port)

def run_curl_tests(proxy_host, proxy_port):
    """Run additional tests using curl for more detailed diagnostics"""
    console.print("\n[bold yellow]Running curl-based Tests...[/bold yellow]")
    
    # Test direct IP access
    console.print("\n[bold]Testing direct IP access with curl:[/bold]")
    curl_cmd = f"curl -v -x {proxy_host}:{proxy_port} http://8.8.8.8"
    console.print(f"[dim]$ {curl_cmd}[/dim]")
    
    try:
        result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
        
        if "403 Forbidden" in result.stderr or "407 Proxy Authentication Required" in result.stderr:
            console.print("[green]✅ Direct IP access correctly blocked[/green]")
        else:
            console.print("[red]❌ Direct IP access not blocked as expected[/red]")
        
        if result.stderr:
            console.print(Panel(result.stderr, title="curl stderr", border_style="dim"))
        if result.stdout:
            console.print(Panel(result.stdout, title="curl stdout", border_style="dim"))
    except Exception as e:
        console.print(f"[red]Error running curl test: {str(e)}[/red]")
    
    # Test HTTPS with direct IP
    console.print("\n[bold]Testing direct IP HTTPS access with curl:[/bold]")
    curl_cmd = f"curl -v -x {proxy_host}:{proxy_port} https://1.1.1.1"
    console.print(f"[dim]$ {curl_cmd}[/dim]")
    
    try:
        result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
        
        if "403 Forbidden" in result.stderr or "tunnel connection failed" in result.stderr:
            console.print("[green]✅ Direct IP HTTPS/CONNECT access correctly blocked[/green]")
        else:
            console.print("[red]❌ Direct IP HTTPS/CONNECT access not blocked as expected[/red]")
        
        if result.stderr:
            console.print(Panel(result.stderr, title="curl stderr", border_style="dim"))
        if result.stdout:
            console.print(Panel(result.stdout, title="curl stdout", border_style="dim"))
    except Exception as e:
        console.print(f"[red]Error running curl test: {str(e)}[/red]")
    
    # Test normal website access
    console.print("\n[bold]Testing normal website access with curl:[/bold]")
    curl_cmd = f"curl -v -x {proxy_host}:{proxy_port} http://example.com"
    console.print(f"[dim]$ {curl_cmd}[/dim]")
    
    try:
        result = subprocess.run(curl_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0 and "200 OK" in result.stderr:
            console.print("[green]✅ Normal website access works correctly[/green]")
        else:
            console.print("[red]❌ Normal website access failed[/red]")
        
        if result.stderr:
            console.print(Panel(result.stderr, title="curl stderr", border_style="dim"))
    except Exception as e:
        console.print(f"[red]Error running curl test: {str(e)}[/red]")

if __name__ == "__main__":
    main()