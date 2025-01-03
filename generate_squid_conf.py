import yaml
import requests
import json

def download_file(url, local_path):
    """Download a file from a URL and save it locally."""
    response = requests.get(url)
    with open(local_path, "wb") as file:
        file.write(response.content)

def download_json(url):
    """Download and parse a JSON file from a URL."""
    response = requests.get(url)
    return response.json()

def extract_ips_from_json(json_data, key_path):
    """Extract IP ranges from a JSON file using a key path."""
    keys = key_path.split(".")
    data = json_data
    for key in keys:
        data = data.get(key, {})
    return data if isinstance(data, list) else []

# Load YAML configuration
with open("config.yaml", "r") as file:
    config = yaml.safe_load(file)

# Extract configuration
squid_config = config["squid"]
port = squid_config["port"]
ssl_port = squid_config.get("ssl_port")
ssl_intercept = squid_config.get("ssl_intercept", False)
allowed_ips = squid_config["allowed_ips"]
ip_blacklist_sources = squid_config["ip_blacklist_sources"]
dns_blacklist_sources = squid_config["dns_blacklist_sources"]
owasp_protection = squid_config["owasp_protection"]
owasp_rules_file = squid_config.get("owasp_rules_file", "/etc/squid/owasp.rules")
block_vpn = squid_config.get("block_vpn", False)
block_tor = squid_config.get("block_tor", False)
block_cloudflare = squid_config.get("block_cloudflare", False)
block_aws = squid_config.get("block_aws", False)
block_microsoft = squid_config.get("block_microsoft", False)
block_google = squid_config.get("block_google", False)
vpn_ip_sources = squid_config.get("vpn_ip_sources", [])
tor_ip_sources = squid_config.get("tor_ip_sources", [])
cloudflare_ip_sources = squid_config.get("cloudflare_ip_sources", [])
aws_ip_sources = squid_config.get("aws_ip_sources", [])
microsoft_ip_sources = squid_config.get("microsoft_ip_sources", [])
google_ip_sources = squid_config.get("google_ip_sources", [])
user_agent_rewrite = squid_config.get("user_agent_rewrite", {})
logging_config = squid_config.get("logging", {})
cache_config = squid_config.get("cache", {})
auth_config = squid_config.get("authentication", {})
time_restrictions = squid_config.get("time_restrictions", [])
custom_acls = squid_config.get("custom_acls", [])

# Download remote blacklist files (if any)
local_ip_blacklists = []
local_dns_blacklists = []
local_vpn_ips = []
local_tor_ips = []
local_cloudflare_ips = []
local_aws_ips = []
local_microsoft_ips = []
local_google_ips = []

for source in ip_blacklist_sources:
    if source.startswith("http"):
        local_path = f"/etc/squid/ip_blacklist_{len(local_ip_blacklists) + 1}.txt"
        download_file(source, local_path)
        local_ip_blacklists.append(local_path)
    else:
        local_ip_blacklists.append(source)

for source in dns_blacklist_sources:
    if source.startswith("http"):
        local_path = f"/etc/squid/dns_blacklist_{len(local_dns_blacklists) + 1}.txt"
        download_file(source, local_path)
        local_dns_blacklists.append(local_path)
    else:
        local_dns_blacklists.append(source)

if block_vpn:
    for source in vpn_ip_sources:
        local_path = f"/etc/squid/vpn_ips_{len(local_vpn_ips) + 1}.txt"
        download_file(source, local_path)
        local_vpn_ips.append(local_path)

if block_tor:
    for source in tor_ip_sources:
        local_path = f"/etc/squid/tor_ips_{len(local_tor_ips) + 1}.txt"
        download_file(source, local_path)
        local_tor_ips.append(local_path)

if block_cloudflare:
    for source in cloudflare_ip_sources:
        local_path = f"/etc/squid/cloudflare_ips_{len(local_cloudflare_ips) + 1}.txt"
        download_file(source, local_path)
        local_cloudflare_ips.append(local_path)

if block_aws:
    for source in aws_ip_sources:
        local_path = f"/etc/squid/aws_ips_{len(local_aws_ips) + 1}.txt"
        json_data = download_json(source)
        ip_ranges = extract_ips_from_json(json_data, "prefixes")
        with open(local_path, "w") as file:
            file.write("\n".join(ip_ranges))
        local_aws_ips.append(local_path)

if block_microsoft:
    for source in microsoft_ip_sources:
        local_path = f"/etc/squid/microsoft_ips_{len(local_microsoft_ips) + 1}.txt"
        download_file(source, local_path)
        local_microsoft_ips.append(local_path)

if block_google:
    for source in google_ip_sources:
        local_path = f"/etc/squid/google_ips_{len(local_google_ips) + 1}.txt"
        json_data = download_json(source)
        ip_ranges = extract_ips_from_json(json_data, "prefixes")
        with open(local_path, "w") as file:
            file.write("\n".join(ip_ranges))
        local_google_ips.append(local_path)

# Generate Squid configuration
squid_conf = f"""
http_port {port}
{"https_port " + str(ssl_port) + " intercept" if ssl_intercept else ""}

# Allow only specific IPs or IP ranges
acl allowed_ips src {", ".join(allowed_ips)}
http_access allow allowed_ips
http_access deny all

# IP Blacklisting
{"".join([f"acl blacklisted_ips_{i} dstdomain \"{path}\"\n" for i, path in enumerate(local_ip_blacklists)])}
{"".join([f"http_access deny blacklisted_ips_{i}\n" for i in range(len(local_ip_blacklists))])}

# DNS Blacklisting
{"".join([f"acl blacklisted_domains_{i} dstdomain \"{path}\"\n" for i, path in enumerate(local_dns_blacklists)])}
{"".join([f"http_access deny blacklisted_domains_{i}\n" for i in range(len(local_dns_blacklists))])}

# OWASP Protection
{"acl owasp url_regex -i \"" + owasp_rules_file.replace("\\", "\\\\") + "\"" if owasp_protection else ""}
{"http_access deny owasp" if owasp_protection else ""}

# Block VPN IPs
{"".join([f"acl vpn_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_vpn_ips)])}
{"".join([f"http_access deny vpn_ips_{i}\n" for i in range(len(local_vpn_ips))])}

# Block Tor IPs
{"".join([f"acl tor_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_tor_ips)])}
{"".join([f"http_access deny tor_ips_{i}\n" for i in range(len(local_tor_ips))])}

# Block Cloudflare IPs
{"".join([f"acl cloudflare_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_cloudflare_ips)])}
{"".join([f"http_access deny cloudflare_ips_{i}\n" for i in range(len(local_cloudflare_ips))])}

# Block AWS IPs
{"".join([f"acl aws_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_aws_ips)])}
{"".join([f"http_access deny aws_ips_{i}\n" for i in range(len(local_aws_ips))])}

# Block Microsoft IPs
{"".join([f"acl microsoft_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_microsoft_ips)])}
{"".join([f"http_access deny microsoft_ips_{i}\n" for i in range(len(local_microsoft_ips))])}

# Block Google IPs
{"".join([f"acl google_ips_{i} src \"{path}\"\n" for i, path in enumerate(local_google_ips)])}
{"".join([f"http_access deny google_ips_{i}\n" for i in range(len(local_google_ips))])}

# User-Agent rewriting
{"".join([f"acl rewrite_ua_{i} browser \"{rule['user_agent'].replace('\\', '\\\\')}\"\n" for i, rule in enumerate(user_agent_rewrite.get("rules", []))])}
{"".join([f"request_header_replace User-Agent \"{rule['rewrite_to'].replace('\\', '\\\\')}\" rewrite_ua_{i}\n" for i, rule in enumerate(user_agent_rewrite.get("rules", [])) if not rule.get("block", False)])}
{"".join([f"http_access deny rewrite_ua_{i}\n" for i, rule in enumerate(user_agent_rewrite.get("rules", [])) if rule.get("block", False)])}

# Logging
access_log {logging_config.get("access_log", "/var/log/squid/access.log")} {logging_config.get("log_format", "combined")}
cache_log {logging_config.get("cache_log", "/var/log/squid/cache.log")}

# Cache settings
{"cache_dir " + cache_config.get("cache_dir", "/var/spool/squid") + " " + str(cache_config.get("cache_size", 10000)) + " 16 256" if cache_config.get("enabled", True) else ""}
{"maximum_object_size " + cache_config.get("max_object_size", "512 MB") if cache_config.get("enabled", True) else ""}

# Authentication
{"auth_param basic program /usr/lib/squid/basic_ncsa_auth " + auth_config.get("auth_file", "/etc/squid/passwords") if auth_config.get("enabled", False) else ""}
{"acl authenticated_users proxy_auth " + " ".join(auth_config.get("auth_users", [])) if auth_config.get("enabled", False) else ""}
{"http_access allow authenticated_users" if auth_config.get("enabled", False) else ""}

# Time-based restrictions
{"".join([f"acl {restriction['name']} time {restriction['days']} {restriction['time']}\nhttp_access {restriction['action']} {restriction['name']}\n" for restriction in time_restrictions])}

# Custom ACLs
{"".join([f"acl {acl['name']} {acl['type']} {', '.join(acl['values'])}\nhttp_access {acl['action']} {acl['name']}\n" for acl in custom_acls])}
"""

# Write Squid configuration to file
with open("squid.conf", "w") as file:
    file.write(squid_conf)

print("squid.conf generated successfully!")
