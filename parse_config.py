#!/usr/bin/env python3
import os
import sys
import yaml
import requests

CONFIG_FILE = "/app/config.yaml"
SQUID_CONF_TEMPLATE = "/app/squid.conf.template"
SQUID_CONF_OUTPUT = "/etc/squid/squid.conf"

def fetch_external_list(url):
    """
    Fetch a text file from a URL and return as a list of lines.
    Comments/empty lines are stripped.
    """
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        lines = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
        return lines
    except Exception as e:
        print(f"Warning: Unable to fetch {url}: {e}")
        return []

def load_config():
    """
    Load config.yaml from disk and apply environment overrides.
    Environment variables (if set) take precedence over config.yaml.
    Example: WHITELIST_IPS=1.2.3.4,1.2.3.5 ...
    """
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: {CONFIG_FILE} not found.")
        sys.exit(1)

    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f) or {}

    # Read environment variables (if any) to override or append
    # For multiple items, split by commas
    env_whitelist_ips = os.environ.get("WHITELIST_IPS")
    if env_whitelist_ips:
        # Replace the existing or create a new list
        config["whitelist_ips"] = [ip.strip() for ip in env_whitelist_ips.split(",")]

    env_whitelist_domains = os.environ.get("WHITELIST_DOMAINS")
    if env_whitelist_domains:
        config["whitelist_domains"] = [
            d.strip() for d in env_whitelist_domains.split(",")
        ]

    env_blocked_ips = os.environ.get("BLOCKED_IPS")
    if env_blocked_ips:
        config["blocked_ips"] = [ip.strip() for ip in env_blocked_ips.split(",")]

    env_blocked_domains = os.environ.get("BLOCKED_DOMAINS")
    if env_blocked_domains:
        config["blocked_domains"] = [
            d.strip() for d in env_blocked_domains.split(",")
        ]

    # Example of toggling OWASP by env
    env_owasp_protection = os.environ.get("OWASP_PROTECTION")
    if env_owasp_protection is not None:
        # Convert "true"/"false" strings to boolean
        config.setdefault("features", {})
        config["features"]["owasp_protection"] = (
            env_owasp_protection.lower() in ("true", "1", "yes")
        )

    return config

def generate_squid_config(
    whitelist_ips,
    whitelist_domains,
    blocked_ips,
    blocked_domains,
    features
):
    lines = []

    # Whitelist IPs
    if whitelist_ips:
        lines.append("acl whitelist_ips src {}".format(" ".join(whitelist_ips)))
        lines.append("http_access allow whitelist_ips")

    # Whitelist domains
    if whitelist_domains:
        wl_domain_file = "/etc/squid/whitelist_domains.acl"
        with open(wl_domain_file, "w") as f:
            for domain in whitelist_domains:
                if not domain.startswith("."):
                    domain = "." + domain
                f.write(domain + "\n")
        lines.append(f"acl whitelist_domains dstdomain \"{wl_domain_file}\"")
        lines.append("http_access allow whitelist_domains")

    # Blocked IPs
    if blocked_ips:
        lines.append("acl blocked_ips src {}".format(" ".join(blocked_ips)))
        lines.append("http_access deny blocked_ips")

    # Blocked domains
    if blocked_domains:
        bl_domain_file = "/etc/squid/blocked_domains.acl"
        with open(bl_domain_file, "w") as f:
            for domain in blocked_domains:
                if not domain.startswith("."):
                    domain = "." + domain
                f.write(domain + "\n")
        lines.append(f"acl blocked_domains dstdomain \"{bl_domain_file}\"")
        lines.append("http_access deny blocked_domains")

    # Real OWASP-like or advanced protections
    # This example demonstrates some basic suspicious URL and UA blocking
    if features.get("owasp_protection"):
        lines.append("# BEGIN: Additional ACL rules for OWASP-like protections")
        # Suspicious paths: attempts at directory traversal, /etc/passwd, etc.
        lines.append("acl suspicious_path urlpath_regex -i \\.\\./ \\./\\. /etc/passwd")
        lines.append("http_access deny suspicious_path")

        # Suspicious user-agent: block some known malicious scanners or placeholders
        lines.append("acl suspicious_ua req_header User-Agent -i Nikto|sqlmap|BadBot")
        lines.append("http_access deny suspicious_ua")

        # Suspicious methods: block methods that should not be used externally
        lines.append("acl bad_methods method TRACE DELETE PURGE")
        lines.append("http_access deny bad_methods")
        lines.append("# END: Additional ACL rules for OWASP-like protections")

    return "\n".join(lines)

def main():
    config = load_config()

    whitelist_ips = set(config.get("whitelist_ips", []))
    whitelist_domains = set(config.get("whitelist_domains", []))
    blocked_ips = set(config.get("blocked_ips", []))
    blocked_domains = set(config.get("blocked_domains", []))
    features = config.get("features", {})

    # Fetch external blacklists
    for entry in config.get("external_blocklists", []):
        blk_type = entry.get("type", "").lower()
        blk_url = entry.get("url", "")
        if not blk_type or not blk_url:
            continue
        external_items = fetch_external_list(blk_url)
        if blk_type == "ip":
            blocked_ips.update(external_items)
        elif blk_type == "domain":
            blocked_domains.update(external_items)

    # Fetch external allowlists
    for entry in config.get("external_allowlists", []):
        allow_type = entry.get("type", "").lower()
        allow_url = entry.get("url", "")
        if not allow_type or not allow_url:
            continue
        external_items = fetch_external_list(allow_url)
        if allow_type == "ip":
            whitelist_ips.update(external_items)
        elif allow_type == "domain":
            whitelist_domains.update(external_items)

    # Whitelist takes priority over blocklist
    intersect_ips = whitelist_ips.intersection(blocked_ips)
    if intersect_ips:
        blocked_ips.difference_update(intersect_ips)

    intersect_domains = whitelist_domains.intersection(blocked_domains)
    if intersect_domains:
        blocked_domains.difference_update(intersect_domains)

    with open(SQUID_CONF_TEMPLATE, "r") as f:
        template = f.read()

    acl_rules = generate_squid_config(
        sorted(whitelist_ips),
        sorted(whitelist_domains),
        sorted(blocked_ips),
        sorted(blocked_domains),
        features
    )

    final_conf = template.replace("##CUSTOM_ACLS##", acl_rules)
    with open(SQUID_CONF_OUTPUT, "w") as f:
        f.write(final_conf)

if __name__ == "__main__":
    main()
