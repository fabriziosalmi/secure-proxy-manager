import yaml
import requests
import json
import os
import logging
from jinja2 import Environment, FileSystemLoader
from jsonschema import validate, ValidationError

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the configuration schema
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "squid": {
            "type": "object",
            "required": ["port", "allowed_ips"],
            "properties": {
                "port": {"type": "integer"},
                "ssl_port": {"type": "integer"},
                "ssl_intercept": {"type": "boolean"},
                "allowed_ips": {"type": "array", "items": {"type": "string"}},
                "ip_blacklist_sources": {"type": "array", "items": {"type": "string"}},
                "dns_blacklist_sources": {"type": "array", "items": {"type": "string"}},
                "owasp_protection": {"type": "boolean"},
                "owasp_rules_file": {"type": "string"},
                "block_vpn": {"type": "boolean"},
                "block_tor": {"type": "boolean"},
                "block_cloudflare": {"type": "boolean"},
                "block_aws": {"type": "boolean"},
                "block_microsoft": {"type": "boolean"},
                "block_google": {"type": "boolean"},
                "vpn_ip_sources": {"type": "array", "items": {"type": "string"}},
                "tor_ip_sources": {"type": "array", "items": {"type": "string"}},
                "cloudflare_ip_sources": {"type": "array", "items": {"type": "string"}},
                "aws_ip_sources": {"type": "array", "items": {"type": "string"}},
                "microsoft_ip_sources": {"type": "array", "items": {"type": "string"}},
                "google_ip_sources": {"type": "array", "items": {"type": "string"}},
                "user_agent_rewrite": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "rules": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "user_agent": {"type": "string"},
                                    "rewrite_to": {"type": "string"},
                                    "block": {"type": "boolean"}
                                }
                            }
                        }
                    }
                },
                "logging": {
                    "type": "object",
                    "properties": {
                        "access_log": {"type": "string"},
                        "cache_log": {"type": "string"},
                        "log_format": {"type": "string"}
                    }
                },
                "cache": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "cache_dir": {"type": "string"},
                        "cache_size": {"type": "integer"},
                        "max_object_size": {"type": "string"}
                    }
                },
                "authentication": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "auth_file": {"type": "string"},
                        "auth_users": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "time_restrictions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "days": {"type": "string"},
                            "time": {"type": "string"},
                            "action": {"type": "string"}
                        }
                    }
                },
                "custom_acls": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string"},
                            "values": {"type": "array", "items": {"type": "string"}},
                            "action": {"type": "string"}
                        }
                    }
                }
            }
        }
    },
    "required": ["squid"]
}


def validate_config(config):
    """Validate the configuration against the schema."""
    try:
        validate(config, CONFIG_SCHEMA)
        logging.info("Configuration is valid.")
    except ValidationError as e:
        logging.error(f"Configuration validation error: {e}")
        raise


def download_file(url, local_path):
    """Download a file from a URL and save it locally."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        with open(local_path, "wb") as file:
            file.write(response.content)
        logging.info(f"Downloaded {url} to {local_path}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading {url}: {e}")
        raise


def download_json(url):
    """Download and parse a JSON file from a URL."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error downloading JSON from {url}: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {url}: {e}")
        raise


def extract_ips_from_json(json_data, key_path):
    """Extract IP ranges from a JSON file using a key path."""
    try:
        keys = key_path.split(".")
        data = json_data
        for key in keys:
            data = data.get(key, {})
        if isinstance(data, list):
            return data
        else:
            logging.warning(f"No IP ranges found for key path {key_path}")
            return []
    except Exception as e:
        logging.error(f"Error extracting IPs from JSON: {e}")
        raise


def prepare_blacklist_files(config, temp_dir):
    """Download and prepare blacklist files."""
    local_ip_blacklists = []
    local_dns_blacklists = []
    local_vpn_ips = []
    local_tor_ips = []
    local_cloudflare_ips = []
    local_aws_ips = []
    local_microsoft_ips = []
    local_google_ips = []

    for i, source in enumerate(config.get("ip_blacklist_sources", [])):
        local_path = os.path.join(temp_dir, f"ip_blacklist_{i + 1}.txt")
        if source.startswith("http"):
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote ip blacklist file: {source}")
                continue
        else:
            if not os.path.exists(source):
                logging.error(f"Local ip blacklist file not found: {source}")
                raise Exception(f"Local ip blacklist file not found: {source}")
            logging.info(f"Using local ip blacklist file: {source}")
            local_path = source
        local_ip_blacklists.append((i, local_path))

    for i, source in enumerate(config.get("dns_blacklist_sources", [])):
        local_path = os.path.join(temp_dir, f"dns_blacklist_{i + 1}.txt")
        if source.startswith("http"):
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote dns blacklist file: {source}")
                continue
        else:
            if not os.path.exists(source):
                logging.error(f"Local dns blacklist file not found: {source}")
                raise Exception(f"Local dns blacklist file not found: {source}")
            logging.info(f"Using local dns blacklist file: {source}")
            local_path = source
        local_dns_blacklists.append((i, local_path))

    if config.get("block_vpn", False):
        for i, source in enumerate(config.get("vpn_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"vpn_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote vpn ip file: {source}")
                continue
            local_vpn_ips.append((i, local_path))

    if config.get("block_tor", False):
        for i, source in enumerate(config.get("tor_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"tor_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote tor ip file: {source}")
                continue
            local_tor_ips.append((i, local_path))

    if config.get("block_cloudflare", False):
        for i, source in enumerate(config.get("cloudflare_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"cloudflare_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote cloudflare ip file: {source}")
                continue
            local_cloudflare_ips.append((i, local_path))

    if config.get("block_aws", False):
        for i, source in enumerate(config.get("aws_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"aws_ips_{i + 1}.txt")
            try:
                json_data = download_json(source)
                ip_ranges = extract_ips_from_json(json_data, "prefixes")
                ip_prefixes = [item["ip_prefix"] for item in ip_ranges]
                with open(local_path, "w") as file:
                    file.write("\n".join(ip_prefixes))
            except Exception as e:
                logging.error(f"Failed to download remote aws ip file: {source}")
                continue
            local_aws_ips.append((i, local_path))

    if config.get("block_microsoft", False):
        for i, source in enumerate(config.get("microsoft_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"microsoft_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote microsoft ip file: {source}")
                continue
            local_microsoft_ips.append((i, local_path))

    if config.get("block_google", False):
        for i, source in enumerate(config.get("google_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"google_ips_{i + 1}.txt")
            try:
                json_data = download_json(source)
                ip_ranges = extract_ips_from_json(json_data, "prefixes")
                ip_prefixes = [item.get("ipv4Prefix") or item.get("ipv6Prefix") for item in ip_ranges]
                with open(local_path, "w") as file:
                    file.write("\n".join(ip_prefixes))
            except Exception as e:
                logging.error(f"Failed to download remote google ip file: {source}")
                continue
            local_google_ips.append((i, local_path))

    if config.get("owasp_protection", False):
        owasp_rules_file = config.get("owasp_rules_file", "https://raw.githubusercontent.com/SpiderLabs/owasp-modsecurity-crs/v3.3/dev/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf")
        local_path = os.path.join(temp_dir, "owasp.rules")
        try:
            download_file(owasp_rules_file, local_path)
        except Exception as e:
            logging.error(f"Failed to download remote owasp rules file: {owasp_rules_file}")
            local_path = None
    else:
        local_path = None

    return {
        "ip_blacklists": local_ip_blacklists,
        "dns_blacklists": local_dns_blacklists,
        "vpn_ips": local_vpn_ips,
        "tor_ips": local_tor_ips,
        "cloudflare_ips": local_cloudflare_ips,
        "aws_ips": local_aws_ips,
        "microsoft_ips": local_microsoft_ips,
        "google_ips": local_google_ips,
        "owasp_rules_file": local_path
    }


def prepare_template_data(config, blacklist_files, temp_dir):
    """Prepare data for the Jinja2 template."""
    squid_config = config["squid"]
    template_data = {
        "port": squid_config["port"],
        "ssl_port": squid_config.get("ssl_port"),
        "ssl_intercept": squid_config.get("ssl_intercept", False),
        "allowed_ips": squid_config["allowed_ips"],
        "ip_blacklists": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["ip_blacklists"]],
        "ip_blacklist_length": len(blacklist_files["ip_blacklists"]),
        "dns_blacklists": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["dns_blacklists"]],
        "dns_blacklist_length": len(blacklist_files["dns_blacklists"]),
        "owasp_rules_file": f"/etc/squid/{blacklist_files['owasp_rules_file']}" if blacklist_files["owasp_rules_file"] else None,
        "block_vpn": squid_config.get("block_vpn", False),
        "vpn_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["vpn_ips"]],
        "vpn_ips_length": len(blacklist_files["vpn_ips"]),
        "block_tor": squid_config.get("block_tor", False),
        "tor_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["tor_ips"]],
        "tor_ips_length": len(blacklist_files["tor_ips"]),
        "block_cloudflare": squid_config.get("block_cloudflare", False),
        "cloudflare_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["cloudflare_ips"]],
        "cloudflare_ips_length": len(blacklist_files["cloudflare_ips"]),
        "block_aws": squid_config.get("block_aws", False),
        "aws_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["aws_ips"]],
        "aws_ips_length": len(blacklist_files["aws_ips"]),
        "block_microsoft": squid_config.get("block_microsoft", False),
        "microsoft_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["microsoft_ips"]],
        "microsoft_ips_length": len(blacklist_files["microsoft_ips"]),
        "block_google": squid_config.get("block_google", False),
        "google_ips": [(i, f"/etc/squid/{path}") for i, path in blacklist_files["google_ips"]],
        "google_ips_length": len(blacklist_files["google_ips"]),
        "user_agent_rewrite": squid_config.get("user_agent_rewrite", {}),
        "logging": squid_config.get("logging", {}),
        "cache": squid_config.get("cache", {}),
        "authentication": squid_config.get("authentication", {}),
        "time_restrictions": squid_config.get("time_restrictions", []),
        "custom_acls": squid_config.get("custom_acls", []),
    }
    logging.info(f"Template data: {template_data}")
    logging.info(f"User-Agent Rewrite Rules: {template_data['user_agent_rewrite'].get('rules')}")
    return template_data


def generate_squid_config(template_data, template_path="squid.conf.j2"):
    """Generate Squid configuration using Jinja2 template."""
    try:
        env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
        template = env.get_template(os.path.basename(template_path))
        squid_conf = template.render(template_data)
        logging.info("Squid configuration generated successfully using template.")
        return squid_conf
    except Exception as e:
        logging.error(f"Error generating squid config using Jinja2: {e}")
        raise


def main():
    """Main function to generate Squid configuration."""
    try:
        # Load YAML configuration
        with open("config.yaml", "r") as file:
            config = yaml.safe_load(file)

        # Validate the configuration
        validate_config(config)

        # Temporary directory for blacklist files
        temp_dir = "temp_squid_files"
        os.makedirs(temp_dir, exist_ok=True)

        # Prepare blacklist files
        blacklist_files = prepare_blacklist_files(config["squid"], temp_dir)

        # Prepare template data
        template_data = prepare_template_data(config, blacklist_files, temp_dir)

        # Generate Squid config
        squid_conf = generate_squid_config(template_data)

        # Write Squid configuration to file
        with open("squid.conf", "w") as file:
            file.write(squid_conf)

        logging.info("squid.conf generated successfully!")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    main()
