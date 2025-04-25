import yaml
import requests
import json
import os
import logging
import sys
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
                "ssl_cert_path": {"type": "string"},
                "ssl_key_path": {"type": "string"},
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
                        "cache_type": {"type": "string"},
                        "cache_size": {"type": "integer"},
                        "max_object_size": {"type": "string"}
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


def download_file(url, local_path, retries=3):
    """Download a file from a URL and save it locally."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            with open(local_path, "wb") as file:
                file.write(response.content)
            logging.info(f"Downloaded {url} to {local_path}")
            return
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt+1}/{retries}: Error downloading {url}: {e}")
            if attempt == retries - 1:
                logging.error(f"All retries failed for {url}")
                raise
            # Wait before retrying
            import time
            time.sleep(2)


def download_json(url, retries=3):
    """Download and parse a JSON file from a URL."""
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.warning(f"Attempt {attempt+1}/{retries}: Error downloading JSON from {url}: {e}")
            if attempt == retries - 1:
                logging.error(f"All retries failed for {url}")
                raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from {url}: {e}")
            raise
        # Wait before retrying
        import time
        time.sleep(2)


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

    # Process IP blacklists
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
                continue
            logging.info(f"Using local ip blacklist file: {source}")
            local_path = source
        local_ip_blacklists.append((i, local_path))

    # Process DNS blacklists
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
                continue
            logging.info(f"Using local dns blacklist file: {source}")
            local_path = source
        local_dns_blacklists.append((i, local_path))

    # Process VPN IPs
    if config.get("block_vpn", False):
        for i, source in enumerate(config.get("vpn_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"vpn_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote vpn ip file: {source}")
                continue
            local_vpn_ips.append((i, local_path))

    # Process Tor IPs
    if config.get("block_tor", False):
        for i, source in enumerate(config.get("tor_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"tor_ips_{i + 1}.txt")
            try:
                download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote tor ip file: {source}")
                continue
            local_tor_ips.append((i, local_path))

    # Process Cloudflare IPs
    if config.get("block_cloudflare", False):
        for i, source in enumerate(config.get("cloudflare_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"cloudflare_ips_{i + 1}.txt")
            try:
                if source.endswith(".json"):
                    json_data = download_json(source)
                    ip_ranges = extract_ips_from_json(json_data, "prefixes")
                    ip_prefixes = [item["ip_prefix"] for item in ip_ranges]
                    with open(local_path, "w") as file:
                        file.write("\n".join(ip_prefixes))
                else:
                    download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote cloudflare ip file: {source}")
                continue
            local_cloudflare_ips.append((i, local_path))

    # Process AWS IPs
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

    # Process Microsoft IPs
    if config.get("block_microsoft", False):
        for i, source in enumerate(config.get("microsoft_ip_sources", [])):
            local_path = os.path.join(temp_dir, f"microsoft_ips_{i + 1}.txt")
            try:
                if source.endswith(".json"):
                    json_data = download_json(source)
                    ip_ranges = extract_ips_from_json(json_data, "prefixes")
                    ip_prefixes = [item["ip_prefix"] for item in ip_ranges]
                    with open(local_path, "w") as file:
                        file.write("\n".join(ip_prefixes))
                else:
                    download_file(source, local_path)
            except Exception as e:
                logging.error(f"Failed to download remote microsoft ip file: {source}")
                continue
            local_microsoft_ips.append((i, local_path))

    # Process Google IPs
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

    # Process OWASP rules
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
        "ssl_cert_path": squid_config.get("ssl_cert_path"),
        "ssl_key_path": squid_config.get("ssl_key_path"),
        "allowed_ips": squid_config["allowed_ips"],
        "ip_blacklists": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["ip_blacklists"]],
        "ip_blacklist_length": len(blacklist_files["ip_blacklists"]),
        "dns_blacklists": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["dns_blacklists"]],
        "dns_blacklist_length": len(blacklist_files["dns_blacklists"]),
        "owasp_rules_file": f"/etc/squid/{os.path.basename(blacklist_files['owasp_rules_file'])}" if blacklist_files["owasp_rules_file"] else None,
        "block_vpn": squid_config.get("block_vpn", False),
        "vpn_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["vpn_ips"]],
        "vpn_ips_length": len(blacklist_files["vpn_ips"]),
        "block_tor": squid_config.get("block_tor", False),
        "tor_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["tor_ips"]],
        "tor_ips_length": len(blacklist_files["tor_ips"]),
        "block_cloudflare": squid_config.get("block_cloudflare", False),
        "cloudflare_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["cloudflare_ips"]],
        "cloudflare_ips_length": len(blacklist_files["cloudflare_ips"]),
        "block_aws": squid_config.get("block_aws", False),
        "aws_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["aws_ips"]],
        "aws_ips_length": len(blacklist_files["aws_ips"]),
        "block_microsoft": squid_config.get("block_microsoft", False),
        "microsoft_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["microsoft_ips"]],
        "microsoft_ips_length": len(blacklist_files["microsoft_ips"]),
        "block_google": squid_config.get("block_google", False),
        "google_ips": [(i, f"/etc/squid/{os.path.basename(path)}") for i, path in blacklist_files["google_ips"]],
        "google_ips_length": len(blacklist_files["google_ips"]),
        "logging": squid_config.get("logging", {}),
        "cache": squid_config.get("cache", {}),
    }
    logging.info(f"Template data prepared successfully")
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
        # Check for config file argument
        config_file = "config.yaml"
        if len(sys.argv) > 1:
            config_file = sys.argv[1]
            
        # Load YAML configuration
        with open(config_file, "r") as file:
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

        # Output file
        output_file = "squid.conf"
        if len(sys.argv) > 2:
            output_file = sys.argv[2]
            
        # Write Squid configuration to file
        with open(output_file, "w") as file:
            file.write(squid_conf)

        logging.info(f"squid.conf generated successfully at {output_file}!")

        # Copy blacklist files to a directory for Docker
        docker_files_dir = "docker_files"
        os.makedirs(docker_files_dir, exist_ok=True)
        
        # Copy all blacklist files to docker_files directory
        for file_type in ["ip_blacklists", "dns_blacklists", "vpn_ips", "tor_ips", 
                         "cloudflare_ips", "aws_ips", "microsoft_ips", "google_ips"]:
            for _, file_path in blacklist_files[file_type]:
                if os.path.exists(file_path):
                    dest_path = os.path.join(docker_files_dir, os.path.basename(file_path))
                    with open(file_path, "rb") as src_file, open(dest_path, "wb") as dest_file:
                        dest_file.write(src_file.read())
                        
        # Copy OWASP rules if they exist
        if blacklist_files["owasp_rules_file"] and os.path.exists(blacklist_files["owasp_rules_file"]):
            dest_path = os.path.join(docker_files_dir, os.path.basename(blacklist_files["owasp_rules_file"]))
            with open(blacklist_files["owasp_rules_file"], "rb") as src_file, open(dest_path, "wb") as dest_file:
                dest_file.write(src_file.read())
                
        logging.info(f"Files prepared for Docker in {docker_files_dir}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)


if __name__ == "__main__":
    main()
