import yaml
import requests
import json
import os
import logging
from jinja2 import Environment, FileSystemLoader
from jsonschema import validate, ValidationError
import unittest
import jinja2

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
                         "auth_users": {"type": "array","items": {"type": "string"}}
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
         local_ip_blacklists.append(local_path)

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
        local_dns_blacklists.append(local_path)

    if config.get("block_vpn", False):
        for i, source in enumerate(config.get("vpn_ip_sources", [])):
             local_path = os.path.join(temp_dir, f"vpn_ips_{i + 1}.txt")
             try:
                 download_file(source, local_path)
             except Exception as e:
                 logging.error(f"Failed to download remote vpn ip file: {source}")
                 continue
             local_vpn_ips.append(local_path)

    if config.get("block_tor", False):
        for i, source in enumerate(config.get("tor_ip_sources", [])):
             local_path = os.path.join(temp_dir, f"tor_ips_{i + 1}.txt")
             try:
                 download_file(source, local_path)
             except Exception as e:
                 logging.error(f"Failed to download remote tor ip file: {source}")
                 continue
             local_tor_ips.append(local_path)

    if config.get("block_cloudflare", False):
        for i, source in enumerate(config.get("cloudflare_ip_sources", [])):
             local_path = os.path.join(temp_dir, f"cloudflare_ips_{i + 1}.txt")
             try:
                 download_file(source, local_path)
             except Exception as e:
                  logging.error(f"Failed to download remote cloudflare ip file: {source}")
                  continue
             local_cloudflare_ips.append(local_path)

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
             local_aws_ips.append(local_path)

    if config.get("block_microsoft", False):
         for i, source in enumerate(config.get("microsoft_ip_sources", [])):
             local_path = os.path.join(temp_dir, f"microsoft_ips_{i + 1}.txt")
             try:
                 download_file(source, local_path)
             except Exception as e:
                  logging.error(f"Failed to download remote microsoft ip file: {source}")
                  continue
             local_microsoft_ips.append(local_path)

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
             local_google_ips.append(local_path)
    
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
        return {
            "port": squid_config["port"],
            "ssl_port": squid_config.get("ssl_port"),
            "ssl_intercept": squid_config.get("ssl_intercept", False),
            "allowed_ips": squid_config["allowed_ips"],
            "ip_blacklists": [f"/etc/squid/{path}" for path in blacklist_files["ip_blacklists"]],
            "dns_blacklists": [f"/etc/squid/{path}" for path in blacklist_files["dns_blacklists"]],
            "owasp_rules_file": f"/etc/squid/{blacklist_files['owasp_rules_file']}" if blacklist_files["owasp_rules_file"] else None,
            "block_vpn": squid_config.get("block_vpn", False),
            "vpn_ips": [f"/etc/squid/{path}" for path in blacklist_files["vpn_ips"]],
            "block_tor": squid_config.get("block_tor", False),
            "tor_ips": [f"/etc/squid/{path}" for path in blacklist_files["tor_ips"]],
            "block_cloudflare": squid_config.get("block_cloudflare", False),
            "cloudflare_ips": [f"/etc/squid/{path}" for path in blacklist_files["cloudflare_ips"]],
            "block_aws": squid_config.get("block_aws", False),
            "aws_ips": [f"/etc/squid/{path}" for path in blacklist_files["aws_ips"]],
            "block_microsoft": squid_config.get("block_microsoft", False),
             "microsoft_ips": [f"/etc/squid/{path}" for path in blacklist_files["microsoft_ips"]],
            "block_google": squid_config.get("block_google", False),
            "google_ips": [f"/etc/squid/{path}" for path in blacklist_files["google_ips"]],
             "user_agent_rewrite": squid_config.get("user_agent_rewrite", {}),
            "logging": squid_config.get("logging", {}),
            "cache": squid_config.get("cache", {}),
            "authentication": squid_config.get("authentication", {}),
            "time_restrictions": squid_config.get("time_restrictions", []),
            "custom_acls": squid_config.get("custom_acls", []),
        }

def generate_squid_config(template_data, template_path="squid.conf.j2"):
    """Generate Squid configuration using Jinja2 template."""
    try:
        env = jinja2.Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
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


class TestConfigGenerator(unittest.TestCase):
    """Test cases for the configuration generator"""
    
    def setUp(self):
        self.test_config = {
                "squid": {
                    "port": 3128,
                    "allowed_ips": ["192.168.1.0/24"],
                    "ip_blacklist_sources": [],
                     "dns_blacklist_sources": [],
                     "owasp_protection": False,
                     "block_vpn": False,
                    "block_tor": False,
                    "block_cloudflare": False,
                    "block_aws": False,
                    "block_microsoft": False,
                    "block_google": False,
                    "vpn_ip_sources": [],
                    "tor_ip_sources": [],
                    "cloudflare_ip_sources": [],
                    "aws_ip_sources": [],
                    "microsoft_ip_sources": [],
                    "google_ip_sources": [],
                    "user_agent_rewrite": {"enabled": False, "rules": []},
                    "logging": {},
                    "cache": {},
                    "authentication": {},
                    "time_restrictions": [],
                    "custom_acls": []
                   }
                }
        self.temp_dir = "test_temp"
        os.makedirs(self.temp_dir, exist_ok=True)


    def tearDown(self):
        os.rmdir(self.temp_dir)

    def test_validate_valid_config(self):
      """ Test a valid configuration"""
      try:
         validate_config(self.test_config)
      except Exception:
         self.fail("validation failed on a valid config")

    def test_validate_invalid_config(self):
        """Test an invalid configuration"""
        invalid_config = { "squid": { "allowed_ips": ["192.168.1.0/24"]}} # Missing port.
        with self.assertRaises(ValidationError):
            validate_config(invalid_config)


    def test_download_file(self):
        """ Test file download"""
        test_url = "https://www.google.com"
        test_local_path = os.path.join(self.temp_dir, "test_file.txt")
        try:
            download_file(test_url, test_local_path)
            self.assertTrue(os.path.exists(test_local_path))
        except Exception as e:
              self.fail(f"Error downloading file: {e}")
        finally:
            if os.path.exists(test_local_path):
                os.remove(test_local_path)

    def test_download_invalid_url(self):
         """Test file download with an invalid URL"""
         test_url = "https://thisisnotawebsite.website"
         test_local_path = os.path.join(self.temp_dir, "test_file.txt")
         with self.assertRaises(Exception):
             download_file(test_url, test_local_path)

    def test_extract_ips_from_valid_json(self):
        """Test extract ips from json function with valid json data"""
        test_json = {"prefixes": [{"ip_prefix": "192.168.1.0/24"}, {"ip_prefix": "10.0.0.0/24"}]}
        expected_ips = ["192.168.1.0/24", "10.0.0.0/24"]
        actual_ips = extract_ips_from_json(test_json, "prefixes")
        self.assertEqual(actual_ips, [{"ip_prefix": "192.168.1.0/24"}, {"ip_prefix": "10.0.0.0/24"}])

    def test_extract_ips_from_invalid_json(self):
        """Test extract ips from json function with invalid json data"""
        test_json = {"no_prefixes": ["192.168.1.0/24", "10.0.0.0/24"]}
        expected_ips = []
        actual_ips = extract_ips_from_json(test_json, "prefixes")
        self.assertEqual(actual_ips, [])


    def test_generate_squid_config(self):
       """ Test that the squid config is generated correctly"""
       template_data = {
             "port": 3128,
             "ssl_port": 3129,
             "ssl_intercept": False,
             "allowed_ips": ["192.168.1.0/24", "10.0.0.1"],
             "ip_blacklists": [],
            "dns_blacklists": [],
            "owasp_rules_file": None,
            "block_vpn": False,
            "vpn_ips": [],
            "block_tor": False,
            "tor_ips": [],
            "block_cloudflare": False,
            "cloudflare_ips": [],
            "block_aws": False,
            "aws_ips": [],
            "block_microsoft": False,
            "microsoft_ips": [],
             "block_google": False,
            "google_ips": [],
             "user_agent_rewrite": {"enabled": False, "rules": []},
             "logging": {},
             "cache": {},
             "authentication": {},
             "time_restrictions": [],
              "custom_acls": []
       }
       try:
           squid_conf = generate_squid_config(template_data, "squid.conf.j2")
           self.assertIsNotNone(squid_conf)
       except Exception as e:
           self.fail(f"Error generating squid config: {e}")

if __name__ == "__main__":
    main()
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
