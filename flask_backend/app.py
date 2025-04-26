import os
import re
import json
import ipaddress
import subprocess
from flask import Flask, jsonify, request, send_file, redirect, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration paths - Use environment variables with defaults
BASE_DIR = os.environ.get('BASE_DIR', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SQUID_CONFIG_DIR = os.environ.get('SQUID_CONFIG_DIR', os.path.join(BASE_DIR, 'squid_config'))
DASHBOARD_DIR = os.environ.get('DASHBOARD_DIR', os.path.join(BASE_DIR, 'dashboard'))
BLACKLIST_DOMAINS_PATH = os.path.join(SQUID_CONFIG_DIR, 'blacklist_domains.txt')
BLACKLIST_IPS_PATH = os.path.join(SQUID_CONFIG_DIR, 'blacklist_ips.txt')
ALLOWED_DIRECT_IPS_PATH = os.path.join(SQUID_CONFIG_DIR, 'allowed_direct_ips.txt')
BAD_USER_AGENTS_PATH = os.path.join(SQUID_CONFIG_DIR, 'bad_user_agents.txt')
SQUID_CONF_PATH = os.path.join(SQUID_CONFIG_DIR, 'squid.conf')

print(f"Base directory: {BASE_DIR}")
print(f"Dashboard directory: {DASHBOARD_DIR}")
print(f"Squid config directory: {SQUID_CONFIG_DIR}")

# Make sure the directories exist
for directory in [SQUID_CONFIG_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

# Add route for root URL - now serve index.html directly
@app.route('/')
def index():
    if os.path.exists(os.path.join(DASHBOARD_DIR, 'index.html')):
        return send_from_directory(DASHBOARD_DIR, 'index.html')
    else:
        return f"Dashboard index.html not found at {os.path.join(DASHBOARD_DIR, 'index.html')}", 404

# Make dashboard files available at root path
@app.route('/<path:filename>')
def serve_static(filename):
    # Check if file exists in dashboard directory
    if os.path.exists(os.path.join(DASHBOARD_DIR, filename)):
        return send_from_directory(DASHBOARD_DIR, filename)
    else:
        # Return 404 if file doesn't exist
        return f"File {filename} not found in {DASHBOARD_DIR}", 404

# Commands
SQUID_RELOAD_COMMAND = "sudo systemctl reload squid"
SQUID_RESTART_COMMAND = "sudo systemctl restart squid"
SQUID_START_COMMAND = "sudo systemctl start squid"
SQUID_STOP_COMMAND = "sudo systemctl stop squid"
SQUID_STATUS_COMMAND = "sudo systemctl status squid"

# Helper Functions
def is_valid_ip(ip_str):
    """Validate an IP address (IPv4 or IPv6)."""
    try:
        # Handle CIDR notation
        if '/' in ip_str:
            ip_part, cidr_part = ip_str.split('/', 1)
            # Validate the IP part
            ipaddress.ip_address(ip_part)
            # Validate the CIDR part
            cidr = int(cidr_part)
            if '.' in ip_part:                
                # IPv4 CIDR should be between 0 and 32
                return 0 <= cidr <= 32
            else:                
                # IPv6 CIDR should be between 0 and 128
                return 0 <= cidr <= 128
        else:
            # Regular IP address
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Validate a domain name."""
    # Pattern for validating domain names
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def read_list_file(file_path):
    """Read a list from a file, one item per line."""
    if not os.path.exists(file_path):
        return []
    
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

def write_list_file(file_path, items):
    """Write a list to a file, one item per line."""
    try:
        with open(file_path, 'w') as f:
            for item in items:
                f.write(f"{item}\n")
        return True
    except Exception as e:
        print(f"Error writing to {file_path}: {e}")
        return False

# API Routes
@app.route('/api/status')
def get_status():
    try:
        result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return jsonify({
                'status': 'running',
                'details': result.stdout
            })
        else:
            return jsonify({
                'status': 'stopped',
                'details': result.stderr
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'details': str(e)
        })

@app.route('/api/control', methods=['POST'])
def control_squid():
    data = request.get_json()
    action = data.get('action')
    
    if action == 'start':
        cmd = SQUID_START_COMMAND
        action_desc = 'started'
    elif action == 'stop':
        cmd = SQUID_STOP_COMMAND
        action_desc = 'stopped'
    elif action == 'restart':
        cmd = SQUID_RESTART_COMMAND
        action_desc = 'restarted'
    elif action == 'reload':
        cmd = SQUID_RELOAD_COMMAND
        action_desc = 'reloaded'
    else:
        return jsonify({
            'status': 'error',
            'message': f'Invalid action: {action}'
        })
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return jsonify({
                'status': 'success',
                'message': f'Squid {action_desc} successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to {action} Squid: {result.stderr}'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        })

@app.route('/api/clients/count')
def get_clients_count():
    # In a real implementation, this would query Squid for active client connections
    # For now, we'll return a placeholder
    return jsonify({
        'count': 3  # Placeholder
    })

@app.route('/api/stats/realtime')
def get_realtime_stats():
    # In a real implementation, this would query Squid for real-time statistics
    # For now, we'll return placeholders
    return jsonify({
        'connections': 12,
        'clients': 3,
        'maxConnections': 1000,
        'maxClients': 100,
        'cpu': 2.5,
        'memory': 12.3,
        'memoryMB': 128,
        'diskUsageMB': 256,
        'pid': 1234
    })

@app.route('/api/security/feature-status')
def get_feature_status():
    return jsonify({
        'ipBlacklist': True,
        'domainBlacklist': True,
        'directIpBlocking': True,
        'userAgentFiltering': True,
        'malwareBlocking': False,
        'httpsFiltering': False
    })

@app.route('/api/security/feature-status', methods=['POST'])
def update_feature_status():
    try:
        data = request.get_json()
        # In a real implementation, this would update Squid configuration files
        return jsonify({
            'status': 'success',
            'message': 'Feature settings updated successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to update feature status: {str(e)}'
        })

@app.route('/api/security/blacklist-ips')
def get_blacklist_ips():
    ips = read_list_file(BLACKLIST_IPS_PATH)
    return jsonify({'ips': ips})

@app.route('/api/security/blacklist-ips', methods=['POST'])
def update_blacklist_ips():
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        # Validate IPs
        for ip in ips:
            if not ip.startswith('#') and not is_valid_ip(ip):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid IP address: {ip}'
                })
        
        success = write_list_file(BLACKLIST_IPS_PATH, ips)
        if success:
            return jsonify({
                'status': 'success',
                'message': 'IP blacklist updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to write IP blacklist file'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error updating IP blacklist: {str(e)}'
        })

@app.route('/api/security/blacklist-domains')
def get_blacklist_domains():
    domains = read_list_file(BLACKLIST_DOMAINS_PATH)
    return jsonify({'domains': domains})

@app.route('/api/security/blacklist-domains', methods=['POST'])
def update_blacklist_domains():
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        # Validate domains
        for domain in domains:
            if not domain.startswith('#') and not is_valid_domain(domain):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid domain: {domain}'
                })
        
        # Write to file
        success = write_list_file(BLACKLIST_DOMAINS_PATH, domains)
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Domain blacklist updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to write domain blacklist file'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error updating domain blacklist: {str(e)}'
        })

@app.route('/api/security/allowed-direct-ips')
def get_allowed_direct_ips():
    ips = read_list_file(ALLOWED_DIRECT_IPS_PATH)
    return jsonify({'ips': ips})

@app.route('/api/security/allowed-direct-ips', methods=['POST'])
def update_allowed_direct_ips():
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        # Validate IPs
        for ip in ips:
            if not ip.startswith('#') and not is_valid_ip(ip):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid IP address: {ip}'
                })
        
        success = write_list_file(ALLOWED_DIRECT_IPS_PATH, ips)
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Allowed direct IPs updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to write allowed direct IPs file'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error updating allowed direct IPs: {str(e)}'
        })

@app.route('/api/security/bad-user-agents')
def get_bad_user_agents():
    agents = read_list_file(BAD_USER_AGENTS_PATH)
    return jsonify({'userAgents': agents})

@app.route('/api/security/bad-user-agents', methods=['POST'])
def update_bad_user_agents():
    try:
        data = request.get_json()
        agents = data.get('userAgents', [])
        
        success = write_list_file(BAD_USER_AGENTS_PATH, agents)
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Bad user agents updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to write bad user agents file'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error updating bad user agents: {str(e)}'
        })

@app.route('/api/config')
def get_config():
    # In a real implementation, this would parse Squid configuration
    # For now, we'll return placeholders
    return jsonify({
        'cacheSize': '100',
        'maxObjectSize': '4 MB'
    })

@app.route('/api/config/raw')
def get_raw_config():
    try:
        if os.path.exists(SQUID_CONF_PATH):
            with open(SQUID_CONF_PATH, 'r') as f:
                content = f.read()
            return jsonify({
                'status': 'success',
                'content': content
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Squid configuration file not found'
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to read config: {str(e)}'
        })

@app.route('/api/config/raw', methods=['POST'])
def update_raw_config():
    try:
        data = request.get_json()
        content = data.get('content', '')
        
        # Create backup
        backup_path = f"{SQUID_CONF_PATH}.backup"
        if os.path.exists(SQUID_CONF_PATH):
            with open(SQUID_CONF_PATH, 'r') as src:
                with open(backup_path, 'w') as dst:
                    dst.write(src.read())
        
        # Write new config
        with open(SQUID_CONF_PATH, 'w') as f:
            f.write(content)
            
        return jsonify({
            'status': 'success',
            'message': 'Configuration updated successfully',
            'backupPath': backup_path
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to update config: {str(e)}'
        })

@app.route('/api/security/cache-settings', methods=['POST'])
def update_cache_settings():
    # This would update the cache settings in a real implementation
    return jsonify({
        'status': 'success',
        'message': 'Cache settings updated successfully'
    })

@app.route('/api/system/info')
def get_system_info():
    # This would return real system information in a production environment
    return jsonify({
        'squidVersion': '4.13',
        'osVersion': 'Ubuntu 22.04 LTS',
        'hostname': 'proxy-server',
        'kernelVersion': '5.15.0-52-generic'
    })

@app.route('/api/logs/<log_type>')
def get_logs(log_type):
    # This would fetch actual logs in a production environment
    # For demo, we'll return dummy data
    lines = request.args.get('lines', default=100, type=int)
    content = [f"{log_type} log line {i}" for i in range(1, lines + 1)]
    
    return jsonify({
        'content': content,
        'totalLines': lines,
        'errorCount': 5,
        'size': 12345
    })

@app.route('/api/logs/<log_type>/analysis')
def analyze_logs(log_type):
    # This would analyze actual logs in a production environment
    return jsonify({
        'topDomains': {'example.com': 120, 'google.com': 85, 'github.com': 42},
        'statusCodes': {'200': 247, '404': 23, '500': 5},
        'requestMethods': {'GET': 200, 'POST': 75, 'HEAD': 15},
        'trafficByHour': {'09': 45, '10': 78, '11': 92, '12': 65}
    })

@app.route('/api/security/ssl-certificate')
def get_certificate_status():
    # This would check the actual certificate in a production environment
    return jsonify({
        'status': 'success',
        'exists': True,
        'certificate': {
            'subject': 'CN=Secure Proxy CA',
            'issuer': 'CN=Secure Proxy CA',
            'validFrom': '2023-01-01',
            'validTo': '2033-01-01',
            'serialNumber': '1234567890abcdef'
        }
    })

@app.route('/api/security/ssl-certificate/generate', methods=['POST'])
def generate_certificate():
    # This would generate a real certificate in a production environment
    return jsonify({
        'status': 'success',
        'message': 'Certificate generated successfully'
    })

@app.route('/api/security/ssl-certificate/download')
def download_certificate():
    # This would return the actual certificate in a production environment
    # For demo, we'll return a placeholder file
    return send_file(os.path.join(BASE_DIR, 'README.md'), as_attachment=True, download_name='secure-proxy-ca.crt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)