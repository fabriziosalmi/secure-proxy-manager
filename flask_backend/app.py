import os
import re
import json
import ipaddress
import subprocess
import time
from datetime import datetime
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

# Commands - Docker-compatible commands for Squid control
# Check if running in Docker and set appropriate commands
IN_DOCKER = os.environ.get('RUNNING_IN_DOCKER', 'false').lower() == 'true'

if IN_DOCKER:
    # In Docker, use supervisorctl for control but pgrep for status
    SQUID_RELOAD_COMMAND = "supervisorctl signal HUP squid"
    SQUID_RESTART_COMMAND = "supervisorctl restart squid"
    SQUID_START_COMMAND = "supervisorctl start squid"
    SQUID_STOP_COMMAND = "supervisorctl stop squid"
    SQUID_STATUS_COMMAND = "pgrep -x squid > /dev/null && echo 'running' || echo 'stopped'"
else:
    # Traditional systemctl commands for non-Docker environments
    SQUID_RELOAD_COMMAND = "sudo systemctl reload squid"
    SQUID_RESTART_COMMAND = "sudo systemctl restart squid"
    SQUID_START_COMMAND = "sudo systemctl start squid"
    SQUID_STOP_COMMAND = "sudo systemctl stop squid"
    SQUID_STATUS_COMMAND = "sudo systemctl status squid"

# Define log directory for Squid logs
SQUID_LOG_DIR = os.environ.get('SQUID_LOG_DIR', '/var/log/squid')

# Add debugging to see which commands are being used
print(f"SQUID_START_COMMAND: {SQUID_START_COMMAND}")
print(f"SQUID_STATUS_COMMAND: {SQUID_STATUS_COMMAND}")

# Squid monitoring configuration
SQUID_HOST = os.environ.get('SQUID_HOST', 'localhost')
SQUID_PORT = int(os.environ.get('SQUID_PORT', 3128))
SQUID_CLIENT_BIN = os.environ.get('SQUID_CLIENT_BIN', 'squidclient')

# Cache for metrics to avoid frequent calls to squid
metrics_cache = {
    'last_update': 0,
    'cache_duration': 5,  # seconds
    'data': {}
}

print(f"Base directory: {BASE_DIR}")
print(f"Dashboard directory: {DASHBOARD_DIR}")
print(f"Squid config directory: {SQUID_CONFIG_DIR}")
print(f"Running in Docker: {IN_DOCKER}")

# Make sure the directories exist
for directory in [SQUID_CONFIG_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

# Health check endpoint for Docker
@app.route('/health')
def health_check():
    return jsonify({'status': 'ok'}), 200

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

# Squid Monitoring Utility Functions
def get_squid_metrics(force_refresh=False):
    """
    Get Squid metrics using squidclient utility
    Returns cached values if called frequently
    """
    current_time = time.time()
    
    # Return cached data if still valid
    if not force_refresh and metrics_cache['last_update'] > 0:
        if current_time - metrics_cache['last_update'] < metrics_cache['cache_duration']:
            return metrics_cache['data']
    
    # Default metrics in case of failure
    default_metrics = {
        'clients': 0,
        'connections': 0,
        'maxClients': 100,
        'maxConnections': 1000,
        'cpu': 0.0,
        'memory': 0.0,
        'memoryMB': 0,
        'diskUsageMB': 0,
        'pid': 0,
        'uptime': 'N/A',
        'status': 'error',
        'error': 'Failed to fetch Squid metrics'
    }
    
    try:
        # Check if squid is running first
        status_result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
        if status_result.returncode != 0:
            default_metrics['status'] = 'stopped'
            default_metrics['error'] = 'Squid is not running'
            metrics_cache['data'] = default_metrics
            metrics_cache['last_update'] = current_time
            return default_metrics

        # Run squidclient to get metrics
        cmd = f"{SQUID_CLIENT_BIN} -h {SQUID_HOST} -p {SQUID_PORT} mgr:info"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if result.returncode != 0:
            metrics_cache['data'] = default_metrics
            metrics_cache['last_update'] = current_time
            return default_metrics
        
        output = result.stdout
        
        # Parse the output to extract metrics
        metrics = {
            'clients': 0,
            'connections': 0,
            'maxClients': 100,
            'maxConnections': 1000,
            'cpu': 0.0,
            'memory': 0.0,
            'memoryMB': 0,
            'diskUsageMB': 0,
            'pid': 0,
            'uptime': 'N/A',
            'status': 'running',
            'error': None
        }
        
        # Extract client count
        client_match = re.search(r'Number of HTTP clients: (\d+)', output)
        if client_match:
            metrics['clients'] = int(client_match.group(1))
        
        # Extract connection count
        conn_match = re.search(r'Number of active connections: (\d+)', output)
        if conn_match:
            metrics['connections'] = int(conn_match.group(1))
        
        # Extract memory usage
        mem_match = re.search(r'Total memory accounted: (\d+)', output)
        if mem_match:
            mem_kb = int(mem_match.group(1))
            metrics['memoryMB'] = mem_kb // 1024  # Convert KB to MB
            
            # Get total system memory to calculate percentage
            mem_info_cmd = "free -m | grep 'Mem:' | awk '{print $2}'"
            mem_info = subprocess.run(mem_info_cmd, shell=True, capture_output=True, text=True)
            if mem_info.returncode == 0 and mem_info.stdout.strip():
                total_mem = int(mem_info.stdout.strip())
                if total_mem > 0:
                    metrics['memory'] = (metrics['memoryMB'] / total_mem) * 100
        
        # Extract disk usage (cache)
        disk_match = re.search(r'Storage Swap size:\s+(\d+) KB', output)
        if disk_match:
            metrics['diskUsageMB'] = int(disk_match.group(1)) // 1024  # Convert KB to MB
        
        # Extract PID
        pid_match = re.search(r'Process id: (\d+)', output)
        if pid_match:
            metrics['pid'] = int(pid_match.group(1))
        
        # Extract uptime
        uptime_match = re.search(r'Service Up Time: ([\d\.\s]+)', output)
        if uptime_match:
            metrics['uptime'] = uptime_match.group(1).strip()
        
        # Extract CPU usage
        # This is more complex and might need a separate command
        cpu_cmd = f"ps -p {metrics['pid']} -o %cpu | tail -1" if metrics['pid'] > 0 else "echo 0"
        cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
        if cpu_result.returncode == 0:
            try:
                metrics['cpu'] = float(cpu_result.stdout.strip())
            except ValueError:
                metrics['cpu'] = 0.0
        
        # Update the cache
        metrics_cache['data'] = metrics
        metrics_cache['last_update'] = current_time
        
        return metrics
    
    except subprocess.TimeoutExpired:
        default_metrics['error'] = 'Squid metrics query timed out'
        metrics_cache['data'] = default_metrics
        metrics_cache['last_update'] = current_time
        return default_metrics
    except Exception as e:
        default_metrics['error'] = str(e)
        metrics_cache['data'] = default_metrics
        metrics_cache['last_update'] = current_time
        return default_metrics

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
        # Modified to handle Docker environment
        if IN_DOCKER:
            # Use pgrep to check if Squid is running
            result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
            status_output = result.stdout.strip()
            
            if status_output == 'running':
                # Get additional details about the running squid process
                details_cmd = "ps -ef | grep -v grep | grep squid"
                details_result = subprocess.run(details_cmd, shell=True, capture_output=True, text=True)
                
                return jsonify({
                    'status': 'running',
                    'details': details_result.stdout or 'Squid proxy is running'
                })
            else:
                return jsonify({
                    'status': 'stopped',
                    'details': 'Squid proxy is not running'
                })
        else:
            # Original systemd implementation
            result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return jsonify({
                    'status': 'running',
                    'details': result.stdout
                })
            else:
                return jsonify({
                    'status': 'stopped',
                    'details': result.stderr or 'Squid service is not running'
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
        print(f"Executing command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"Command output: {result.stdout}, Error: {result.stderr}, Return code: {result.returncode}")
        
        # In Docker with direct commands, squid might return non-zero even on success
        # For example, shutdown when squid isn't running returns non-zero
        # So we need to check status based on action rather than just returncode
        
        if IN_DOCKER:
            # For Docker, verify the result by checking the actual status
            if action == 'stop':
                # Check that Squid is actually stopped
                status_result = subprocess.run("pgrep -x squid > /dev/null", shell=True)
                success = status_result.returncode != 0  # Return code 0 means process found, which isn't what we want for 'stop'
            else:
                # For start/restart/reload, check that Squid is running
                status_result = subprocess.run("pgrep -x squid > /dev/null", shell=True)
                success = status_result.returncode == 0  # Return code 0 means process found
                
            if success:
                return jsonify({
                    'status': 'success',
                    'message': f'Squid {action_desc} successfully'
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to {action} Squid'
                })
        else:
            # Original logic for non-Docker
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
    try:
        metrics = get_squid_metrics()
        return jsonify({
            'count': metrics['clients'],
            'status': metrics['status']
        })
    except Exception as e:
        return jsonify({
            'count': 0,
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/stats/realtime')
def get_realtime_stats():
    try:
        # Force refresh if requested
        force_refresh = request.args.get('refresh', 'false') == 'true'
        metrics = get_squid_metrics(force_refresh)
        
        return jsonify({
            'connections': metrics['connections'],
            'clients': metrics['clients'],
            'maxConnections': metrics['maxConnections'],
            'maxClients': metrics['maxClients'],
            'cpu': metrics['cpu'],
            'memory': metrics['memory'],
            'memoryMB': metrics['memoryMB'],
            'diskUsageMB': metrics['diskUsageMB'],
            'pid': metrics['pid'],
            'uptime': metrics['uptime'],
            'status': metrics['status'],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'connections': 0,
            'clients': 0,
            'maxConnections': 1000,
            'maxClients': 100,
            'cpu': 0,
            'memory': 0,
            'memoryMB': 0,
            'diskUsageMB': 0,
            'pid': 0,
            'timestamp': datetime.now().isoformat()
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
    # Fetch actual logs from Squid log directory
    lines_count = request.args.get('lines', default=100, type=int)
    log_files = {
        'access': os.path.join(SQUID_LOG_DIR, 'access.log'),
        'cache': os.path.join(SQUID_LOG_DIR, 'cache.log'),
        'store': os.path.join(SQUID_LOG_DIR, 'store.log'),
        'system': os.path.join(SQUID_LOG_DIR, 'store.log')  # reuse store log for system if needed
    }
    path = log_files.get(log_type)
    content = []
    total_lines = 0
    error_count = 0
    size = 0
    try:
        if path and os.path.exists(path):
            with open(path, 'r') as f:
                all_lines = f.read().splitlines()
            total_lines = len(all_lines)
            # Get last n lines
            content = all_lines[-lines_count:]
            # Estimate file size
            size = os.path.getsize(path)
            # Count 'error' occurrences
            error_count = sum(1 for line in content if 'error' in line.lower())
        else:
            content = []
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    return jsonify({
        'content': content,
        'totalLines': total_lines,
        'errorCount': error_count,
        'size': size
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

@app.route('/api/logs/<log_type>/download')
def download_log_file(log_type):
    """Download the full log file for the given type"""
    log_files = {
        'access': os.path.join(SQUID_LOG_DIR, 'access.log'),
        'cache': os.path.join(SQUID_LOG_DIR, 'cache.log'),
        'store': os.path.join(SQUID_LOG_DIR, 'store.log'),
        'system': os.path.join(SQUID_LOG_DIR, 'store.log')
    }
    path = log_files.get(log_type)
    if path and os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=f"{log_type}.log")
    return jsonify({'status':'error','message':'Log file not found'}), 404

@app.route('/api/logs/<log_type>/clear', methods=['POST'])
def clear_log_file(log_type):
    """Clear the contents of the specified log file"""
    log_files = {
        'access': os.path.join(SQUID_LOG_DIR, 'access.log'),
        'cache': os.path.join(SQUID_LOG_DIR, 'cache.log'),
        'store': os.path.join(SQUID_LOG_DIR, 'store.log'),
        'system': os.path.join(SQUID_LOG_DIR, 'store.log')
    }
    path = log_files.get(log_type)
    if path:
        try:
            open(path, 'w').close()
            return jsonify({'status':'success','message':'Log cleared successfully'})
        except Exception as e:
            return jsonify({'status':'error','message': str(e)}), 500
    return jsonify({'status':'error','message':'Log file not found'}), 404

if __name__ == '__main__':
    # Use environment variable for port with fallback to 8001 for local development
    port = int(os.environ.get('FLASK_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)