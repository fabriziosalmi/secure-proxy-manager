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
    # In Docker, use supervisorctl for control but more robust status checks
    SQUID_RELOAD_COMMAND = "supervisorctl signal HUP squid"
    SQUID_RESTART_COMMAND = "supervisorctl restart squid"
    SQUID_START_COMMAND = "supervisorctl start squid"
    SQUID_STOP_COMMAND = "supervisorctl stop squid"
    # More reliable status check that doesn't require "squid" in the process name
    SQUID_STATUS_COMMAND = "netstat -tulpn | grep -E ':(3128|8080)' > /dev/null && echo 'running' || echo 'stopped'"
else:
    # Traditional systemctl commands for non-Docker environments
    SQUID_RELOAD_COMMAND = "sudo systemctl reload squid"
    SQUID_RESTART_COMMAND = "sudo systemctl restart squid"
    SQUID_START_COMMAND = "sudo systemctl start squid"
    SQUID_STOP_COMMAND = "sudo systemctl stop squid"
    SQUID_STATUS_COMMAND = "sudo systemctl status squid"

# Define log directory for Squid logs - Ubuntu uses a different path
SQUID_LOG_DIR = os.environ.get('SQUID_LOG_DIR', '/var/log/squid')
# Ubuntu uses /var/spool/squid for cache, Alpine might use a different path
SQUID_CACHE_DIR = os.environ.get('SQUID_CACHE_DIR', '/var/spool/squid')

# Set the correct user for squid based on OS
# Ubuntu uses 'proxy' user, Alpine uses 'squid'
SQUID_USER = os.environ.get('SQUID_USER', 'proxy')

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
print(f"Squid user: {SQUID_USER}")
print(f"Squid cache directory: {SQUID_CACHE_DIR}")

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
    current_time = time.time()

    if not force_refresh and metrics_cache['last_update'] > 0:
        if current_time - metrics_cache['last_update'] < metrics_cache['cache_duration']:
            return metrics_cache['data']

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
        status_result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
        if status_result.returncode != 0:
            default_metrics['status'] = 'stopped'
            default_metrics['error'] = 'Squid is not running'
            metrics_cache['data'] = default_metrics
            metrics_cache['last_update'] = current_time
            return default_metrics

        cmd = f"{SQUID_CLIENT_BIN} -h {SQUID_HOST} -p {SQUID_PORT} mgr:info"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)

        if result.returncode != 0:
            metrics_cache['data'] = default_metrics
            metrics_cache['last_update'] = current_time
            return default_metrics

        output = result.stdout

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

        client_match = re.search(r'Number of HTTP clients:\s+(\d+)', output)
        if client_match:
            metrics['clients'] = int(client_match.group(1))

        conn_match = re.search(r'Number of active connections:\s+(\d+)', output)
        if conn_match:
            metrics['connections'] = int(conn_match.group(1))

        mem_match = re.search(r'Total memory accounted:\s+(\d+)', output)
        if mem_match:
            mem_kb = int(mem_match.group(1))
            metrics['memoryMB'] = mem_kb // 1024

        disk_match = re.search(r'Storage Swap size:\s+(\d+)\s+KB', output)
        if disk_match:
            metrics['diskUsageMB'] = int(disk_match.group(1)) // 1024

        pid_match = re.search(r'Process id:\s+(\d+)', output)
        if pid_match:
            metrics['pid'] = int(pid_match.group(1))

        uptime_match = re.search(r'Service Up Time:\s+(.+)', output)
        if uptime_match:
            metrics['uptime'] = uptime_match.group(1).strip()

        cpu_cmd = f"ps -p {metrics['pid']} -o %cpu | tail -1" if metrics['pid'] > 0 else "echo 0"
        cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
        if cpu_result.returncode == 0:
            metrics['cpu'] = float(cpu_result.stdout.strip())

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
            # First check using netstat (port check)
            port_check = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
            status_output = port_check.stdout.strip()
            
            # If port check says running, trust it
            if status_output == 'running':
                # Get additional details about the running squid process
                details_cmd = "supervisorctl status squid && netstat -tulpn | grep -E ':(3128|8080)'"
                details_result = subprocess.run(details_cmd, shell=True, capture_output=True, text=True)
                
                return jsonify({
                    'status': 'running',
                    'details': details_result.stdout or 'Squid proxy is running'
                })
            
            # Secondary check using squidclient as a more reliable indicator
            client_check = subprocess.run(f"{SQUID_CLIENT_BIN} -h {SQUID_HOST} -p {SQUID_PORT} -t 1 mgr:info > /dev/null 2>&1", shell=True)
            if client_check.returncode == 0:
                # Squid is responding to queries
                details_cmd = "supervisorctl status squid"
                details_result = subprocess.run(details_cmd, shell=True, capture_output=True, text=True)
                
                return jsonify({
                    'status': 'running',
                    'details': details_result.stdout or 'Squid proxy is running and responding to queries'
                })
                
            # Final check using supervisor (most reliable for process state)
            supervisor_check = subprocess.run("supervisorctl status squid | grep RUNNING", shell=True, capture_output=True, text=True)
            if supervisor_check.returncode == 0:
                # Supervisor says it's running
                return jsonify({
                    'status': 'running',
                    'details': 'Squid proxy is running according to supervisor'
                })
                
            # All checks failed, safe to assume it's not running
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
        # So we need to check status based on action rather than just returncode
        
        if IN_DOCKER:
            # For Docker, verify the result by checking supervisor status first
            supervisor_check = subprocess.run("supervisorctl status squid | grep RUNNING", shell=True, capture_output=True, text=True)
            supervisor_success = supervisor_check.returncode == 0
            
            # Different verification approaches based on action
            if action == 'stop':
                # For stop, we want the process to be gone and port to be free
                port_check = subprocess.run(f"netstat -tulpn | grep -E ':{SQUID_PORT}' > /dev/null", shell=True)
                success = port_check.returncode != 0  # Port should NOT be in use
                
                # If success was determined, return immediately
                if success:
                    return jsonify({
                        'status': 'success',
                        'message': f'Squid {action_desc} successfully'
                    })
            else:
                # For start/restart/reload, first check supervisor
                if supervisor_success:
                    # Supervisor says it's running, verify with port check
                    port_check = subprocess.run(f"netstat -tulpn | grep -E ':{SQUID_PORT}' > /dev/null", shell=True)
                    port_success = port_check.returncode == 0  # Port SHOULD be in use
                    
                    # If supervisor and port both indicate success, return immediately
                    if port_success:
                        return jsonify({
                            'status': 'success',
                            'message': f'Squid {action_desc} successfully'
                        })
                    
                    # If only supervisor shows success, give it a bit more time to bind to port
                    for _ in range(5):
                        time.sleep(0.5)
                        port_check = subprocess.run(f"netstat -tulpn | grep -E ':{SQUID_PORT}' > /dev/null", shell=True)
                        if port_check.returncode == 0:
                            return jsonify({
                                'status': 'success',
                                'message': f'Squid {action_desc} successfully'
                            })
                
                # If we get here, we need to do the full checking routine
                success = False
                
                # Try up to 15 times with shorter intervals
                for i in range(15):
                    # Check if squid is in RUNNING state according to supervisor
                    supervisor_check = subprocess.run("supervisorctl status squid | grep RUNNING", shell=True, capture_output=True, text=True)
                    if supervisor_check.returncode == 0:
                        # Supervisor says it's running, check if port is open
                        port_check = subprocess.run(f"netstat -tulpn | grep -E ':{SQUID_PORT}' > /dev/null", shell=True)
                        if port_check.returncode == 0:
                            # Finally, try squidclient to verify it's actually responding
                            client_check = subprocess.run(f"{SQUID_CLIENT_BIN} -h {SQUID_HOST} -p {SQUID_PORT} -t 1 mgr:info > /dev/null 2>&1", shell=True)
                            if client_check.returncode == 0:
                                success = True
                                break
                    
                    # Short sleep between checks
                    time.sleep(0.3)
            
            # If still no success, get detailed diagnostics
            if not success and action != 'stop':
                # Get supervisor status
                supervisor_status = subprocess.run("supervisorctl status squid", shell=True, capture_output=True, text=True).stdout
                
                # Get netstat info
                netstat_info = subprocess.run(f"netstat -tulpn | grep -E ':{SQUID_PORT}'", shell=True, capture_output=True, text=True).stdout
                
                # Get recent log entries
                try:
                    log_cmd = "tail -n 20 /var/log/squid/cache.log"
                    log_result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True, timeout=2)
                    error_details = log_result.stdout.strip() if log_result.returncode == 0 else "No log details available"
                except Exception:
                    error_details = "Failed to retrieve log details"
                
                # Compile diagnostic info
                diagnostic = f"""
Supervisor status: {supervisor_status}
Port {SQUID_PORT} status: {"In use" if netstat_info else "Not in use"}
Recent logs: {error_details}
"""
                
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to {action} Squid. Diagnostics: {diagnostic}'
                })
            
            # If we got here without returning, success is determined by the last check
            if success or action == 'stop':
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

@app.route('/api/stats/realtime', methods=['GET'])
def get_realtime_stats():
    """
    Endpoint for real-time statistics of the Squid Proxy.
    Returns information about connections, clients, CPU usage, memory usage, etc.
    Can be refreshed by passing ?refresh=true in the query string.
    """
    try:
        refresh = request.args.get('refresh', 'false').lower() == 'true'
        print(f"Real-time stats requested with refresh={refresh}")

        # Debugging output about the execution environment
        print(f"SQUID_CACHE_DIR: {SQUID_CACHE_DIR}")
        print(f"SQUID_PORT: {SQUID_PORT}")
        
        # Get process information using ps command
        if IN_DOCKER:
            # In Docker, we use supervisorctl to check if squid is running
            supervisor_check = subprocess.run("supervisorctl status squid | grep RUNNING", 
                                            shell=True, capture_output=True, text=True)
            is_running = supervisor_check.returncode == 0
            print(f"Squid running status according to supervisor: {is_running}")
            
            if is_running:
                # Get PID using ps command inside Docker
                ps_cmd = "ps -ef | grep squid | grep -v grep | head -1 | awk '{print $2}'"
                ps_result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
                pid = ps_result.stdout.strip() if ps_result.returncode == 0 else 0
                print(f"Found Squid PID: {pid}")
                
                # Get CPU and memory usage
                if pid and pid != '0':
                    # Get CPU usage
                    cpu_cmd = f"ps -p {pid} -o %cpu | tail -1"
                    cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
                    cpu = cpu_result.stdout.strip() if cpu_result.returncode == 0 else '0'
                    
                    # Get memory usage
                    mem_cmd = f"ps -p {pid} -o %mem | tail -1"
                    mem_result = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True)
                    memory = mem_result.stdout.strip() if mem_result.returncode == 0 else '0'
                    
                    # Get memory in MB
                    mem_mb_cmd = f"ps -p {pid} -o rss | tail -1"
                    mem_mb_result = subprocess.run(mem_mb_cmd, shell=True, capture_output=True, text=True)
                    memory_mb = int(mem_mb_result.stdout.strip()) // 1024 if mem_mb_result.returncode == 0 and mem_mb_result.stdout.strip().isdigit() else 0
                    
                    # Get disk usage for cache - use the environment variable for cache directory
                    du_cmd = f"du -sm {SQUID_CACHE_DIR} 2>/dev/null | cut -f1"
                    print(f"Executing disk usage command: {du_cmd}")
                    du_result = subprocess.run(du_cmd, shell=True, capture_output=True, text=True)
                    disk_usage_mb = du_result.stdout.strip() if du_result.returncode == 0 and du_result.stdout.strip().isdigit() else '0'
                    print(f"Disk usage result: {du_result.stdout}, returncode: {du_result.returncode}")
                    
                    # Get active connections and clients using netstat
                    netstat_cmd = f"netstat -ant | grep ESTABLISHED | grep :{SQUID_PORT} | wc -l"
                    netstat_result = subprocess.run(netstat_cmd, shell=True, capture_output=True, text=True)
                    connections = netstat_result.stdout.strip() if netstat_result.returncode == 0 and netstat_result.stdout.strip().isdigit() else '0'
                    
                    # Get unique client IPs
                    unique_ips_cmd = f"netstat -ant | grep ESTABLISHED | grep :{SQUID_PORT} | awk '{{print $5}}' | cut -d: -f1 | sort -u | wc -l"
                    unique_ips_result = subprocess.run(unique_ips_cmd, shell=True, capture_output=True, text=True)
                    clients = unique_ips_result.stdout.strip() if unique_ips_result.returncode == 0 and unique_ips_result.stdout.strip().isdigit() else '0'
                    
                    # Create response
                    response_data = {
                        'pid': pid,
                        'cpu': cpu,
                        'memory': memory,
                        'memoryMB': memory_mb,
                        'diskUsageMB': disk_usage_mb,
                        'connections': connections,
                        'clients': clients,
                        'maxConnections': 1000,  # Default hard limits
                        'maxClients': 100
                    }
                    print(f"Returning real-time stats: {response_data}")
                    return jsonify(response_data)
                else:
                    print("PID not found or invalid, returning zeros")
                    return jsonify({
                        'pid': 0,
                        'cpu': 0,
                        'memory': 0,
                        'memoryMB': 0,
                        'diskUsageMB': 0,
                        'connections': 0,
                        'clients': 0,
                        'maxConnections': 1000,
                        'maxClients': 100
                    })
            else:
                print("Squid is not running, returning zeros")
                # Return zeros if not running
                return jsonify({
                    'pid': 0,
                    'cpu': 0,
                    'memory': 0,
                    'memoryMB': 0,
                    'diskUsageMB': 0,
                    'connections': 0,
                    'clients': 0,
                    'maxConnections': 1000,
                    'maxClients': 100
                })
        else:
            # Non-Docker environment
            # Check if squid is running
            ps_result = subprocess.run(f"pgrep -x squid", shell=True, capture_output=True, text=True)
            is_running = ps_result.returncode == 0
            
            if is_running:
                pid = ps_result.stdout.strip()
                
                # Get CPU and memory usage
                cpu_cmd = f"ps -p {pid} -o %cpu | tail -1"
                cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
                cpu = cpu_result.stdout.strip() if cpu_result.returncode == 0 else '0'
                
                mem_cmd = f"ps -p {pid} -o %mem | tail -1"
                mem_result = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True)
                memory = mem_result.stdout.strip() if mem_result.returncode == 0 else '0'
                
                mem_mb_cmd = f"ps -p {pid} -o rss | tail -1"
                mem_mb_result = subprocess.run(mem_mb_cmd, shell=True, capture_output=True, text=True)
                memory_mb = int(mem_mb_result.stdout.strip()) // 1024 if mem_mb_result.returncode == 0 and mem_mb_result.stdout.strip().isdigit() else 0
                
                # Get disk usage for cache - use the environment variable for cache directory
                du_cmd = f"du -sm {SQUID_CACHE_DIR} 2>/dev/null | cut -f1"
                du_result = subprocess.run(du_cmd, shell=True, capture_output=True, text=True)
                disk_usage_mb = du_result.stdout.strip() if du_result.returncode == 0 and du_result.stdout.strip().isdigit() else '0'
                
                # Get active connections and clients
                netstat_cmd = f"netstat -ant | grep ESTABLISHED | grep :{SQUID_PORT} | wc -l"
                netstat_result = subprocess.run(netstat_cmd, shell=True, capture_output=True, text=True)
                connections = netstat_result.stdout.strip() if netstat_result.returncode == 0 and netstat_result.stdout.strip().isdigit() else '0'
                
                unique_ips_cmd = f"netstat -ant | grep ESTABLISHED | grep :{SQUID_PORT} | awk '{{print $5}}' | cut -d: -f1 | sort -u | wc -l"
                unique_ips_result = subprocess.run(unique_ips_cmd, shell=True, capture_output=True, text=True)
                clients = unique_ips_result.stdout.strip() if unique_ips_result.returncode == 0 and unique_ips_result.stdout.strip().isdigit() else '0'
                
                return jsonify({
                    'pid': pid,
                    'cpu': cpu,
                    'memory': memory,
                    'memoryMB': memory_mb,
                    'diskUsageMB': disk_usage_mb,
                    'connections': connections,
                    'clients': clients,
                    'maxConnections': 1000,
                    'maxClients': 100
                })
            else:
                # Return zeros if not running
                return jsonify({
                    'pid': 0,
                    'cpu': 0,
                    'memory': 0,
                    'memoryMB': 0,
                    'diskUsageMB': 0,
                    'connections': 0,
                    'clients': 0,
                    'maxConnections': 1000,
                    'maxClients': 100
                })
    except Exception as e:
        print(f"Error fetching real-time stats: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e),
            'pid': 0,
            'cpu': 0,
            'memory': 0,
            'memoryMB': 0,
            'diskUsageMB': 0,
            'connections': 0,
            'clients': 0,
            'maxConnections': 1000,
            'maxClients': 100
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
        if path:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    all_lines = f.read().splitlines()
                total_lines = len(all_lines)
                content = all_lines[-lines_count:]
                size = os.path.getsize(path)
                error_count = sum(1 for line in content if 'error' in line.lower())
            else:
                # File exists mapping but not found on disk
                return jsonify({'status':'error','message':'Log file not found'}), 404
        # If file is found but empty, return placeholder
        if path and total_lines == 0:
            content = ['No log entries available yet.']
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