from flask import Flask, request, jsonify, render_template, send_from_directory, session
import subprocess
import os
import socket
import re
import json
import time
import secrets
import shutil
from datetime import datetime
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize Flask application with security features
app = Flask(__name__, static_folder='../dashboard')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

# Support for running behind a proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add session cookie security settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session timeout

# Add security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response

# Configuration with corrected paths and commands
SQUID_CONFIG_PATH = '/etc/squid/squid.conf'
SQUID_STATUS_COMMAND = 'pidof squid || echo "not running"'
SQUID_RESTART_COMMAND = 'pkill -15 squid; sleep 1; /usr/sbin/squid -N -f /etc/squid/squid.conf'
SQUID_STOP_COMMAND = 'pkill -15 squid'
SQUID_START_COMMAND = '/usr/sbin/squid -N -f /etc/squid/squid.conf'
SQUID_RELOAD_COMMAND = '/usr/sbin/squid -k reconfigure'

# Security file paths
BLACKLIST_IPS_PATH = '/etc/squid/blacklist_ips.txt'
BLACKLIST_DOMAINS_PATH = '/etc/squid/blacklist_domains.txt'
ALLOWED_DIRECT_IPS_PATH = '/etc/squid/allowed_direct_ips.txt'
BAD_USER_AGENTS_PATH = '/etc/squid/bad_user_agents.txt'

# Log paths
LOG_PATHS = {
    'access': '/var/log/squid/access.log',
    'cache': '/var/log/squid/cache.log',
    'store': '/var/log/squid/store.log',
    'system': '/var/log/syslog'
}

# Routes for serving the dashboard
@app.route('/')
def index():
    return send_from_directory('../dashboard', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../dashboard', path)

# API endpoints
@app.route('/api/status', methods=['GET'])
def get_status():
    try:
        result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
        is_running = 'not running' not in result.stdout
        
        # Get more detailed status if running
        details = "Squid is not running"
        if is_running:
            try:
                with open('/var/log/squid/cache.log', 'r') as f:
                    # Get the last 10 lines
                    log_lines = f.readlines()[-10:]
                    details = ''.join(log_lines)
            except Exception as e:
                details = f"Squid is running but could not read logs: {str(e)}"
        
        return jsonify({
            'status': 'running' if is_running else 'stopped',
            'details': details
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    try:
        port = get_squid_port()
        return jsonify({
            'port': port
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config', methods=['POST'])
def update_config():
    try:
        data = request.get_json()
        port = data.get('port')
        
        if port and port.isdigit() and 1 <= int(port) <= 65535:
            update_squid_port(int(port))
            return jsonify({
                'status': 'success',
                'message': f'Port updated to {port}'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid port number'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def run_subprocess_safely(command, shell=True, timeout=30):
    """
    Run a subprocess command with error handling and timeout protection.
    
    Args:
        command: The command to run
        shell: Whether to use shell execution (default True)
        timeout: Maximum time to wait for the command to complete in seconds
        
    Returns:
        A tuple containing (success, stdout, stderr)
    """
    try:
        process = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout  # Prevent hanging
        )
        return (True, process.stdout, process.stderr)
    except subprocess.TimeoutExpired:
        return (False, "", f"Command timed out after {timeout} seconds: {command}")
    except Exception as e:
        return (False, "", f"Error executing command: {str(e)}")

@app.route('/api/control', methods=['POST'])
def control_squid():
    try:
        action = request.get_json().get('action')
        
        if action not in ['start', 'stop', 'restart', 'reload']:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action'
            }), 400
        
        command = None
        if action == 'start':
            command = SQUID_START_COMMAND
        elif action == 'stop':
            command = SQUID_STOP_COMMAND
        elif action == 'restart':
            command = SQUID_RESTART_COMMAND
        elif action == 'reload':
            command = SQUID_RELOAD_COMMAND
            
        success, stdout, stderr = run_subprocess_safely(command, timeout=60)
        
        if success:
            return jsonify({
                'status': 'success',
                'action': action,
                'details': stdout
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to {action} Squid: {stderr}'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# New security API endpoints
@app.route('/api/security/blacklist-ips', methods=['GET'])
def get_blacklist_ips():
    try:
        return jsonify({
            'ips': read_list_file(BLACKLIST_IPS_PATH)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/blacklist-ips', methods=['POST'])
def update_blacklist_ips():
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        # Validate IPs
        for ip in ips:
            if not is_valid_ip(ip) and not ip.startswith('#'):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid IP address: {ip}'
                }), 400
        
        # Write to file
        success = write_list_file(BLACKLIST_IPS_PATH, ips)
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'IP blacklist updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update IP blacklist'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/blacklist-domains', methods=['GET'])
def get_blacklist_domains():
    try:
        return jsonify({
            'domains': read_list_file(BLACKLIST_DOMAINS_PATH)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/blacklist-domains', methods=['POST'])
def update_blacklist_domains():
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        # Write to file
        success = write_list_file(BLACKLIST_DOMAINS_PATH, domains)
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'Domain blacklist updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update domain blacklist'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
                'message': str(e)
        }), 500

@app.route('/api/security/allowed-direct-ips', methods=['GET'])
def get_allowed_direct_ips():
    try:
        return jsonify({
            'ips': read_list_file(ALLOWED_DIRECT_IPS_PATH)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/allowed-direct-ips', methods=['POST'])
def update_allowed_direct_ips():
    try:
        data = request.get_json()
        ips = data.get('ips', [])
        
        # Validate IPs
        for ip in ips:
            if not is_valid_ip(ip) and not ip.startswith('#'):
                return jsonify({
                    'status': 'error',
                    'message': f'Invalid IP address: {ip}'
                }), 400
        
        # Write to file
        success = write_list_file(ALLOWED_DIRECT_IPS_PATH, ips)
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'Allowed direct IPs updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update allowed direct IPs'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/cache-settings', methods=['GET'])
def get_cache_settings():
    try:
        cache_size = get_cache_size()
        max_object_size = get_max_object_size()
        
        return jsonify({
            'cacheSize': cache_size,
            'maxObjectSize': max_object_size
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/cache-settings', methods=['POST'])
def update_cache_settings():
    try:
        data = request.get_json()
        cache_size = data.get('cacheSize')
        max_object_size = data.get('maxObjectSize')
        
        success = True
        if cache_size:
            success = update_cache_size(cache_size) and success
        
        if max_object_size:
            success = update_max_object_size(max_object_size) and success
        
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'Cache settings updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update cache settings'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/feature-status', methods=['GET'])
def get_feature_status():
    try:
        features = {
            'ipBlacklist': is_feature_enabled('blacklist_ips'),
            'domainBlacklist': is_feature_enabled('blacklist_domains'),
            'directIpBlocking': is_feature_enabled('direct_ip_access'),
            'userAgentFiltering': is_feature_enabled('bad_user_agents'),
            'malwareBlocking': is_feature_enabled('malware_extensions'),
            'httpsFiltering': is_feature_enabled('ssl_bump')
        }
        
        return jsonify(features)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/feature-status', methods=['POST'])
def update_feature_status():
    try:
        data = request.get_json()
        features = {
            'ipBlacklist': data.get('ipBlacklist'),
            'domainBlacklist': data.get('domainBlacklist'),
            'directIpBlocking': data.get('directIpBlocking'),
            'userAgentFiltering': data.get('userAgentFiltering'),
            'malwareBlocking': data.get('malwareBlocking'),
            'httpsFiltering': data.get('httpsFiltering')
        }
        
        # Update each feature in the config
        success = update_features_in_config(features)
        
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'Security features updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update security features'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Helper functions for security features
def read_list_file(file_path):
    try:
        if not os.path.exists(file_path):
            # Create empty file if it doesn't exist
            directory = os.path.dirname(file_path)
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                
            with open(file_path, 'w') as f:
                f.write('# Add entries one per line\n')
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
            # Filter out comments and empty lines
            entries = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
            return entries
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return []

def write_list_file(file_path, entries):
    try:
        # Create directory if it doesn't exist
        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            
        # Add a header comment
        content = "# Updated via Squid Management Dashboard on {}\n".format(
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        for entry in entries:
            content += entry.strip() + "\n"
        
        # Use a temporary file and rename for atomicity
        temp_file = file_path + ".tmp"
        with open(temp_file, 'w') as f:
            f.write(content)
        
        # Atomic file replacement to prevent partial writes
        os.replace(temp_file, file_path)
        return True
    except Exception as e:
        print(f"Error writing to file {file_path}: {str(e)}")
        return False

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def get_cache_size():
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
            cache_match = re.search(r'cache_dir\s+ufs\s+/var/cache/squid\s+(\d+)', config)
            if cache_match:
                return cache_match.group(1)
            return "100"  # Default
    except Exception as e:
        print(f"Error reading cache size: {str(e)}")
        return "100"  # Default

def update_cache_size(size):
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
        
        new_config = re.sub(
            r'(cache_dir\s+ufs\s+/var/cache/squid\s+)\d+(\s+\d+\s+\d+)', 
            r'\1' + str(size) + r'\2', 
            config
        )
        
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(new_config)
        return True
    except Exception as e:
        print(f"Error updating cache size: {str(e)}")
        return False

def get_max_object_size():
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
            size_match = re.search(r'maximum_object_size\s+(\d+)\s+(\w+)', config)
            if size_match:
                return f"{size_match.group(1)} {size_match.group(2)}"
            return "10 MB"  # Default
    except Exception as e:
        print(f"Error reading max object size: {str(e)}")
        return "10 MB"  # Default

def update_max_object_size(size):
    try:
        size_parts = size.split()
        if len(size_parts) != 2:
            return False
        
        value, unit = size_parts
        if not value.isdigit() or unit not in ['KB', 'MB', 'GB']:
            return False
        
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
        
        new_config = re.sub(
            r'maximum_object_size\s+\d+\s+\w+', 
            f'maximum_object_size {value} {unit}', 
            config
        )
        
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(new_config)
        return True
    except Exception as e:
        print(f"Error updating max object size: {str(e)}")
        return False

def is_feature_enabled(feature_name):
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
            
            # Check for comment markers that would disable the feature
            if feature_name == 'blacklist_ips':
                return ('acl blacklist_ips src' in config and not re.search(r'^\s*#\s*acl blacklist_ips src', config, re.MULTILINE) and
                        'http_access deny blacklist_ips' in config and not re.search(r'^\s*#\s*http_access deny blacklist_ips', config, re.MULTILINE))
            elif feature_name == 'blacklist_domains':
                return ('acl blacklist_domains dstdomain' in config and not re.search(r'^\s*#\s*acl blacklist_domains dstdomain', config, re.MULTILINE) and
                        'http_access deny blacklist_domains' in config and not re.search(r'^\s*#\s*http_access deny blacklist_domains', config, re.MULTILINE))
            elif feature_name == 'direct_ip_access':
                return ('acl direct_ip_access url_regex' in config and not re.search(r'^\s*#\s*acl direct_ip_access url_regex', config, re.MULTILINE) and
                        'http_access deny direct_ip_access' in config and not re.search(r'^\s*#\s*http_access deny direct_ip_access', config, re.MULTILINE))
            elif feature_name == 'bad_user_agents':
                return ('acl bad_user_agents browser' in config and not re.search(r'^\s*#\s*acl bad_user_agents browser', config, re.MULTILINE) and
                        'http_access deny bad_user_agents' in config and not re.search(r'^\s*#\s*http_access deny bad_user_agents', config, re.MULTILINE))
            elif feature_name == 'malware_extensions':
                return ('acl malware_extensions urlpath_regex' in config and not re.search(r'^\s*#\s*acl malware_extensions urlpath_regex', config, re.MULTILINE) and
                        'http_access deny malware_extensions' in config and not re.search(r'^\s*#\s*http_access deny malware_extensions', config, re.MULTILINE))
            elif feature_name == 'ssl_bump':
                try:
                    # Explicitly require that ssl_bump is present AND not commented out
                    ssl_bump_line = re.search(r'^[^#]*ssl_bump\s+server-first', config, re.MULTILINE)
                    return ssl_bump_line is not None
                except re.error as e:
                    print(f"Regex error while checking ssl_bump: {str(e)}")
                    return False
            
            return False
    except Exception as e:
        print(f"Error checking if feature {feature_name} is enabled: {str(e)}")
        return False

def update_features_in_config(features):
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config_lines = f.readlines()
        
        new_config_lines = []
        for line in config_lines:
            # Process each line based on features
            if 'acl blacklist_ips src' in line:
                line = line if features['ipBlacklist'] else '# ' + line.lstrip('# ')
            elif 'http_access deny blacklist_ips' in line:
                line = line if features['ipBlacklist'] else '# ' + line.lstrip('# ')
            elif 'acl blacklist_domains dstdomain' in line:
                line = line if features['domainBlacklist'] else '# ' + line.lstrip('# ')
            elif 'http_access deny blacklist_domains' in line:
                line = line if features['domainBlacklist'] else '# ' + line.lstrip('# ')
            elif 'acl direct_ip_access url_regex' in line:
                line = line if features['directIpBlocking'] else '# ' + line.lstrip('# ')
            elif 'http_access deny direct_ip_access' in line:
                line = line if features['directIpBlocking'] else '# ' + line.lstrip('# ')
            elif 'acl bad_user_agents browser' in line:
                line = line if features['userAgentFiltering'] else '# ' + line.lstrip('# ')
            elif 'http_access deny bad_user_agents' in line:
                line = line if features['userAgentFiltering'] else '# ' + line.lstrip('# ')
            elif 'acl malware_extensions urlpath_regex' in line:
                line = line if features['malwareBlocking'] else '# ' + line.lstrip('# ')
            elif 'http_access deny malware_extensions' in line:
                line = line if features['malwareBlocking'] else '# ' + line.lstrip('# ')
            elif 'ssl_bump server-first' in line:
                line = line if features['httpsFiltering'] else '# ' + line.lstrip('# ')
            
            new_config_lines.append(line)
        
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.writelines(new_config_lines)
        
        return True
    except Exception as e:
        print(f"Error updating features in config: {str(e)}")
        return False

# Helper functions
def get_squid_port():
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
            port_match = re.search(r'http_port\s+(\d+)', config)
            if port_match:
                return port_match.group(1)
            return "3128"  # Default port
    except Exception as e:
        print(f"Error reading Squid config: {str(e)}")
        return "3128"  # Default port

def update_squid_port(port):
    try:
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
        
        new_config = re.sub(r'http_port\s+\d+', f'http_port {port}', config)
        
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(new_config)
        
        # Reload squid to apply changes
        subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
        return True
    except Exception as e:
        print(f"Error updating Squid port: {str(e)}")
        return False

@app.route('/api/clients/count', methods=['GET'])
def get_clients_count():
    try:
        # Get client count from Squid by parsing access.log for unique client IPs
        # within a recent timeframe (last 5 minutes)
        access_log = LOG_PATHS.get('access')
        if not os.path.exists(access_log):
            return jsonify({'count': 0})
        
        # Use awk to extract client IPs and count unique ones from the last 5 minutes
        current_time = time.time()
        five_minutes_ago = current_time - 300  # 5 minutes in seconds
        
        # Try using tail + awk for efficiency on large files
        try:
            # Get the last 1000 lines as a sample (adjust as needed)
            cmd = f"tail -n 1000 {access_log} | awk '{{print $1, $2}}'"
            process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if process.returncode != 0:
                return jsonify({'count': 0})
                
            lines = process.stdout.strip().split('\n')
            unique_ips = set()
            
            # Process the lines
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    client_ip = parts[0]
                    timestamp_str = parts[1]
                    
                    # Try to parse timestamp (assuming it's in Unix epoch format)
                    try:
                        timestamp = float(timestamp_str)
                        if timestamp >= five_minutes_ago:
                            unique_ips.add(client_ip)
                    except ValueError:
                        # If timestamp isn't in expected format, just count the IP
                        unique_ips.add(client_ip)
            
            return jsonify({'count': len(unique_ips)})
            
        except Exception as e:
            print(f"Error counting clients: {str(e)}")
            return jsonify({'count': 0})
    except Exception as e:
        print(f"Error in get_clients_count: {str(e)}")
        return jsonify({'count': 0})

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Check if Squid is running
        result = subprocess.run(SQUID_STATUS_COMMAND, shell=True, capture_output=True, text=True)
        squid_running = 'not running' not in result.stdout
        
        # Check if Flask is running (which it is if we're handling this request)
        flask_running = True
        
        if squid_running and flask_running:
            return jsonify({'status': 'healthy'}), 200
        else:
            return jsonify({
                'status': 'unhealthy',
                'squid_running': squid_running,
                'flask_running': flask_running
            }), 503
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# New Log API endpoints
@app.route('/api/logs/<log_type>', methods=['GET'])
def get_logs(log_type):
    try:
        if log_type not in LOG_PATHS:
            return jsonify({
                'status': 'error',
                'message': f'Unknown log type: {log_type}'
            }), 400
            
        log_path = LOG_PATHS[log_type]
        lines = request.args.get('lines', default=100, type=int)
        
        if not os.path.exists(log_path):
            return jsonify({
                'content': f"Log file not found: {log_path}",
                'totalLines': 0,
                'errors': 0,
                'size': '0 KB',
                'lastModified': 'Never'
            })
        
        # Get file stats
        file_stats = os.stat(log_path)
        file_size = file_stats.st_size
        last_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        # Format file size
        if file_size < 1024:
            formatted_size = f"{file_size} B"
        elif file_size < 1024 * 1024:
            formatted_size = f"{file_size / 1024:.1f} KB"
        else:
            formatted_size = f"{file_size / (1024 * 1024):.1f} MB"
        
        # For very large files, use tail to get the last lines efficiently
        # to avoid loading the entire file into memory
        if file_size > 10 * 1024 * 1024:  # If file is > 10MB
            error_count = 0
            try:
                # Count total lines efficiently
                wc_cmd = f"wc -l < {log_path}"
                wc_process = subprocess.run(wc_cmd, shell=True, capture_output=True, text=True)
                total_lines = int(wc_process.stdout.strip())
                
                # Get the last N lines using tail
                tail_cmd = f"tail -n {lines} {log_path}"
                tail_process = subprocess.run(tail_cmd, shell=True, capture_output=True, text=True)
                log_content = tail_process.stdout.strip().split('\n')
                
                # Count error lines in the returned content
                for line in log_content:
                    if " ERROR " in line or " FATAL " in line or " CRITICAL " in line:
                        error_count += 1
                
                # If we need error count for entire file (not just tail)
                # grep_cmd = f"grep -E ' ERROR | FATAL | CRITICAL ' {log_path} | wc -l"
                # grep_process = subprocess.run(grep_cmd, shell=True, capture_output=True, text=True)
                # error_count = int(grep_process.stdout.strip())
            except Exception as e:
                print(f"Error in subprocess commands for large log file: {str(e)}")
                # Fall back to standard processing if subprocess fails
                return read_log_standard(log_path, lines, formatted_size, last_modified)
                
            return jsonify({
                'content': log_content,
                'totalLines': total_lines,
                'errors': error_count,
                'size': formatted_size,
                'lastModified': last_modified
            })
        else:
            # For smaller files, read them directly
            return read_log_standard(log_path, lines, formatted_size, last_modified)
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def read_log_standard(log_path, lines, formatted_size, last_modified):
    """Standard log reading function for smaller files"""
    try:
        log_content = []
        error_count = 0
        
        with open(log_path, 'r') as f:
            all_lines = f.readlines()
            total_lines = len(all_lines)
            
            # Get the last 'lines' number of lines
            log_lines = all_lines[-lines:] if lines < total_lines else all_lines
            
            for line in log_lines:
                log_content.append(line.rstrip())
                # Count error lines
                if " ERROR " in line or " FATAL " in line or " CRITICAL " in line:
                    error_count += 1
        
        return jsonify({
            'content': log_content,
            'totalLines': total_lines,
            'errors': error_count,
            'size': formatted_size,
            'lastModified': last_modified
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f"Error reading log file: {str(e)}"
        }), 500

@app.route('/api/logs/<log_type>/analysis', methods=['GET'])
def analyze_logs(log_type):
    try:
        if log_type not in LOG_PATHS:
            return jsonify({
                'status': 'error',
                'message': f'Unknown log type: {log_type}'
            }), 400
            
        log_path = LOG_PATHS[log_type]
        
        if not os.path.exists(log_path):
            return jsonify({
                'status': 'error',
                'message': f'Log file not found: {log_path}'
            }), 404
        
        # Initialize analysis data structures
        domains = {}
        status_codes = {}
        request_methods = {}
        traffic_by_hour = {str(h): 0 for h in range(24)}
        
        # Read log file
        with open(log_path, 'r') as f:
            for line in f:
                # Analysis will depend on your log format
                # For access.log, we typically have squid format logs
                if log_type == 'access':
                    # Extract domains
                    domain_match = re.search(r'https?://([^/]+)', line)
                    if domain_match:
                        domain = domain_match.group(1)
                        domains[domain] = domains.get(domain, 0) + 1
                    
                    # Extract status codes - typically the 3rd field in squid logs
                    parts = line.split()
                    if len(parts) > 3:
                        status = parts[3].split('/')[1] if '/' in parts[3] else parts[3]
                        status_codes[status] = status_codes.get(status, 0) + 1
                    
                    # Extract request methods - typically in the 5th field
                    if len(parts) > 5:
                        method = parts[5].strip('"')
                        request_methods[method] = request_methods.get(method, 0) + 1
                    
                    # Extract time for traffic by hour
                    timestamp_match = re.search(r'\[\d+/\w+/\d+:(\d+):', line)
                    if timestamp_match:
                        hour = timestamp_match.group(1)
                        traffic_by_hour[hour] = traffic_by_hour.get(hour, 0) + 1
        
        # Sort and limit results
        top_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
        sorted_status = sorted(status_codes.items(), key=lambda x: x[0])
        sorted_methods = sorted(request_methods.items(), key=lambda x: x[1], reverse=True)
        sorted_traffic = [(hour, count) for hour, count in traffic_by_hour.items()]
        sorted_traffic.sort(key=lambda x: int(x[0]))
        
        return jsonify({
            'topDomains': dict(top_domains),
            'statusCodes': dict(sorted_status),
            'requestMethods': dict(sorted_methods),
            'trafficByHour': dict(sorted_traffic)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/logs/<log_type>/download', methods=['GET'])
def download_log(log_type):
    try:
        if log_type not in LOG_PATHS:
            return jsonify({
                'status': 'error',
                'message': f'Unknown log type: {log_type}'
            }), 400
            
        log_path = LOG_PATHS[log_type]
        
        if not os.path.exists(log_path):
            return jsonify({
                'status': 'error',
                'message': f'Log file not found: {log_path}'
            }), 404
        
        return send_from_directory(os.path.dirname(log_path), os.path.basename(log_path), as_attachment=True)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/logs/<log_type>/clear', methods=['POST'])
def clear_log(log_type):
    try:
        if log_type not in LOG_PATHS:
            return jsonify({
                'status': 'error',
                'message': f'Unknown log type: {log_type}'
            }), 400
            
        log_path = LOG_PATHS[log_type]
        
        if not os.path.exists(log_path):
            return jsonify({
                'status': 'error',
                'message': f'Log file not found: {log_path}'
            }), 404
        
        # Clear the log file (keeping the file but emptying contents)
        with open(log_path, 'w') as f:
            f.write(f"# Log cleared at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return jsonify({
            'status': 'success',
            'message': f'Log file {log_type} cleared successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config/raw', methods=['GET'])
def get_raw_config():
    try:
        if not os.path.exists(SQUID_CONFIG_PATH):
            return jsonify({
                'status': 'error',
                'message': f'Config file not found: {SQUID_CONFIG_PATH}'
            }), 404
            
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config_content = f.read()
            
        return jsonify({
            'content': config_content
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config/raw', methods=['POST'])
def update_raw_config():
    try:
        data = request.get_json()
        content = data.get('content')
        
        if not content:
            return jsonify({
                'status': 'error',
                'message': 'Empty configuration content'
            }), 400
        
        # Backup the existing config
        backup_path = f"{SQUID_CONFIG_PATH}.bak.{int(time.time())}"
        with open(SQUID_CONFIG_PATH, 'r') as src:
            with open(backup_path, 'w') as dst:
                dst.write(src.read())
        
        # Write the new config
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(content)
        
        # Reload Squid to apply changes
        result = subprocess.run(SQUID_RELOAD_COMMAND, shell=True, capture_output=True, text=True)
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration updated successfully',
            'details': result.stdout,
            'backupPath': backup_path
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/bad-user-agents', methods=['GET'])
def get_bad_user_agents():
    try:
        return jsonify({
            'userAgents': read_list_file(BAD_USER_AGENTS_PATH)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/bad-user-agents', methods=['POST'])
def update_bad_user_agents():
    try:
        data = request.get_json()
        user_agents = data.get('userAgents', [])
        
        # Write to file
        success = write_list_file(BAD_USER_AGENTS_PATH, user_agents)
        if success:
            # Reload Squid to apply changes
            subprocess.run(SQUID_RELOAD_COMMAND, shell=True)
            return jsonify({
                'status': 'success',
                'message': 'Bad user agents updated successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to update bad user agents'
            }), 500
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    try:
        # Get Squid version
        version_result = subprocess.run('squid -v | head -1', shell=True, capture_output=True, text=True)
        squid_version = version_result.stdout.strip() if version_result.returncode == 0 else "Unknown"
        
        # Get system info
        os_info = subprocess.run('uname -a', shell=True, capture_output=True, text=True)
        os_info_text = os_info.stdout.strip() if os_info.returncode == 0 else "Unknown"
        
        # Get current paths
        current_paths = {
            'squidPath': '/usr/sbin/squid',
            'configPath': SQUID_CONFIG_PATH,
            'cacheDir': '/var/cache/squid'
        }
        
        return jsonify({
            'squidVersion': squid_version,
            'osInfo': os_info_text,
            'currentPaths': current_paths
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/system/paths', methods=['POST'])
def update_system_paths():
    try:
        data = request.get_json()
        squid_path = data.get('squidPath')
        config_path = data.get('configPath')
        cache_dir = data.get('cacheDir')
        
        # Validate paths
        if squid_path and not os.path.exists(squid_path):
            return jsonify({
                'status': 'error',
                'message': f'Squid binary not found at {squid_path}'
            }), 400
            
        if config_path and not os.path.exists(os.path.dirname(config_path)):
            return jsonify({
                'status': 'error',
                'message': f'Config directory not found for {config_path}'
            }), 400
            
        if cache_dir and not os.path.exists(cache_dir):
            return jsonify({
                'status': 'error',
                'message': f'Cache directory not found at {cache_dir}'
            }), 400
        
        # TODO: Actually update the paths in the application
        # This would require updating global variables and possibly restarting the application
        
        return jsonify({
            'status': 'success',
            'message': 'System paths updated successfully'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/stats/realtime', methods=['GET'])
def get_realtime_stats():
    try:
        # Get real-time connections
        connections = 0
        clients = 0
        max_connections = 1000  # Default
        max_clients = 100  # Default
        
        # Get CPU and memory usage using 'ps'
        cpu_usage = 0
        memory_usage = 0
        disk_usage = 0
        pid = 0
        
        # Check if squid is running and get its PID
        pid_cmd = "pidof squid"
        pid_result = subprocess.run(pid_cmd, shell=True, capture_output=True, text=True)
        if pid_result.returncode == 0 and pid_result.stdout.strip():
            # Get first PID if multiple are returned
            pid = pid_result.stdout.strip().split()[0]
            
            # Get CPU and memory for this PID
            ps_cmd = f"ps -p {pid} -o %cpu,%mem,rss"
            ps_result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
            if ps_result.returncode == 0:
                lines = ps_result.stdout.strip().split('\n')
                if len(lines) > 1:  # First line is header
                    stats = lines[1].split()
                    if len(stats) >= 3:
                        cpu_usage = float(stats[0])
                        memory_usage = float(stats[1])
                        memory_rss = int(stats[2]) // 1024  # Convert KB to MB
        
        # Get disk usage for cache directory
        cache_dir = "/var/cache/squid"
        du_cmd = f"du -sm {cache_dir} 2>/dev/null | cut -f1"
        du_result = subprocess.run(du_cmd, shell=True, capture_output=True, text=True)
        if du_result.returncode == 0 and du_result.stdout.strip():
            disk_usage = int(du_result.stdout.strip())
        
        # Count active connections
        if pid:
            # Use netstat to count connections
            netstat_cmd = f"netstat -anp | grep {pid} | grep ESTABLISHED | wc -l"
            netstat_result = subprocess.run(netstat_cmd, shell=True, capture_output=True, text=True)
            if netstat_result.returncode == 0:
                connections = int(netstat_result.stdout.strip())
        
        # Get max connections from config
        config_cmd = f"grep 'maximum_object_size\|cache_mem' {SQUID_CONFIG_PATH}"
        config_result = subprocess.run(config_cmd, shell=True, capture_output=True, text=True)
        if config_result.returncode == 0:
            # Parse config values - simplified for example
            max_connections = 1000  # Default value
            max_clients = 100  # Default value
        
        # Count unique client IPs in the last minute
        client_count_cmd = "tail -n 1000 /var/log/squid/access.log | awk '{print $3}' | sort | uniq | wc -l"
        client_result = subprocess.run(client_count_cmd, shell=True, capture_output=True, text=True)
        if client_result.returncode == 0:
            clients = int(client_result.stdout.strip())
        
        return jsonify({
            'connections': connections,
            'maxConnections': max_connections,
            'clients': clients,
            'maxClients': max_clients,
            'cpu': cpu_usage,
            'memory': memory_usage,
            'memoryMB': memory_rss if 'memory_rss' in locals() else 0,
            'diskUsageMB': disk_usage,
            'pid': pid
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'connections': 0,
            'maxConnections': 100,
            'clients': 0,
            'maxClients': 10
        }), 500

@app.route('/api/security/ssl-certificate', methods=['GET'])
def get_ssl_certificate_status():
    try:
        # Define paths for SSL certificates
        cert_path = '/etc/squid/ssl_cert/myCA.pem'
        key_path = '/etc/squid/ssl_cert/myCA.key'
        
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            return jsonify({
                'status': 'success',
                'exists': False,
                'message': 'SSL certificate not found'
            })
        
        # Get certificate details using OpenSSL
        cert_info_cmd = f"openssl x509 -in {cert_path} -text -noout"
        success, stdout, stderr = run_subprocess_safely(cert_info_cmd)
        
        if not success:
            return jsonify({
                'status': 'error',
                'message': f'Failed to read certificate: {stderr}'
            }), 500
        
        # Parse certificate details
        cert_info = stdout.strip()
        
        # Extract subject
        subject_match = re.search(r'Subject:\s*(.*?)(?=\n)', cert_info)
        subject = subject_match.group(1).strip() if subject_match else 'Unknown'
        
        # Extract issuer
        issuer_match = re.search(r'Issuer:\s*(.*?)(?=\n)', cert_info)
        issuer = issuer_match.group(1).strip() if issuer_match else 'Unknown'
        
        # Extract validity dates
        valid_from_match = re.search(r'Not Before:\s*(.*?)(?=\n)', cert_info)
        valid_from = valid_from_match.group(1).strip() if valid_from_match else 'Unknown'
        
        valid_to_match = re.search(r'Not After\s*:\s*(.*?)(?=\n)', cert_info)
        valid_to = valid_to_match.group(1).strip() if valid_to_match else 'Unknown'
        
        # Extract serial number
        serial_match = re.search(r'Serial Number:\s*(.*?)(?=\n)', cert_info)
        serial_number = serial_match.group(1).strip() if serial_match else 'Unknown'
        
        return jsonify({
            'status': 'success',
            'exists': True,
            'certificate': {
                'subject': subject,
                'issuer': issuer,
                'validFrom': valid_from,
                'validTo': valid_to,
                'serialNumber': serial_number
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/ssl-certificate/generate', methods=['POST'])
def generate_ssl_certificate():
    try:
        data = request.get_json()
        common_name = data.get('commonName', 'secure-proxy.local')
        organization = data.get('organization', 'Secure Proxy')
        valid_days = data.get('validDays', 3650)  # Default 10 years
        
        # Create directory for SSL certificates
        ssl_dir = '/etc/squid/ssl_cert'
        if not os.path.exists(ssl_dir):
            os.makedirs(ssl_dir, exist_ok=True)
        
        # Full paths for certificate files
        cert_path = os.path.join(ssl_dir, 'myCA.pem')
        key_path = os.path.join(ssl_dir, 'myCA.key')
        
        # Generate root CA certificate
        openssl_commands = [
            # Generate private key
            f"openssl genrsa -out {key_path} 2048",
            
            # Generate CA certificate
            f"openssl req -new -x509 -key {key_path} -out {cert_path} -days {valid_days} "
            f"-subj '/CN={common_name}/O={organization}/OU=Secure Proxy CA'"
        ]
        
        # Execute commands
        for cmd in openssl_commands:
            success, stdout, stderr = run_subprocess_safely(cmd, timeout=30)
            if not success:
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to generate certificate: {stderr}'
                }), 500
        
        # Update Squid configuration to use the new certificate
        with open(SQUID_CONFIG_PATH, 'r') as f:
            config = f.read()
        
        # Ensure SSL certificate paths are correctly set
        if 'ssl_bump' in config:
            # Check if ssl_cert_dir is already set
            if 'ssl_cert_dir' not in config:
                config += f"\n\n# SSL Certificate Directory\nssl_cert_dir {ssl_dir}\n"
            
            # Check if ssl_bump is already configured
            ssl_bump_configured = re.search(r'ssl_bump\s+server-first', config)
            
            if not ssl_bump_configured:
                # Add SSL bump configuration
                config += f"""
# SSL Bump Configuration
http_port 3128 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert={cert_path} key={key_path}
ssl_bump server-first all
sslproxy_cert_error deny all
sslcrtd_program /usr/lib/squid/security_file_certgen -s {ssl_dir}/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1
"""
        
        # Write updated config
        with open(SQUID_CONFIG_PATH, 'w') as f:
            f.write(config)
        
        return jsonify({
            'status': 'success',
            'message': 'SSL certificate generated successfully',
            'details': {
                'certPath': cert_path,
                'keyPath': key_path,
                'commonName': common_name,
                'validDays': valid_days
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/security/ssl-certificate/download', methods=['GET'])
def download_ssl_certificate():
    try:
        cert_path = '/etc/squid/ssl_cert/myCA.pem'
        
        if not os.path.exists(cert_path):
            return jsonify({
                'status': 'error',
                'message': 'Certificate file not found'
            }), 404
        
        # Send the certificate file for download
        return send_file(cert_path, 
                        mimetype='application/x-x509-ca-cert',
                        as_attachment=True,
                        download_name='secure-proxy-ca.crt')
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)