from flask import Flask, request, jsonify, render_template, send_from_directory
import subprocess
import os
import socket
import re
import json

app = Flask(__name__, static_folder='../dashboard')

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

@app.route('/api/control', methods=['POST'])
def control_squid():
    try:
        action = request.get_json().get('action')
        
        if action == 'start':
            result = subprocess.run(SQUID_START_COMMAND, shell=True, capture_output=True, text=True)
        elif action == 'stop':
            result = subprocess.run(SQUID_STOP_COMMAND, shell=True, capture_output=True, text=True)
        elif action == 'restart':
            result = subprocess.run(SQUID_RESTART_COMMAND, shell=True, capture_output=True, text=True)
        elif action == 'reload':
            result = subprocess.run(SQUID_RELOAD_COMMAND, shell=True, capture_output=True, text=True)
        else:
            return jsonify({
                'status': 'error',
                'message': 'Invalid action'
            }), 400
            
        return jsonify({
            'status': 'success',
            'action': action,
            'details': result.stdout
        })
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
        # Add a header comment
        content = "# Updated via Squid Management Dashboard\n"
        for entry in entries:
            content += entry.strip() + "\n"
        
        with open(file_path, 'w') as f:
            f.write(content)
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
                return 'acl blacklist_ips src' in config and 'http_access deny blacklist_ips' in config
            elif feature_name == 'blacklist_domains':
                return 'acl blacklist_domains dstdomain' in config and 'http_access deny blacklist_domains' in config
            elif feature_name == 'direct_ip_access':
                return 'acl direct_ip_access url_regex' in config and 'http_access deny direct_ip_access' in config
            elif feature_name == 'bad_user_agents':
                return 'acl bad_user_agents browser' in config and 'http_access deny bad_user_agents' in config
            elif feature_name == 'malware_extensions':
                return 'acl malware_extensions urlpath_regex' in config and 'http_access deny malware_extensions' in config
            elif feature_name == 'ssl_bump':
                return 'ssl_bump server-first' in config
            
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)