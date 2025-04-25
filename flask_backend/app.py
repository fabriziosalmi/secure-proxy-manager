from flask import Flask, request, jsonify, render_template, send_from_directory
import subprocess
import os
import socket
import re

app = Flask(__name__, static_folder='../dashboard')

# Configuration with corrected paths and commands
SQUID_CONFIG_PATH = '/etc/squid/squid.conf'
SQUID_STATUS_COMMAND = 'pidof squid || echo "not running"'
SQUID_RESTART_COMMAND = 'pkill -15 squid; sleep 1; /usr/sbin/squid -N -f /etc/squid/squid.conf'
SQUID_STOP_COMMAND = 'pkill -15 squid'
SQUID_START_COMMAND = '/usr/sbin/squid -N -f /etc/squid/squid.conf'
SQUID_RELOAD_COMMAND = '/usr/sbin/squid -k reconfigure'

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