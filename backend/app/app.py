from flask import Flask, request, jsonify, g, send_file, session
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
import sqlite3
import os
import subprocess
import logging
import json
import secrets
from datetime import datetime, timedelta
import requests
import threading
import time
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import ipaddress
import re
from os import R_OK
from collections import defaultdict
from contextlib import contextmanager
import signal
import sys

# Rate limiting setup
auth_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure CORS with the right settings to allow credentials
CORS(app, supports_credentials=True, resources={
    r"/api/*": {
        "origins": "*",
        "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"],
        "expose_headers": ["X-CSRF-Token"]
    }
})
auth = HTTPBasicAuth()

# Configure logging
log_path = '/logs/backend.log'
# Check if running in local/test environment
if not os.path.exists('/logs'):
    os.makedirs('logs', exist_ok=True)
    log_path = 'logs/backend.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_PATH = '/data/secure_proxy.db'
# Check if running in local/test environment
if not os.path.exists('/data'):
    os.makedirs('data', exist_ok=True)
    DATABASE_PATH = 'data/secure_proxy.db'

# Proxy service configuration
PROXY_HOST = os.environ.get('PROXY_HOST', 'proxy')
PROXY_PORT = os.environ.get('PROXY_PORT', '3128')

# Initialize database
def init_db():
    # Create data directory if it doesn't exist
    data_dir = os.path.dirname(DATABASE_PATH)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Create ip_blacklist table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create domain_blacklist table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create proxy_logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS proxy_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        destination TEXT,
        status TEXT,
        bytes INTEGER
    )
    ''')
    
    # Create settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_name TEXT UNIQUE NOT NULL,
        setting_value TEXT,
        description TEXT
    )
    ''')
    
    # Insert default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        # Use a known password hash for 'admin' to ensure UI can authenticate
        admin_password_hash = generate_password_hash('admin')
        logger.info(f"Creating default admin user with password hash")
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      ('admin', admin_password_hash))
    else:
        # For existing installations, ensure the admin password hash is correct
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", 
                     (generate_password_hash('admin'), 'admin'))
        logger.info("Updated admin password hash to ensure authentication works")
    
    # Insert default settings if not exists
    default_settings = [
        # Basic settings
        ('block_direct_ip', 'true', 'Block direct IP access'),
        ('enable_ip_blacklist', 'true', 'Enable IP blacklist filtering'),
        ('enable_domain_blacklist', 'true', 'Enable domain blacklist filtering'),
        ('log_level', 'info', 'Logging level'),
        
        # Cache settings
        ('cache_size', '1000', 'Cache size in megabytes'),
        ('max_object_size', '50', 'Maximum size of cached objects in megabytes'),
        ('enable_compression', 'false', 'Enable HTTP compression'),
        
        # Advanced filtering settings
        ('enable_content_filtering', 'false', 'Enable content type filtering'),
        ('blocked_file_types', 'exe,bat,cmd,dll,js', 'Blocked file extensions'),
        ('enable_https_filtering', 'false', 'Enable HTTPS filtering'),
        ('enable_time_restrictions', 'false', 'Enable time-based access restrictions'),
        ('time_restriction_start', '09:00', 'Time restrictions start time'),
        ('time_restriction_end', '17:00', 'Time restrictions end time'),
        
        # Authentication settings
        ('enable_proxy_auth', 'false', 'Enable proxy authentication'),
        ('auth_method', 'basic', 'Authentication method'),
        ('enable_user_management', 'false', 'Enable user management'),
        
        # Performance settings
        ('connection_timeout', '30', 'Connection timeout in seconds'),
        ('dns_timeout', '5', 'DNS lookup timeout in seconds'),
        ('max_connections', '100', 'Maximum number of connections'),
        
        # Logging settings
        ('enable_extended_logging', 'false', 'Enable extended logging'),
        ('log_retention', '30', 'Log retention period in days'),
        ('enable_alerts', 'false', 'Enable email alerts')
    ]
    
    for setting in default_settings:
        cursor.execute("SELECT COUNT(*) FROM settings WHERE setting_name = ?", (setting[0],))
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO settings (setting_name, setting_value, description) VALUES (?, ?, ?)", 
                          setting)
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# Get database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Database context manager for safer transactions
@contextmanager
def get_db_connection():
    """Context manager for database connections to ensure proper closing"""
    conn = None
    try:
        conn = get_db()
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        if conn:
            conn.commit()
            # Note: We don't close the connection here as it's managed by Flask's teardown_appcontext

# Authentication
@auth.verify_password
def verify_password(username, password):
    """Verify username and password with rate limiting protection"""
    # Get client IP for rate limiting
    client_ip = request.remote_addr
    
    # Check for rate limiting
    now = datetime.now()
    auth_attempts[client_ip] = [t for t in auth_attempts[client_ip] if (now - t).total_seconds() < RATE_LIMIT_WINDOW]
    
    # If too many attempts, reject this request
    if len(auth_attempts[client_ip]) >= MAX_ATTEMPTS:
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        return None
    
    # Add this attempt to the list
    auth_attempts[client_ip].append(now)
    
    # Check for environment variable authentication first (for UI to backend communication)
    env_username = os.environ.get('BASIC_AUTH_USERNAME', 'admin')
    env_password = os.environ.get('BASIC_AUTH_PASSWORD', 'admin')
    
    if username == env_username and password == env_password:
        logger.info(f"Authenticated using environment variables: {username}")
        auth_attempts[client_ip] = []  # Reset rate limiting on successful login
        return username
    
    # Fall back to database authentication for regular users
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and check_password_hash(user['password'], password):
        # Reset rate limiting on successful login
        auth_attempts[client_ip] = []
        return username
    
    # Log failed attempt but keep the rate limiting record
    if user:
        logger.warning(f"Failed login attempt for user {username} from IP {client_ip}")
    
    return None

# CSRF protection functions
def generate_csrf_token():
    """Generate a CSRF token for the current session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    """Validate that the CSRF token in the request matches the session token"""
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return False
    return True

# Add CSRF token to all API responses
@app.after_request
def add_csrf_token(response):
    if request.endpoint != 'static':
        token = generate_csrf_token()
        response.headers['X-CSRF-Token'] = token
    return response

# CSRF protection decorator for state-changing endpoints
def csrf_protected(func):
    """Decorator to protect routes from CSRF attacks"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if request.method not in ['GET', 'HEAD', 'OPTIONS']:
            if not validate_csrf_token():
                return jsonify({
                    "status": "error", 
                    "message": "CSRF token validation failed"
                }), 403
            
            # Rotate CSRF token after state-changing operations
            if hasattr(g, 'rotate_csrf') and g.rotate_csrf:
                session.pop('csrf_token', None)
                generate_csrf_token()
                
        # Flag to rotate the token after this request
        g.rotate_csrf = True if request.method not in ['GET', 'HEAD', 'OPTIONS'] else False
        return func(*args, **kwargs)
    return wrapper

# Enhance security headers function
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Remove server header
    response.headers['Server'] = 'Secure-Proxy'
    
    # Add basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Add Content Security Policy
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",  # Unsafe-inline needed for Bootstrap JS
        "style-src 'self' 'unsafe-inline'",   # Unsafe-inline needed for Bootstrap CSS
        "img-src 'self' data:",                # Allow data: for simple images
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'"
    ]
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    
    # Add Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add Feature Policy / Permissions Policy
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    # Add CSRF token if applicable
    if request.endpoint != 'static':
        token = generate_csrf_token()
        response.headers['X-CSRF-Token'] = token
        
    return response

# Routes
@app.route('/api/status', methods=['GET'])
@auth.login_required
def get_status():
    """Get the current status of the proxy service"""
    try:
        # Check if squid is running
        response = requests.get(f"http://{PROXY_HOST}:{PROXY_PORT}", 
                               proxies={"http": f"http://{PROXY_HOST}:{PROXY_PORT}"}, 
                               timeout=1)
        proxy_status = "running" if response.status_code == 400 else "error"  # Squid returns 400 for direct access
    except Exception as e:
        proxy_status = "error"
        logger.error(f"Error checking proxy status: {str(e)}")
    
    # Get system stats
    stats = {
        "proxy_status": proxy_status,
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }
    
    return jsonify({"status": "success", "data": stats})

@app.route('/api/settings', methods=['GET'])
@auth.login_required
def get_settings():
    """Get all settings"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings")
    settings = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({"status": "success", "data": settings})

@app.route('/api/settings/<setting_name>', methods=['PUT'])
@auth.login_required
@csrf_protected
def update_setting(setting_name):
    """Update a specific setting"""
    data = request.get_json()
    if not data or 'value' not in data:
        return jsonify({"status": "error", "message": "No value provided"}), 400
    
    if not validate_setting(setting_name, data['value']):
        return jsonify({"status": "error", "message": "Invalid value provided"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?", 
                  (data['value'], setting_name))
    conn.commit()
    
    # Apply settings to proxy configuration
    apply_settings()
    
    return jsonify({"status": "success", "message": f"Setting {setting_name} updated"})

@app.route('/api/ip-blacklist', methods=['GET'])
@auth.login_required
def get_ip_blacklist():
    """Get all blacklisted IPs"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_blacklist")
    blacklist = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({"status": "success", "data": blacklist})

@app.route('/api/ip-blacklist', methods['POST'])
@auth.login_required
@csrf_protected
def add_ip_to_blacklist():
    """Add an IP to the blacklist"""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"status": "error", "message": "No IP provided"}), 400
    
    # Validate IP address format
    ip = data['ip'].strip()
    description = data.get('description', '')
    
    # Validate CIDR notation or single IP address
    try:
        # This will validate both individual IPs and CIDR notation
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid IP address format"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)", 
                      (ip, description))
        conn.commit()
        
        # Update blacklist file
        update_ip_blacklist()
        
        return jsonify({"status": "success", "message": "IP added to blacklist"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "IP already in blacklist"}), 400

@app.route('/api/ip-blacklist/<int:id>', methods=['DELETE'])
@auth.login_required
@csrf_protected
def remove_ip_from_blacklist(id):
    """Remove an IP from the blacklist"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ip_blacklist WHERE id = ?", (id,))
    conn.commit()
    
    # Update blacklist file
    update_ip_blacklist()
    
    return jsonify({"status": "success", "message": "IP removed from blacklist"})

@app.route('/api/domain-blacklist', methods=['GET'])
@auth.login_required
def get_domain_blacklist():
    """Get all blacklisted domains"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM domain_blacklist")
    blacklist = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({"status": "success", "data": blacklist})

@app.route('/api/domain-blacklist', methods=['POST'])
@auth.login_required
@csrf_protected
def add_domain_to_blacklist():
    """Add a domain to the blacklist"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"status": "error", "message": "No domain provided"}), 400
    
    domain = data['domain'].strip()
    description = data.get('description', '')
    
    # Basic domain validation
    # Allow wildcard domains (*.example.com) and regular domains
    domain_pattern = r'^(\*\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    if not re.match(domain_pattern, domain):
        return jsonify({"status": "error", "message": "Invalid domain format"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO domain_blacklist (domain, description) VALUES (?, ?)", 
                      (domain, description))
        conn.commit()
        
        # Update blacklist file
        update_domain_blacklist()
        
        return jsonify({"status": "success", "message": "Domain added to blacklist"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Domain already in blacklist"}), 400

@app.route('/api/domain-blacklist/<int:id>', methods=['DELETE'])
@auth.login_required
@csrf_protected
def remove_domain_from_blacklist(id):
    """Remove a domain from the blacklist"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM domain_blacklist WHERE id = ?", (id,))
    conn.commit()
    
    # Update blacklist file
    update_domain_blacklist()
    
    return jsonify({"status": "success", "message": "Domain removed from blacklist"})

@app.route('/api/logs', methods=['GET'])
@auth.login_required
def get_logs():
    """Get proxy logs"""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'timestamp')  # Default sort by timestamp
    order = request.args.get('order', 'desc')     # Default order is descending (latest first)
    
    # Validate and sanitize input parameters
    try:
        # Ensure limit and offset are positive integers
        limit = max(1, min(1000, int(limit)))  # Cap at 1000 records
        offset = max(0, int(offset))
    except (ValueError, TypeError):
        limit = 100
        offset = 0
    
    # Define a mapping of allowed sort columns to their actual DB counterparts
    valid_sort_mappings = {
        'timestamp': 'timestamp',
        'unix_timestamp': 'unix_timestamp', 
        'source_ip': 'source_ip',
        'destination': 'destination',
        'status': 'status',
        'bytes': 'bytes'
    }

    # Define allowed order directions
    valid_orders = {'asc': 'ASC', 'desc': 'DESC'}
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if the unix_timestamp column exists
    cursor.execute("PRAGMA table_info(proxy_logs)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Validate sorting parameters
    if sort not in valid_sort_mappings:
        sort = 'timestamp'  # Default to timestamp if invalid
    
    if order.lower() not in valid_orders:
        order = 'desc'  # Default to descending if invalid
    
    # Determine the correct column name for sorting
    column_name = valid_sort_mappings[sort]
    
    # Special case for timestamp
    if sort == 'timestamp' and 'unix_timestamp' in columns:
        column_name = 'unix_timestamp'
    
    # Get the direction
    direction = valid_orders[order.lower()]
    
    # Base query with parameters
    if search:
        # Apply search to multiple fields with proper parameter binding
        query = f"""
            SELECT * FROM proxy_logs 
            WHERE source_ip LIKE ? 
            OR destination LIKE ? 
            OR status LIKE ?
            ORDER BY {column_name} {direction} LIMIT ? OFFSET ?
        """
        search_param = f"%{search}%"
        cursor.execute(query, (search_param, search_param, search_param, limit, offset))
    else:
        query = f"""
            SELECT * FROM proxy_logs 
            ORDER BY {column_name} {direction} LIMIT ? OFFSET ?
        """
        cursor.execute(query, (limit, offset))
                      
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Get total count that matches the search
    if search:
        search_param = f"%{search}%"
        cursor.execute("""
            SELECT COUNT(*) FROM proxy_logs 
            WHERE source_ip LIKE ? 
            OR destination LIKE ? 
            OR status LIKE ?
        """, (search_param, search_param, search_param))
    else:
        cursor.execute("SELECT COUNT(*) FROM proxy_logs")
    
    total = cursor.fetchone()[0]
    
    return jsonify({
        "status": "success", 
        "data": logs,
        "meta": {
            "total": total,
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "order": order
        }
    })

@app.route('/api/logs/import', methods=['POST'])
@auth.login_required
@csrf_protected
def import_logs():
    """Import logs from Squid access.log"""
    try:
        result = parse_squid_logs()
        
        # Check the status of the operation
        if result["status"] == "success":
            return jsonify({
                "status": "success", 
                "message": f"Logs imported successfully. Imported {result['imported_count']} entries with {result['error_count']} errors."
            })
        elif result["status"] == "warning":
            # Return a warning but with a 200 status code
            return jsonify({
                "status": "warning", 
                "message": result.get("message", "Warning during log import")
            })
        else:
            # This is an error
            logger.error(f"Error importing logs: {result.get('message', 'Unknown error')}")
            return jsonify({
                "status": "error", 
                "message": result.get("message", "Error importing logs")
            }), 500
    except Exception as e:
        logger.error(f"Error importing logs: {str(e)}")
        return jsonify({"status": "error", "message": f"Error importing logs: {str(e)}"}), 500

@app.route('/api/logs/blocked-count', methods=['GET'])
@auth.login_required
def get_blocked_count():
    """Get count of blocked requests from logs"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Count logs with status codes that indicate blocked requests
    # Typically in Squid: TCP_DENIED/403 indicates a denied request
    cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%'")
    blocked_count = cursor.fetchone()[0]
    
    return jsonify({
        "status": "success", 
        "data": {
            "blocked_count": blocked_count
        }
    })

@app.route('/api/maintenance/download-cert', methods=['GET'])
@auth.login_required
def download_cert():
     """Download the CA certificate for HTTPS filtering"""
     cert_path = '/config/ssl_cert.pem'
     if not os.path.exists(cert_path):
         return jsonify({"status": "error", "message": "Certificate not found"}), 404
     return send_file(cert_path, as_attachment=True, download_name='secure-proxy-ca.pem', mimetype='application/x-pem-file')

@app.route('/api/maintenance/clear-cache', methods=['POST'])
@auth.login_required
@csrf_protected
def clear_cache():
    """Clear the Squid cache"""
    try:
        # Safer execution of the squid command with validated container name
        container_name = os.environ.get('PROXY_CONTAINER_NAME', 'secure-proxy-proxy-1')
        # Validate container name to prevent command injection
        if not re.match(r'^[a-zA-Z0-9_-]+$', container_name):
            raise ValueError(f"Invalid container name format: {container_name}")
            
        result = subprocess.run(
            ['docker', 'exec', container_name, 'squidclient', '-h', 'localhost', 'mgr:shutdown'],
            capture_output=True, text=True, check=False
        )
        
        if result.returncode != 0:
            logger.error(f"Error clearing cache: {result.stderr}")
            return jsonify({
                "status": "error", 
                "message": f"Error clearing cache: {result.stderr}"
            }), 500
            
        logger.info("Cache cleared successfully")
        return jsonify({"status": "success", "message": "Cache cleared successfully"})
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({"status": "error", "message": f"Validation error: {str(e)}"}), 400
    except subprocess.CalledProcessError as e:
        logger.error(f"Error clearing cache: {str(e)}")
        return jsonify({"status": "error", "message": f"Error clearing cache: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Unexpected error clearing cache: {str(e)}")
        return jsonify({"status": "error", "message": f"Unexpected error clearing cache: {str(e)}"}), 500

@app.route('/api/maintenance/backup-config', methods=['GET'])
@auth.login_required
def backup_config():
    """Create a backup of all configuration settings"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get all settings
        cursor.execute("SELECT * FROM settings")
        settings = [dict(row) for row in cursor.fetchall()]
        
        # Get IP blacklist
        cursor.execute("SELECT * FROM ip_blacklist")
        ip_blacklist = [dict(row) for row in cursor.fetchall()]
        
        # Get domain blacklist
        cursor.execute("SELECT * FROM domain_blacklist")
        domain_blacklist = [dict(row) for row in cursor.fetchall()]
        
        # Compile everything into a backup object
        backup = {
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "settings": settings,
            "ip_blacklist": ip_blacklist,
            "domain_blacklist": domain_blacklist
        }
        
        return jsonify({"status": "success", "data": backup})
    except Exception as e:
        logger.error(f"Error creating backup: {str(e)}")
        return jsonify({"status": "error", "message": f"Error creating backup: {str(e)}"}), 500

@app.route('/api/maintenance/restore-config', methods=['POST'])
@auth.login_required
@csrf_protected
def restore_config():
    """Restore configuration from a backup file"""
    try:
        data = request.get_json()
        if not data or 'backup' not in data:
            return jsonify({"status": "error", "message": "No backup data provided"}), 400
        
        backup = data['backup']
        
        # Use the context manager for safer database operations
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Start a transaction
            conn.execute("BEGIN TRANSACTION")
            
            try:
                # Restore settings
                if 'settings' in backup:
                    for setting in backup['settings']:
                        cursor.execute(
                            "UPDATE settings SET setting_value = ? WHERE setting_name = ?", 
                            (setting['setting_value'], setting['setting_name'])
                        )
                
                # Restore IP blacklist
                if 'ip_blacklist' in backup:
                    cursor.execute("DELETE FROM ip_blacklist")
                    for entry in backup['ip_blacklist']:
                        cursor.execute(
                            "INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)",
                            (entry['ip'], entry['description'])
                        )
                
                # Restore domain blacklist
                if 'domain_blacklist' in backup:
                    cursor.execute("DELETE FROM domain_blacklist")
                    for entry in backup['domain_blacklist']:
                        cursor.execute(
                            "INSERT INTO domain_blacklist (domain, description) VALUES (?, ?)",
                            (entry['domain'], entry['description'])
                        )
                
                # Commit the transaction (handled by context manager)
                
                # Update blacklist files
                update_ip_blacklist()
                update_domain_blacklist()
                
                # Apply settings
                apply_settings()
                
                return jsonify({"status": "success", "message": "Configuration restored successfully"})
            except Exception as e:
                # Rollback in case of error (handled by context manager)
                raise e
                
    except Exception as e:
        logger.error(f"Error restoring backup: {str(e)}")
        return jsonify({"status": "error", "message": f"Error restoring backup: {str(e)}"}), 500

# Helper functions
def update_ip_blacklist():
    """Update the IP blacklist file"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM ip_blacklist")
    ips = [row['ip'] for row in cursor.fetchall()]
    
    # Try multiple possible paths to ensure at least one works
    config_paths = ['/config/ip_blacklist.txt', 'config/ip_blacklist.txt']
    success = False
    
    for config_path in config_paths:
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            # Write to config file
            with open(config_path, 'w') as f:
                f.write('\n'.join(ips))
            
            logger.info(f"IP blacklist updated at {config_path}")
            success = True
            break
        except PermissionError as e:
            logger.error(f"Permission denied writing to {config_path}: {e}")
        except IOError as e:
            logger.error(f"IO Error writing to {config_path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error writing to {config_path}: {e}")
    
    if not success:
        logger.error("Failed to update IP blacklist file in any location")
    
    return success

@app.route('/api/logs/clear', methods=['POST'])
@auth.login_required
@csrf_protected
def clear_logs():
    """Clear all proxy logs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM proxy_logs")
        conn.commit()
        logger.info("All logs cleared successfully")
        return jsonify({"status": "success", "message": "All logs cleared successfully"})
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({"status": "error", "message": f"Error clearing logs: {str(e)}"}), 500

@app.route('/api/maintenance/reload-config', methods=['POST'])
@auth.login_required
@csrf_protected
def reload_proxy_config():
    """Reload the proxy configuration"""
    try:
        # Apply settings to regenerate the config
        if apply_settings():
            return jsonify({"status": "success", "message": "Proxy configuration reloaded successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to reload proxy configuration"}), 500
    except Exception as e:
        logger.error(f"Error reloading proxy configuration: {str(e)}")
        return jsonify({"status": "error", "message": f"Error reloading proxy configuration: {str(e)}"}), 500

def update_domain_blacklist():
    """Update the domain blacklist file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM domain_blacklist")
            domains = [row['domain'] for row in cursor.fetchall()]
            
            # Try multiple possible paths to ensure at least one works
            config_paths = ['/config/domain_blacklist.txt', 'config/domain_blacklist.txt']
            success = False
            
            for config_path in config_paths:
                try:
                    # Ensure directory exists
                    os.makedirs(os.path.dirname(config_path), exist_ok=True)
                    
                    # Write to config file
                    with open(config_path, 'w') as f:
                        f.write('\n'.join(domains))
                    
                    logger.info(f"Domain blacklist updated at {config_path}")
                    success = True
                    break
                except PermissionError as e:
                    logger.error(f"Permission denied writing to {config_path}: {e}")
                except IOError as e:
                    logger.error(f"IO Error writing to {config_path}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error writing to {config_path}: {e}")
            
            if not success:
                logger.error("Failed to update domain blacklist file in any location")
        
        return success
    except Exception as e:
        logger.error(f"Error updating domain blacklist: {str(e)}")
        return False

def apply_settings():
    """Apply settings to proxy configuration"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT setting_name, setting_value FROM settings")
    settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
    
    try:
        # Create custom squid configuration based on settings
        squid_conf = []
        
        # Base configuration
        squid_conf.append("http_port 3128")
        squid_conf.append("visible_hostname secure-proxy")
        squid_conf.append("")
        
        # Access control lists
        squid_conf.append("# Access control lists")
        squid_conf.append("acl localnet src 10.0.0.0/8")
        squid_conf.append("acl localnet src 172.16.0.0/12")
        squid_conf.append("acl localnet src 192.168.0.0/16")
        squid_conf.append("acl localnet src fc00::/7")
        squid_conf.append("acl localnet src fe80::/10")
        squid_conf.append("")
        
        # SSL/HTTPS related ACLs
        squid_conf.append("# SSL/HTTPS related ACLs")
        squid_conf.append("acl SSL_ports port 443")
        squid_conf.append("acl Safe_ports port 80")
        squid_conf.append("acl Safe_ports port 443")
        squid_conf.append("acl Safe_ports port 21")
        squid_conf.append("acl Safe_ports port 70")
        squid_conf.append("acl Safe_ports port 210")
        squid_conf.append("acl Safe_ports port 1025-65535")
        squid_conf.append("acl Safe_ports port 280")
        squid_conf.append("acl Safe_ports port 488")
        squid_conf.append("acl Safe_ports port 591")
        squid_conf.append("acl Safe_ports port 777")
        
        # Add SSL bump configuration for HTTPS filtering
        if settings.get('enable_https_filtering') == 'true':
            squid_conf.append("")
            squid_conf.append("# HTTPS filtering via SSL Bump")
            squid_conf.append("# Define ssl certificate database and helpers")
            squid_conf.append("sslcrtd_program /usr/lib/squid/security_file_certgen -s /config/ssl_db -M 4MB")
            squid_conf.append("sslcrtd_children 5")
            squid_conf.append("# Listen for HTTPS with SSL bump")
            squid_conf.append("https_port 3129 ssl-bump cert=/config/ssl_cert.pem key=/config/ssl_key.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB")
            squid_conf.append("")
            squid_conf.append("# SSL Bump steps")
            squid_conf.append("acl step1 at_step SslBump1")
            squid_conf.append("ssl_bump peek step1")
            squid_conf.append("ssl_bump bump all")
        
        # IP and Domain blacklists
        squid_conf.append("")
        squid_conf.append("# IP blacklists")
        squid_conf.append('acl ip_blacklist src "/etc/squid/blacklists/ip/local.txt"')
        squid_conf.append("")
        squid_conf.append("# Domain blacklists")
        squid_conf.append('acl domain_blacklist dstdomain "/etc/squid/blacklists/domain/local.txt"')
        
        # HTTP method definitions
        squid_conf.append("")
        squid_conf.append("# HTTP method definitions")
        squid_conf.append("acl CONNECT method CONNECT")
        
        # Direct IP access detection - improved for better blocking with proper escaping
        squid_conf.append("")
        squid_conf.append("# Direct IP access detection - improved for better blocking")
        # IPv4 detection with proper escaping
        squid_conf.append(r'acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)')
        squid_conf.append(r'acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$')
        # IPv6 detection
        squid_conf.append(r'acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]')
        squid_conf.append(r'acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$')
        
        # Content filtering if enabled
        if settings.get('enable_content_filtering') == 'true' and settings.get('blocked_file_types'):
            file_types = settings.get('blocked_file_types').split(',')
            squid_conf.append("")
            squid_conf.append("# File type blocking")
            squid_conf.append(r'acl blocked_extensions urlpath_regex -i "\.(' + '|'.join(file_types) + r')$"')
        
        # Time restrictions if enabled
        if settings.get('enable_time_restrictions') == 'true':
            start_time = settings.get('time_restriction_start', '09:00')
            end_time = settings.get('time_restriction_end', '17:00')
            squid_conf.append("")
            squid_conf.append("# Time restrictions")
            squid_conf.append(f'acl allowed_hours time MTWHFA {start_time}-{end_time}')
        
        # Basic access control rules
        squid_conf.append("")
        squid_conf.append("# Basic access control")
        squid_conf.append("http_access deny !Safe_ports")
        squid_conf.append("http_access deny CONNECT !SSL_ports")
        
        # Block direct IP access if enabled - moved to higher priority and improved
        if settings.get('block_direct_ip') == 'true':
            squid_conf.append("")
            squid_conf.append("# Block direct IP URL access - high priority")
            squid_conf.append("http_access deny direct_ip_url")
            squid_conf.append("http_access deny direct_ip_host")
            squid_conf.append("http_access deny direct_ipv6_url")
            squid_conf.append("http_access deny direct_ipv6_host")
            # Block CONNECT to IPs (for HTTPS)
            squid_conf.append("http_access deny CONNECT direct_ip_host")
            squid_conf.append("http_access deny CONNECT direct_ipv6_host")
        
        # Apply blacklists if enabled
        if settings.get('enable_ip_blacklist') == 'true':
            squid_conf.append("")
            squid_conf.append("# Block blacklisted IPs")
            squid_conf.append("http_access deny ip_blacklist")
        
        if settings.get('enable_domain_blacklist') == 'true':
            squid_conf.append("")
            squid_conf.append("# Block blacklisted domains")
            squid_conf.append("http_access deny domain_blacklist")
        
        # Apply content filtering if enabled
        if settings.get('enable_content_filtering') == 'true' and settings.get('blocked_file_types'):
            squid_conf.append("")
            squid_conf.append("# Block banned file extensions")
            squid_conf.append("http_access deny blocked_extensions")
        
        # Apply time restrictions if enabled
        if settings.get('enable_time_restrictions') == 'true':
            squid_conf.append("")
            squid_conf.append("# Apply time restrictions")
            squid_conf.append("http_access deny !allowed_hours")
        
        # Allow local access
        squid_conf.append("")
        squid_conf.append("# Allow local network access")
        squid_conf.append("http_access allow localhost")
        squid_conf.append("http_access allow localnet")
        
        # Default deny rule
        squid_conf.append("")
        squid_conf.append("# Default deny")
        squid_conf.append("http_access deny all")
        
        # Caching options
        cache_size = settings.get('cache_size', '1000')  # Default 1GB
        max_obj_size = settings.get('max_object_size', '50')  # Default 50MB
        squid_conf.append("")
        squid_conf.append("# Caching options")
        squid_conf.append(f"cache_dir ufs /var/spool/squid {cache_size} 16 256")
        squid_conf.append(f"maximum_object_size {max_obj_size} MB")
        squid_conf.append("coredump_dir /var/spool/squid")
        
        # Compression if enabled
        if settings.get('enable_compression') == 'true':
            squid_conf.append("")
            squid_conf.append("# Compression settings")
            squid_conf.append("zph_mode off")
            squid_conf.append("zph_local tos local-hit=0x30")
            squid_conf.append("zph_sibling tos sibling-hit=0x31")
            squid_conf.append("zph_parent tos parent-hit=0x32")
            squid_conf.append("zph_option 136 tos miss=0x33")
        
        # Timeout settings
        conn_timeout = settings.get('connection_timeout', '30')
        dns_timeout = settings.get('dns_timeout', '5')
        squid_conf.append("")
        squid_conf.append("# Timeout settings")
        squid_conf.append(f"connect_timeout {conn_timeout} seconds")
        squid_conf.append(f"dns_timeout {dns_timeout} seconds")
        
        # Log settings
        log_level = settings.get('log_level', 'info').upper()
        squid_conf.append("")
        squid_conf.append("# Log settings")
        squid_conf.append(f"debug_options ALL,{log_level}")
        squid_conf.append("access_log daemon:/var/log/squid/access.log squid")
        squid_conf.append("cache_log /var/log/squid/cache.log")
        squid_conf.append("cache_store_log stdio:/var/log/squid/store.log")
        
        # Add standard refresh patterns
        squid_conf.append("")
        squid_conf.append("# Refresh patterns")
        squid_conf.append("refresh_pattern ^ftp:           1440    20%     10080")
        squid_conf.append("refresh_pattern ^gopher:        1440    0%      1440")
        squid_conf.append("refresh_pattern -i (/cgi-bin/|\\?) 0     0%      0")
        squid_conf.append("refresh_pattern .               0       20%     4320")
        
        # Generate the final configuration
        final_config = '\n'.join(squid_conf)
        
        # Primary configuration path that will be picked up by the container
        # This is mounted to the /config directory in the container via docker-compose.yml
        config_path = '/config/custom_squid.conf'
        local_config_path = 'config/custom_squid.conf'
        
        # Write configuration to the correct location
        logger.info(f"Writing Squid configuration to {config_path}")
        
        # Try all possible paths to ensure at least one works
        success = False
        
        # First try the absolute path
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                f.write(final_config)
            logger.info(f"Successfully wrote configuration to {config_path}")
            success = True
        except Exception as e:
            logger.warning(f"Could not write to {config_path}: {e}")
        
        # Also try relative path from project root
        try:
            os.makedirs(os.path.dirname(local_config_path), exist_ok=True)
            with open(local_config_path, 'w') as f:
                f.write(final_config)
            logger.info(f"Successfully wrote configuration to {local_config_path}")
            success = True
        except Exception as e:
            logger.warning(f"Could not write to {local_config_path}: {e}")
        
        # Ensure blacklist files are updated
        update_ip_blacklist()
        update_domain_blacklist()
        
        # Now restart the proxy container to apply changes
        try:
            logger.info("Restarting proxy container to apply new configuration")
            container_name = os.environ.get('PROXY_CONTAINER_NAME', 'secure-proxy-proxy-1')
            
            # Validate container name to prevent command injection
            if not re.match(r'^[a-zA-Z0-9_-]+$', container_name):
                error_msg = f"Invalid container name format: {container_name}"
                logger.error(error_msg)
                return False  # Return False to indicate failure
                
            # Check if the container exists before attempting restart
            check_result = subprocess.run(
                ['docker', 'inspect', container_name],
                capture_output=True, check=False, timeout=10
            )
            
            if check_result.returncode != 0:
                error_msg = f"Container '{container_name}' does not exist or is not accessible"
                logger.error(error_msg)
                return False  # Return False to indicate failure
                
            # Now restart the container
            restart_result = subprocess.run(
                ['docker', 'restart', container_name],
                capture_output=True, check=False, timeout=20
            )
            
            if restart_result.returncode != 0:
                error_msg = f"Failed to restart container: {restart_result.stderr.decode('utf-8', errors='replace')}"
                logger.error(error_msg)
                return False
                
            logger.info("Proxy container restarted successfully")
            
            # Wait for the container to come up
            time.sleep(5)
            
            return success
        except subprocess.TimeoutExpired:
            logger.error("Timeout expired when restarting proxy container")
            return False
        except Exception as e:
            logger.error(f"Error restarting proxy container: {str(e)}")
            return False  # Always return False on error to indicate failure
            
    except Exception as e:
        logger.error(f"Error applying settings: {str(e)}")
        return False

def parse_squid_logs():
    """Parse Squid access logs and import to database"""
    # Get log path from environment variable or config, with fallbacks
    log_path = os.environ.get('SQUID_LOG_PATH')
    
    # Try multiple potential log paths if not configured
    if not log_path:
        log_paths = [
            '/logs/access.log',
            'logs/access.log',
            '/var/log/squid/access.log',
            './logs/access.log',
            '../logs/access.log'
        ]
        
        # Find the first log file that exists and is readable
        for path in log_paths:
            if os.path.exists(path) and os.access(path, R_OK):
                log_path = path
                logger.info(f"Found Squid access log at: {log_path}")
                break
    
    if not log_path:
        error_msg = f"Log file not found in any of the expected locations. Configure SQUID_LOG_PATH environment variable."
        logger.error(error_msg)
        return {
            "status": "error",
            "message": error_msg,
            "imported_count": 0,
            "error_count": 0,
            "log_path": None
        }
    
    try:
        # Get file stats to see if it's readable and has content
        file_stats = os.stat(log_path)
        if file_stats.st_size == 0:
            logger.warning(f"Log file {log_path} is empty")
            return {
                "status": "warning",
                "message": f"Log file {log_path} is empty",
                "imported_count": 0,
                "error_count": 0,
                "log_path": log_path
            }
            
        conn = get_db()
        cursor = conn.cursor()
        
        # Ensure the log table exists with proper timestamp column
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS proxy_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            destination TEXT,
            status TEXT,
            bytes INTEGER,
            imported_at TEXT,
            unix_timestamp REAL
        )
        """)
        
        # Check if unix_timestamp column exists, add it if not
        cursor.execute("PRAGMA table_info(proxy_logs)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'unix_timestamp' not in columns:
            logger.info("Adding unix_timestamp column to proxy_logs table")
            cursor.execute("ALTER TABLE proxy_logs ADD COLUMN unix_timestamp REAL")
            conn.commit()
        
        # Parse Squid log format matching your actual log format
        imported_count = 0
        error_count = 0
        with open(log_path, 'r') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                    
                try:
                    parts = line.split()
                    if len(parts) < 7:
                        logger.warning(f"Line {line_number} has insufficient fields: {line}")
                        error_count += 1
                        continue
                        
                    timestamp = float(parts[0])  # Unix timestamp
                    elapsed = parts[1]
                    source_ip = parts[2]
                    status_code = parts[3]
                    
                    # Handle non-numeric bytes values
                    try:
                        bytes_value = int(parts[4])
                    except ValueError:
                        bytes_value = 0
                        logger.warning(f"Line {line_number} has non-numeric bytes value: {parts[4]}")
                    
                    method = parts[5]
                    url = parts[6]
                    
                    # Convert Unix timestamp to datetime in ISO format for display
                    readable_time = datetime.fromtimestamp(timestamp).isoformat()
                    
                    # Generate a unique composite key for checking duplicates
                    composite_key = f"{timestamp}_{source_ip}_{url}"
                    
                    # Insert log entry, storing both readable time and unix timestamp
                    cursor.execute("""
                    INSERT OR IGNORE INTO proxy_logs 
                    (timestamp, source_ip, destination, status, bytes, imported_at, unix_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (readable_time, source_ip, url, status_code, bytes_value, 
                          datetime.now().isoformat(), timestamp))
                    
                    imported_count += 1
                    if imported_count % 1000 == 0:
                        # Commit periodically for large files
                        conn.commit()
                        logger.info(f"Imported {imported_count} log entries so far...")
                except (ValueError, IndexError) as e:
                    error_count += 1
                    logger.error(f"Error parsing log line {line_number}: {line} - {str(e)}")
                    continue
                except Exception as e:
                    error_count += 1
                    logger.error(f"Unexpected error on line {line_number}: {str(e)}")
                    continue
        
        # Final commit
        conn.commit()
        
        logger.info(f"Squid logs import completed: {imported_count} entries imported, {error_count} errors")
        
        # Update log stats table to record last import time
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_stats (
            id INTEGER PRIMARY KEY,
            last_import TIMESTAMP,
            import_count INTEGER,
            error_count INTEGER
        )
        """)
        
        cursor.execute("""
        INSERT OR REPLACE INTO log_stats (id, last_import, import_count, error_count)
        VALUES (1, ?, ?, ?)
        """, (datetime.now().isoformat(), imported_count, error_count))
        
        conn.commit()
        
        return {
            "status": "success",
            "imported_count": imported_count,
            "error_count": error_count,
            "log_path": log_path
        }
    except Exception as e:
        logger.error(f"Error processing log file {log_path}: {str(e)}")
        return {
            "status": "error",
            "message": f"Error processing log file: {str(e)}",
            "imported_count": 0,
            "error_count": 1,
            "log_path": log_path
        }

# Add background log parser with mutex
_log_parser_lock = threading.Lock()

# Create a shutdown event
shutdown_event = threading.Event()

def background_log_parser():
    """Parse logs in the background periodically"""
    global _log_parser_lock
    while not shutdown_event.is_set():
        try:
            # Use a lock to prevent concurrent log parsing
            if _log_parser_lock.acquire(blocking=False):
                try:
                    # Create an application context for this thread
                    with app.app_context():
                        parse_squid_logs()
                        logger.info("Background log parsing completed")
                finally:
                    _log_parser_lock.release()
            else:
                logger.debug("Skipping background log parse - another process is already parsing logs")
        except Exception as e:
            logger.error(f"Error in background log parsing: {str(e)}")
        
        # Wait for shutdown event or timeout
        shutdown_event.wait(30)  # Parse logs every 30 seconds or exit if shutdown requested

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    logger.info("Shutdown signal received, stopping background tasks...")
    shutdown_event.set()
    # Give threads a moment to terminate
    time.sleep(1)
    logger.info("Exiting application")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Start the background log parser in a separate thread
log_parser_thread = threading.Thread(target=background_log_parser, daemon=True)
log_parser_thread.start()

# Initialize the application
init_db()

# Apply settings on startup to ensure proper configuration
try:
    with app.app_context():
        update_ip_blacklist()
        update_domain_blacklist()
        apply_settings()
        logger.info("Initial settings applied")
except Exception as e:
    logger.error(f"Error applying initial settings: {str(e)}")

@app.route('/api/logs/stats', methods=['GET'])
@auth.login_required
def get_log_stats():
    """Get statistics about logs including blocked requests and direct IP blocks"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get total log count
        cursor.execute("SELECT COUNT(*) FROM proxy_logs")
        total_count = cursor.fetchone()[0]
        
        # Get blocked requests count (TCP_DENIED, 403, etc.)
        cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE ? OR status LIKE ? OR status LIKE ?", 
                      ('%DENIED%', '%403%', '%BLOCKED%'))
        blocked_count = cursor.fetchone()[0]
        
        # Get direct IP blocks count - use a stronger approach with validation
        try:
            # Try with user-defined function if available
            conn.create_function("is_ip_address", 1, is_ip_address)
            cursor.execute("""
                SELECT COUNT(*) FROM proxy_logs 
                WHERE (status LIKE ? OR status LIKE ? OR status LIKE ?) 
                AND is_ip_address(destination)
            """, ('%DENIED%', '%403%', '%BLOCKED%'))
            ip_blocks_count = cursor.fetchone()[0]
        except (sqlite3.OperationalError, AttributeError):
            # Simplified fallback without regex
            # This is an approximation only looking at IP-like URLs
            cursor.execute("""
                SELECT COUNT(*) FROM proxy_logs 
                WHERE (status LIKE ? OR status LIKE ? OR status LIKE ?)
                AND (
                    (destination LIKE 'http://%.%.%.%' AND destination NOT LIKE 'http://%.%.%.%.%')
                    OR
                    (destination LIKE 'https://%.%.%.%' AND destination NOT LIKE 'https://%.%.%.%.%')
                    OR
                    destination LIKE '%.%.%.%'
                )
            """, ('%DENIED%', '%403%', '%BLOCKED%'))
            ip_blocks_count = cursor.fetchone()[0]
        
        # Get timestamp of last import
        cursor.execute("SELECT MAX(timestamp) FROM proxy_logs")
        last_import = cursor.fetchone()[0]
        
        stats = {
            "total_count": total_count,
            "blocked_count": blocked_count,
            "ip_blocks_count": ip_blocks_count,
            "last_import": last_import
        }
        
        return jsonify({
            "status": "success", 
            "data": stats
        })
    except Exception as e:
        logger.error(f"Error retrieving log statistics: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Error retrieving log statistics: {str(e)}",
            "data": {
                "total_count": 0,
                "blocked_count": 0,
                "ip_blocks_count": 0,
                "last_import": None
            }
        })

# Helper function to check if a string is an IP address
def is_ip_address(text):
    """Check if a string represents an IP address"""
    # Extract potential IPs from URLs
    if text.startswith('http://') or text.startswith('https://'):
        # Extract the domain part from the URL
        parts = text.split('/', 3)
        if len(parts) >= 3:
            text = parts[2]  # Get the domain part
    
    # Simple pattern matching for IPv4 addresses
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, text)
    
    if not match:
        return False
    
    # Validate each octet is in range 0-255
    for octet in match.groups():
        num = int(octet)
        if num < 0 or num > 255:
            return False
    
    return True

def validate_setting(setting_name, setting_value):
    """Validate setting values to prevent injection and ensure proper types"""
    # Define validation rules for different setting types
    validation_rules = {
        # Boolean settings
        'block_direct_ip': lambda x: x in ['true', 'false'],
        'enable_ip_blacklist': lambda x: x in ['true', 'false'],
        'enable_domain_blacklist': lambda x: x in ['true', 'false'],
        'enable_compression': lambda x: x in ['true', 'false'],
        'enable_content_filtering': lambda x: x in ['true', 'false'],
        'enable_https_filtering': lambda x: x in ['true', 'false'],
        'enable_time_restrictions': lambda x: x in ['true', 'false'],
        'enable_proxy_auth': lambda x: x in ['true', 'false'],
        'enable_user_management': lambda x: x in ['true', 'false'],
        'enable_extended_logging': lambda x: x in ['true', 'false'],
        'enable_alerts': lambda x: x in ['true', 'false'],
        
        # Numeric settings
        'cache_size': lambda x: x.isdigit() and 100 <= int(x) <= 10000,
        'max_object_size': lambda x: x.isdigit() and 1 <= int(x) <= 1000,
        'connection_timeout': lambda x: x.isdigit() and 1 <= int(x) <= 300,
        'dns_timeout': lambda x: x.isdigit() and 1 <= int(x) <= 60,
        'max_connections': lambda x: x.isdigit() and 10 <= int(x) <= 1000,
        'log_retention': lambda x: x.isdigit() and 1 <= int(x) <= 365,
        
        # String settings with specific formats
        'log_level': lambda x: x.lower() in ['debug', 'info', 'warning', 'error'],
        'auth_method': lambda x: x.lower() in ['basic', 'digest', 'ntlm'],
        
        # Time format settings
        'time_restriction_start': lambda x: re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', x) is not None,
        'time_restriction_end': lambda x: re.match(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$', x) is not None,
        
        # List settings
        'blocked_file_types': lambda x: all(ext.isalnum() for ext in x.split(','))
    }
    
    # If we have a specific validation rule for this setting
    if setting_name in validation_rules:
        # Apply the validation rule
        if not validation_rules[setting_name](setting_value):
            logger.warning(f"Invalid value for setting {setting_name}: {setting_value}")
            return False
    
    return True

@app.route('/api/change-password', methods=['POST'])
@auth.login_required
@csrf_protected
def change_password():
    """Change user password with proper validation"""
    data = request.get_json()
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({"status": "error", "message": "Missing required password fields"}), 400
    
    current_password = data['current_password']
    new_password = data['new_password']
    
    # Basic password complexity validation
    if len(new_password) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters long"}), 400
        
    # Check for complexity (at least one number and one special character)
    if not re.search(r'\d', new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        return jsonify({
            "status": "error", 
            "message": "Password must contain at least one number and one special character"
        }), 400
    
    # Get the current user
    username = auth.current_user()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404
    
    # Verify current password
    if not check_password_hash(user['password'], current_password):
        logger.warning(f"Failed password change attempt for user {username} - incorrect current password")
        return jsonify({"status": "error", "message": "Current password is incorrect"}), 403
    
    # Update password
    new_password_hash = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password_hash, username))
    conn.commit()
    
    # Check if this was the default admin/admin password change
    if username == 'admin' and check_password_hash(user['password'], 'admin'):
        logger.info("Default admin password has been changed")
        
        # Update the default password flag in settings if it exists
        cursor.execute("SELECT COUNT(*) FROM settings WHERE setting_name = 'default_password_changed'")
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "INSERT INTO settings (setting_name, setting_value, description) VALUES (?, ?, ?)",
                ('default_password_changed', 'true', 'Flag indicating default admin password has been changed')
            )
        else:
            cursor.execute(
                "UPDATE settings SET setting_value = ? WHERE setting_name = ?",
                ('true', 'default_password_changed')
            )
        conn.commit()
    
    logger.info(f"Password changed successfully for user {username}")
    return jsonify({"status": "success", "message": "Password changed successfully"})

@app.route('/api/maintenance/check-cert-security', methods=['GET'])
@auth.login_required
def check_cert_security():
    """Check the security of SSL certificates used for HTTPS filtering"""
    try:
        cert_issues = []
        
        # Check for certificate existence
        cert_paths = ['/config/ssl_cert.pem', 'config/ssl_cert.pem']
        cert_found = False
        
        for cert_path in cert_paths:
            if os.path.exists(cert_path):
                cert_found = True
                logger.info(f"Found SSL certificate at {cert_path}")
                break
        
        if not cert_found:
            cert_issues.append("SSL certificate not found at any expected location")
        
        # Check for certificate database existence
        db_paths = ['/config/ssl_db', 'config/ssl_db']
        db_found = False
        
        for db_path in db_paths:
            if os.path.exists(db_path) and os.path.isdir(db_path) and os.listdir(db_path):
                db_found = True
                logger.info(f"Found SSL database at {db_path}")
                break
        
        if not db_found:
            cert_issues.append("SSL certificate database not found or empty")
        
        # Check certificate permissions if found
        if cert_found:
            try:
                # Check for proper certificate format and expiration
                import OpenSSL.crypto as crypto
                import datetime
                
                with open(cert_path, 'r') as f:
                    cert_data = f.read()
                
                try:
                    # Try to load the certificate
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                    
                    # Check expiration
                    expiry = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    now = datetime.datetime.now()
                    
                    if expiry < now:
                        cert_issues.append(f"SSL certificate has expired on {expiry.strftime('%Y-%m-%d')}")
                    elif (expiry - now).days < 30:
                        cert_issues.append(f"SSL certificate will expire soon (on {expiry.strftime('%Y-%m-%d')})")
                    
                    # Check key length
                    key_length = cert.get_pubkey().bits()
                    if key_length < 2048:
                        cert_issues.append(f"SSL certificate uses a weak key length ({key_length} bits)")
                    
                except Exception as e:
                    cert_issues.append(f"Invalid certificate format: {str(e)}")
            except ImportError:
                cert_issues.append("OpenSSL library not available for certificate validation")
            except Exception as e:
                cert_issues.append(f"Error validating certificate: {str(e)}")
        
        # Determine status based on issues found
        if not cert_issues:
            return jsonify({
                "status": "success",
                "message": "Certificate security checks passed",
                "details": []
            })
        elif cert_found and db_found:
            # We have certificates but there might be issues
            return jsonify({
                "status": "warning",
                "message": "Certificate security check found issues",
                "details": cert_issues
            })
        else:
            # Critical issues - certificates missing
            return jsonify({
                "status": "error",
                "message": "Certificate security check failed",
                "details": cert_issues
            }), 500
    except Exception as e:
        logger.error(f"Error checking certificate security: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Error checking certificate security: {str(e)}",
            "details": [str(e)]
        }), 500

@app.route('/api/security/rate-limits', methods=['GET'])
@auth.login_required
def get_rate_limits():
    """Get current rate limit status for all IPs"""
    # Only administrative users should have access to this endpoint
    try:
        now = datetime.now()
        rate_limit_data = []
        
        for ip, attempts in auth_attempts.items():
            # Clean up expired attempts first
            valid_attempts = [t for t in attempts if (now - t).total_seconds() < RATE_LIMIT_WINDOW]
            auth_attempts[ip] = valid_attempts
            
            # Only include IPs with active attempts
            if valid_attempts:
                rate_limit_data.append({
                    'ip': ip,
                    'attempt_count': len(valid_attempts),
                    'is_blocked': len(valid_attempts) >= MAX_ATTEMPTS,
                    'oldest_attempt': valid_attempts[0].isoformat() if valid_attempts else None,
                    'newest_attempt': valid_attempts[-1].isoformat() if valid_attempts else None,
                    'time_remaining': int(RATE_LIMIT_WINDOW - (now - valid_attempts[0]).total_seconds()) if valid_attempts else 0
                })
        
        return jsonify({
            "status": "success",
            "data": rate_limit_data,
            "meta": {
                "max_attempts": MAX_ATTEMPTS,
                "window_seconds": RATE_LIMIT_WINDOW
            }
        })
    except Exception as e:
        logger.error(f"Error retrieving rate limit data: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error retrieving rate limit data: {str(e)}"
        }), 500

@app.route('/api/security/rate-limits/<ip>', methods=['DELETE'])
@auth.login_required
@csrf_protected
def clear_rate_limit(ip):
    """Reset rate limiting for a specific IP"""
    try:
        if ip in auth_attempts:
            auth_attempts.pop(ip)
            logger.info(f"Rate limit cleared for IP: {ip}")
            return jsonify({
                "status": "success",
                "message": f"Rate limit for IP {ip} has been reset"
            })
        else:
            return jsonify({
                "status": "warning",
                "message": f"No rate limit record found for IP {ip}"
            })
    except Exception as e:
        logger.error(f"Error clearing rate limit for IP {ip}: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error clearing rate limit: {str(e)}"
        }), 500

def get_logs_by_ip(ip_address):
    """Get logs filtered by a specific IP address using safe parameterized queries"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Use parameterized query with proper placeholders
        cursor.execute(
            "SELECT * FROM proxy_logs WHERE source_ip = ? ORDER BY timestamp DESC LIMIT 1000", 
            (ip_address,)
        )
        
        logs = [dict(row) for row in cursor.fetchall()]
        
        return {
            "status": "success",
            "data": logs,
            "meta": {
                "count": len(logs),
                "ip": ip_address
            }
        }
    except Exception as e:
        logger.error(f"Error retrieving logs for IP {ip_address}: {str(e)}")
        return {
            "status": "error",
            "message": f"Error retrieving logs: {str(e)}"
        }

def validate_domain(domain):
    """Validate a domain name with better TLD checking"""
    # Check for wildcards and remove for validation
    is_wildcard = False
    clean_domain = domain
    
    if domain.startswith('*.'):
        is_wildcard = True
        clean_domain = domain[2:]  # Remove the wildcard part
    
    # Basic structure validation
    domain_pattern = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])+$'
    if not re.match(domain_pattern, clean_domain):
        return False
    
    # Check if TLD looks legitimate (at least 2 chars, not all numbers)
    parts = clean_domain.split('.')
    tld = parts[-1]
    
    # TLD shouldn't be all numbers and should be at least 2 chars
    if tld.isdigit() or len(tld) < 2:
        return False
    
    # Check for common TLDs (not exhaustive, but covers most)
    common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'me', 'info', 
                   'biz', 'app', 'dev', 'blog', 'ai', 'uk', 'us', 'ca', 'au', 'de', 'fr', 
                   'jp', 'ru', 'cn', 'in', 'br', 'it', 'pl', 'se', 'nl', 'mx', 'ch', 'at']
    
    # Either the TLD is common or it's at least valid from structural perspective
    return tld.lower() in common_tlds or re.match(r'^[a-zA-Z0-9]{2,}$', tld)

def validate_and_normalize_path(path, allowed_base_dirs=None):
    """
    Validate that a path doesn't contain traversal attempts and normalize it.
    
    Args:
        path: The path to validate and normalize
        allowed_base_dirs: Optional list of allowed base directories
        
    Returns:
        Normalized path or None if validation fails
    """
    try:
        # Normalize the path to resolve any ".." components
        normalized_path = os.path.normpath(path)
        
        # Check if the path tries to traverse outside allowed directories
        if '..' in normalized_path or normalized_path.startswith('../'):
            logger.warning(f"Path traversal attempt detected: {path}")
            return None
            
        # If allowed base directories are specified, validate against them
        if allowed_base_dirs:
            # Convert to absolute paths
            abs_path = os.path.abspath(normalized_path)
            if not any(abs_path.startswith(os.path.abspath(base_dir)) for base_dir in allowed_base_dirs):
                logger.warning(f"Path {path} is outside allowed directories")
                return None
                
        return normalized_path
    except Exception as e:
        logger.error(f"Error validating path {path}: {str(e)}")
        return None

def validate_request_data(data, required_fields=None, field_validators=None):
    """
    Validate that request data contains the required fields and passes custom validators.
    
    Args:
        data: The JSON request data to validate
        required_fields: List of field names that must be present in the data
        field_validators: Dict mapping field names to validator functions
        
    Returns:
        (is_valid, error_message) tuple
    """
    # Check if data is None or empty when fields are required
    if not data and required_fields:
        return False, "Request data is empty"
        
    # Check for required fields
    if required_fields:
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
                
    # Apply field-specific validators
    if field_validators and data:
        for field, validator in field_validators.items():
            if field in data:
                is_valid, error = validator(data[field])
                if not is_valid:
                    return False, f"Invalid {field}: {error}"
                    
    return True, None

def sanitize_url(url):
    """
    Sanitize a URL to prevent potential issues with special characters
    or encoding sequences that could cause problems.
    
    Args:
        url: The URL to sanitize
        
    Returns:
        Sanitized URL string safe for display and processing
    """
    if not url:
        return ""
        
    try:
        # Replace common problematic sequences
        sanitized = url.replace('\0', '')  # Remove null bytes
        
        # Handle potential HTML entities and script tags
        sanitized = sanitized.replace('<', '&lt;').replace('>', '&gt;')
        
        # Clean up any multi-encoding attempts
        sanitized = re.sub(r'%(?:%)+', '%', sanitized)
        
        # Reduce multiple slashes to single slashes (except after protocol)
        sanitized = re.sub(r'(?<!:)/{2,}', '/', sanitized)
        
        # Limit length to prevent DoS
        if len(sanitized) > 2048:  # Standard URL length limit
            sanitized = sanitized[:2048] + "..."
            
        return sanitized
    except Exception as e:
        logger.error(f"Error sanitizing URL: {str(e)}")
        return "[INVALID URL]"

def safe_write_file(target_path, content, mode="w"):
    """
    Safely write content to a file using a temporary file first to prevent 
    race conditions and partial writes.
    
    Args:
        target_path: Path to the final file location
        content: Content to write to the file
        mode: File mode ("w" for text, "wb" for binary)
        
    Returns:
        Boolean indicating success or failure
    """
    import tempfile
    import shutil
    import os
    
    # Ensure the directory exists
    target_dir = os.path.dirname(target_path)
    if target_dir and not os.path.exists(target_dir):
        try:
            os.makedirs(target_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create directory {target_dir}: {e}")
            return False
    
    try:
        # Create a temporary file in the same directory as the target
        fd, temp_path = tempfile.mkstemp(dir=target_dir)
        
        try:
            # Write content to temporary file
            with os.fdopen(fd, mode) as f:
                f.write(content)
            
            # Set the same permissions as the original file if it exists
            if os.path.exists(target_path):
                # Get original file stats
                file_stat = os.stat(target_path)
                # Apply same permissions to temp file
                os.chmod(temp_path, file_stat.st_mode)
                # If possible, match ownership too (may require root)
                try:
                    os.chown(temp_path, file_stat.st_uid, file_stat.st_gid)
                except (AttributeError, PermissionError):
                    pass  # Skip ownership matching if not supported or not permitted
            
            # Rename the temporary file to the target (atomic on POSIX)
            shutil.move(temp_path, target_path)
            
            return True
        except Exception as e:
            # Clean up the temporary file if something went wrong
            os.unlink(temp_path)
            raise e
    except Exception as e:
        logger.error(f"Failed to safely write to {target_path}: {e}")
        return False

# Security event logging
def log_security_event(event_type, message, details=None, level="warning"):
    """
    Log security-relevant events with proper categorization and details
    
    Args:
        event_type: Type of security event (auth, access, blacklist, config)
        message: Message describing the event
        details: Additional details about the event (dict)
        level: Log level (info, warning, error)
    """
    if details is None:
        details = {}
        
    # Add client IP and timestamp
    client_ip = getattr(request, 'remote_addr', 'unknown')
    timestamp = datetime.now().isoformat()
    
    # Add username if authenticated
    username = None
    try:
        username = auth.current_user()
    except:
        pass
        
    event = {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "username": username,
        "event_type": event_type,
        "message": message,
        **details
    }
    
    # Log using appropriate level
    log_message = f"SECURITY EVENT [{event_type.upper()}]: {message} - {json.dumps(details)}"
    if level == "info":
        logger.info(log_message)
    elif level == "error":
        logger.error(log_message)
    else:
        logger.warning(log_message)
        
    # In a more advanced system, we might want to:
    # 1. Write to a dedicated security log file
    # 2. Store security events in a database table
    # 3. Send alerts for critical events
    
    # Store in security_events table if it exists
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            client_ip TEXT,
            message TEXT NOT NULL,
            details TEXT
        )
        """)
        conn.commit()
        
        # Insert the event
        cursor.execute("""
        INSERT INTO security_events 
        (timestamp, event_type, username, client_ip, message, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            timestamp, 
            event_type, 
            username, 
            client_ip, 
            message, 
            json.dumps(details)
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to store security event: {str(e)}")
        
    return event

@app.route('/api/docs', methods=['GET'])
@auth.login_required
def get_api_docs():
    """Get documentation for all API endpoints"""
    api_docs = {
        "version": "1.0.0",
        "base_url": "/api",
        "endpoints": [
            {
                "path": "/status",
                "method": "GET",
                "description": "Get current proxy service status",
                "auth_required": True,
                "parameters": [],
                "response": {
                    "status": "Success status",
                    "data": {
                        "proxy_status": "running|error",
                        "timestamp": "ISO timestamp",
                        "version": "API version"
                    }
                }
            },
            {
                "path": "/settings",
                "method": "GET",
                "description": "Get all proxy settings",
                "auth_required": True,
                "parameters": [],
                "response": {
                    "status": "Success status",
                    "data": [
                        {
                            "id": "Setting ID",
                            "setting_name": "Setting name",
                            "setting_value": "Setting value",
                            "description": "Setting description"
                        }
                    ]
                }
            },
            {
                "path": "/settings/{setting_name}",
                "method": "PUT",
                "description": "Update a specific setting",
                "auth_required": True,
                "csrf_protected": True,
                "parameters": [
                    {
                        "name": "value",
                        "type": "string",
                        "description": "New value for the setting",
                        "required": True
                    }
                ],
                "response": {
                    "status": "Success status",
                    "message": "Result message"
                }
            },
            # Add documentation for IP blacklist endpoints
            {
                "path": "/ip-blacklist",
                "method": "GET",
                "description": "Get all blacklisted IPs",
                "auth_required": True,
                "parameters": [],
                "response": {
                    "status": "Success status",
                    "data": [
                        {
                            "id": "Entry ID",
                            "ip": "IP address or CIDR",
                            "description": "Description",
                            "added_date": "Date added"
                        }
                    ]
                }
            },
            {
                "path": "/ip-blacklist",
                "method": "POST",
                "description": "Add an IP to the blacklist",
                "auth_required": True,
                "csrf_protected": True,
                "parameters": [
                    {
                        "name": "ip",
                        "type": "string",
                        "description": "IP address or CIDR notation",
                        "required": True
                    },
                    {
                        "name": "description",
                        "type": "string",
                        "description": "Description or reason for blacklisting",
                        "required": False
                    }
                ],
                "response": {
                    "status": "Success status",
                    "message": "Result message"
                }
            },
            # Add documentation for logs endpoints
            {
                "path": "/logs",
                "method": "GET",
                "description": "Get proxy logs with pagination and filtering",
                "auth_required": True,
                "parameters": [
                    {
                        "name": "limit",
                        "type": "integer",
                        "description": "Maximum number of logs to return (default: 100, max: 1000)",
                        "required": False
                    },
                    {
                        "name": "offset",
                        "type": "integer",
                        "description": "Offset for pagination (default: 0)",
                        "required": False
                    },
                    {
                        "name": "search",
                        "type": "string",
                        "description": "Search term to filter logs",
                        "required": False
                    },
                    {
                        "name": "sort",
                        "type": "string",
                        "description": "Field to sort by (timestamp, source_ip, destination, status, bytes)",
                        "required": False
                    },
                    {
                        "name": "order",
                        "type": "string",
                        "description": "Sort order (asc, desc)",
                        "required": False
                    }
                ],
                "response": {
                    "status": "Success status",
                    "data": "Array of log entries",
                    "meta": {
                        "total": "Total count of matching logs",
                        "limit": "Current limit value",
                        "offset": "Current offset value",
                        "sort": "Current sort field",
                        "order": "Current sort order"
                    }
                }
            },
            # Security-related endpoints
            {
                "path": "/security/rate-limits",
                "method": "GET",
                "description": "Get current rate limit status for all IPs",
                "auth_required": True,
                "parameters": [],
                "response": {
                    "status": "Success status",
                    "data": "Array of rate limit records by IP",
                    "meta": {
                        "max_attempts": "Maximum allowed attempts",
                        "window_seconds": "Rate limit window duration in seconds"
                    }
                }
            },
            # Maintenance endpoints
            {
                "path": "/maintenance/check-cert-security",
                "method": "GET",
                "description": "Check security of SSL certificates used for HTTPS filtering",
                "auth_required": True,
                "parameters": [],
                "response": {
                    "status": "Success status",
                    "message": "Result message",
                    "details": "Array of certificate issues (if any)"
                }
            }
        ]
    }
    
    return jsonify({
        "status": "success",
        "data": api_docs
    })
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)