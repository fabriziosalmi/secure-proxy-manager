from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
import sqlite3
import os
import subprocess
import logging
import json
from datetime import datetime
import requests
import threading
import time

# Initialize Flask app
app = Flask(__name__)
CORS(app)
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
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                      ('admin', 'admin'))  # Default password - would be hashed in production
    
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

# Authentication
@auth.verify_password
def verify_password(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if user and user['password'] == password:  # In production, use password hashing
        return username
    return None

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
def update_setting(setting_name):
    """Update a specific setting"""
    data = request.get_json()
    if not data or 'value' not in data:
        return jsonify({"status": "error", "message": "No value provided"}), 400
    
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

@app.route('/api/ip-blacklist', methods=['POST'])
@auth.login_required
def add_ip_to_blacklist():
    """Add an IP to the blacklist"""
    data = request.get_json()
    if not data or 'ip' not in data:
        return jsonify({"status": "error", "message": "No IP provided"}), 400
    
    description = data.get('description', '')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)", 
                      (data['ip'], description))
        conn.commit()
        
        # Update blacklist file
        update_ip_blacklist()
        
        return jsonify({"status": "success", "message": "IP added to blacklist"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "IP already in blacklist"}), 400

@app.route('/api/ip-blacklist/<int:id>', methods=['DELETE'])
@auth.login_required
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
def add_domain_to_blacklist():
    """Add a domain to the blacklist"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"status": "error", "message": "No domain provided"}), 400
    
    description = data.get('description', '')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO domain_blacklist (domain, description) VALUES (?, ?)", 
                      (data['domain'], description))
        conn.commit()
        
        # Update blacklist file
        update_domain_blacklist()
        
        return jsonify({"status": "success", "message": "Domain added to blacklist"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Domain already in blacklist"}), 400

@app.route('/api/domain-blacklist/<int:id>', methods=['DELETE'])
@auth.login_required
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
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM proxy_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", 
                  (limit, offset))
    logs = [dict(row) for row in cursor.fetchall()]
    
    # Get total count
    cursor.execute("SELECT COUNT(*) FROM proxy_logs")
    total = cursor.fetchone()[0]
    
    return jsonify({
        "status": "success", 
        "data": logs,
        "meta": {
            "total": total,
            "limit": limit,
            "offset": offset
        }
    })

@app.route('/api/logs/import', methods=['POST'])
@auth.login_required
def import_logs():
    """Import logs from Squid access.log"""
    try:
        parse_squid_logs()
        return jsonify({"status": "success", "message": "Logs imported successfully"})
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

# New maintenance endpoints
@app.route('/api/maintenance/clear-cache', methods=['POST'])
@auth.login_required
def clear_cache():
    """Clear the Squid cache"""
    try:
        # Execute squid command to clear cache
        result = subprocess.run(
            ['docker', 'exec', 'secure-proxy-proxy-1', 'squidclient', '-h', 'localhost', 'mgr:shutdown'],
            capture_output=True, text=True, check=True
        )
        logger.info("Cache cleared successfully")
        return jsonify({"status": "success", "message": "Cache cleared successfully"})
    except subprocess.CalledProcessError as e:
        logger.error(f"Error clearing cache: {str(e)}")
        return jsonify({"status": "error", "message": f"Error clearing cache: {str(e)}"}), 500

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
def restore_config():
    """Restore configuration from a backup file"""
    try:
        data = request.get_json()
        if not data or 'backup' not in data:
            return jsonify({"status": "error", "message": "No backup data provided"}), 400
        
        backup = data['backup']
        conn = get_db()
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
            
            # Commit the transaction
            conn.commit()
            
            # Update blacklist files
            update_ip_blacklist()
            update_domain_blacklist()
            
            # Apply settings
            apply_settings()
            
            return jsonify({"status": "success", "message": "Configuration restored successfully"})
        except Exception as e:
            # Rollback in case of error
            conn.rollback()
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
    
    # Write to config file
    with open('/config/ip_blacklist.txt', 'w') as f:
        f.write('\n'.join(ips))
    
    logger.info("IP blacklist updated")

@app.route('/api/logs/clear', methods=['POST'])
@auth.login_required
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
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM domain_blacklist")
    domains = [row['domain'] for row in cursor.fetchall()]
    
    # Write to config file
    with open('/config/domain_blacklist.txt', 'w') as f:
        f.write('\n'.join(domains))
    
    logger.info("Domain blacklist updated")

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
        squid_conf.append("")
        
        # IP and Domain blacklists
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
        squid_conf.append('acl direct_ip_url url_regex -i ^https?://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)')
        squid_conf.append('acl direct_ip_host dstdom_regex -i ^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$')
        # IPv6 detection
        squid_conf.append('acl direct_ipv6_url url_regex -i ^https?://\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]')
        squid_conf.append('acl direct_ipv6_host dstdom_regex -i ^\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]$')
        
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
            subprocess.run(
                ['docker', 'restart', 'secure-proxy-proxy-1'],
                capture_output=True, check=True, timeout=20
            )
            logger.info("Proxy container restarted successfully")
            
            # Wait for the container to come up
            time.sleep(5)
            
            return success
        except Exception as e:
            logger.error(f"Error restarting proxy container: {str(e)}")
            return success and True  # Return True if we at least wrote a configuration file
            
    except Exception as e:
        logger.error(f"Error applying settings: {str(e)}")
        return False

def parse_squid_logs():
    """Parse Squid access logs and import to database"""
    log_path = '/logs/access.log'
    
    if not os.path.exists(log_path):
        logger.warning(f"Log file not found: {log_path}")
        return
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Clear existing logs before importing
    cursor.execute("DELETE FROM proxy_logs")
    
    # Parse Squid log format matching your actual log format
    with open(log_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 9:
                try:
                    timestamp = float(parts[0])  # Convert timestamp to human-readable format
                    elapsed = parts[1]
                    source_ip = parts[2]
                    status_code = parts[3]
                    bytes = int(parts[4])
                    method = parts[5]
                    url = parts[6]
                    
                    # Convert Unix timestamp to datetime
                    readable_time = datetime.fromtimestamp(timestamp).isoformat()
                    
                    cursor.execute("""
                    INSERT INTO proxy_logs (timestamp, source_ip, destination, status, bytes)
                    VALUES (?, ?, ?, ?, ?)
                    """, (readable_time, source_ip, url, status_code, bytes))
                except (ValueError, IndexError) as e:
                    logger.error(f"Error parsing log line: {line.strip()} - {str(e)}")
                    continue
    
    conn.commit()
    logger.info("Squid logs imported to database")

# Add background log parser
def background_log_parser():
    """Parse logs in the background periodically"""
    while True:
        try:
            parse_squid_logs()
            logger.info("Background log parsing completed")
        except Exception as e:
            logger.error(f"Error in background log parsing: {str(e)}")
        
        # Parse logs every 30 seconds
        time.sleep(30)

# Start the background log parser in a separate thread
log_parser_thread = threading.Thread(target=background_log_parser, daemon=True)
log_parser_thread.start()

# Initialize the application
init_db()

# Apply settings on startup to ensure proper configuration
try:
    update_ip_blacklist()
    update_domain_blacklist()
    apply_settings()
    logger.info("Initial settings applied")
except Exception as e:
    logger.error(f"Error applying initial settings: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)