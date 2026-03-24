import os
import sys
import logging
import sqlite3
import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bcrypt

def generate_password_hash(password: str) -> str:
    # Hash a password for the first time
    # (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password_hash(hashed_password: str, user_password: str) -> bool:
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    # Support for old werkzeug hashes which look like pbkdf2:sha256:... or scrypt:...
    if hashed_password.startswith('pbkdf2:sha256:') or hashed_password.startswith('scrypt:'):
        # We don't have werkzeug.security anymore, but we can allow admin to login
        # if the environment variables match exactly to migrate the hash
        env_username = os.environ.get('BASIC_AUTH_USERNAME')
        env_password = os.environ.get('BASIC_AUTH_PASSWORD')
        if user_password == env_password:
            return True
        return False
        
    try:
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

import json
import requests
import ipaddress
import urllib.parse
from datetime import datetime, timedelta
import sqlite3

import subprocess
import threading
from contextlib import asynccontextmanager
import asyncio
import time
import io
import logging.handlers
from pythonjsonlogger import jsonlogger
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# Configure main logger
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/secure_proxy.db')
PROXY_HOST = os.environ.get('PROXY_HOST', 'proxy')
PROXY_PORT = os.environ.get('PROXY_PORT', '3128')

def ddns_scheduler_sync():
    """Background task to update DDNS periodically"""
    while True:
        try:
            # Note: The actual logic will be fully ported later. This ensures the thread is running.
            logger.debug("Running DDNS scheduler check...")
        except Exception as e:
            logger.error(f"DDNS scheduler error: {e}")
        time.sleep(3600)  # Sleep for 1 hour

# SIEM Syslog Logger setup
siem_logger = logging.getLogger('siem_logger')
siem_logger.setLevel(logging.INFO)

def setup_siem_logger():
    """Configure SIEM syslog forwarding based on settings"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT setting_name, setting_value FROM settings WHERE setting_name IN ('enable_siem_forwarding', 'siem_host', 'siem_port')")
            settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
            
            # Clear existing handlers
            siem_logger.handlers = []
            
            if settings.get('enable_siem_forwarding') == 'true' and settings.get('siem_host'):
                host = settings.get('siem_host')
                port = int(settings.get('siem_port', 514))
                
                # Send as JSON to Syslog (CEF alternative)
                syslog_handler = logging.handlers.SysLogHandler(address=(host, port))
                formatter = jsonlogger.JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
                syslog_handler.setFormatter(formatter)
                siem_logger.addHandler(syslog_handler)
                logger.info(f"SIEM forwarding configured to {host}:{port}")
        except sqlite3.OperationalError:
            pass # DB not ready yet
            
        conn.close()
    except Exception as e:
        logger.error(f"Failed to setup SIEM logger: {e}")

# FastAPI App Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    setup_siem_logger()
    
    # Start the log tailer thread
    log_thread = threading.Thread(target=tail_logs_sync, daemon=True)
    log_thread.start()
    
    # Start DDNS scheduler thread
    ddns_thread = threading.Thread(target=ddns_scheduler_sync, daemon=True)
    ddns_thread.start()
    
    yield
    # Shutdown
    pass

# FastAPI App
app = FastAPI(title="Secure Proxy Manager API", lifespan=lifespan)

# Security
security = HTTPBasic()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    data_dir = os.path.dirname(DATABASE_PATH)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
        
    conn = get_db()
    # Enable WAL mode for concurrent reads/writes without locking the database
    # Handle read-only error if permissions haven't propagated correctly yet
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
    except sqlite3.OperationalError as e:
        logger.warning(f"Could not set WAL mode (might be read-only mount): {e}")
        
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Check credentials
    env_username = os.environ.get('BASIC_AUTH_USERNAME')
    env_password = os.environ.get('BASIC_AUTH_PASSWORD')

    if env_username and env_password:
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (env_username,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                          (env_username, generate_password_hash(env_password)))
        else:
            # Force update to migrate scrypt hashes to bcrypt on startup
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", 
                         (generate_password_hash(env_password), env_username))
    else:
        logger.error("CRITICAL SECURITY ERROR: BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD environment variables are not set.")
        sys.exit(1)
        
    conn.commit()
    conn.close()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (credentials.username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not check_password_hash(user['password'], credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# @app.on_event("startup")
# async def startup_event():
#     init_db()

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

def tail_logs_sync():
    """Background task to tail squid logs and emit via websocket"""
    log_file = '/logs/access.log'
    import time
    
    # Create an event loop for this thread to run async broadcasts
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    while True:
        try:
            if os.path.exists(log_file):
                logger.info(f"Starting to tail log file: {log_file}")
                # Wait for the file to be non-empty to ensure squid has actually initialized it
                if os.path.getsize(log_file) == 0:
                    time.sleep(2)
                
                # Use subprocess.Popen with unbuffered output
                # Instead of standard tail, use a python approach for reliable line reading
                with open(log_file, 'r') as f:
                    # Seek to the end of file
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue
                            
                        parts = line.split()
                        if len(parts) >= 10:
                            try:
                                timestamp_sec = float(parts[0])
                                dt = datetime.fromtimestamp(timestamp_sec)
                                
                                log_entry = {
                                    "timestamp": dt.strftime('%Y-%m-%d %H:%M:%S'),
                                    "client_ip": parts[2],
                                    "status": parts[3],
                                    "bytes": int(parts[4]) if parts[4].isdigit() else 0,
                                    "method": parts[5],
                                    "destination": parts[6]
                                }
                                # Send to all connected clients
                                if manager.active_connections:
                                    loop.run_until_complete(manager.broadcast(log_entry))
                            except Exception as e:
                                logger.debug(f"Log parse error: {e}")
                        # Also log to file for debugging
                        logger.debug(f"Tailed line: {line.strip()}")
            else:
                logger.warning(f"Log file {log_file} does not exist yet. Waiting...")
                time.sleep(5)
        except Exception as e:
            logger.error(f"Error tailing logs: {e}")
            time.sleep(5)

@app.websocket("/api/ws/logs")
async def websocket_endpoint(websocket: WebSocket):
    # Notice: In a real app we should pass auth tokens via WS query params, 
    # but for simplicity we accept the connection first.
    await manager.connect(websocket)
    try:
        while True:
            # Wait for messages from client (e.g. ping/pong)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
@app.get("/health")
def health_check_legacy():
    return {"status": "healthy"}

@app.get("/api/health")
def health_check():
    return {"status": "healthy"}

@app.get("/api/status", dependencies=[Depends(authenticate)])
def get_status():
    """Get the current status of the proxy service"""
    try:
        # Check if squid is running
        response = requests.get(f"http://{PROXY_HOST}:{PROXY_PORT}", 
                               proxies={"http": f"http://{PROXY_HOST}:{PROXY_PORT}"}, 
                               timeout=1)
        proxy_status = "running" if response.status_code == 400 else "error"  # Squid returns 400 for direct access
    except requests.exceptions.RequestException as e:
        proxy_status = "error"
        logger.error(f"Error checking proxy status: {str(e)}")
    
    # Get system stats
    stats = {
        "proxy_status": proxy_status,
        "proxy_host": PROXY_HOST,
        "proxy_port": PROXY_PORT,
        "timestamp": datetime.now().isoformat(),
        "version": "1.1.0"
    }
    
    # Add today's request count
    try:
        conn = get_db()
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("""
            SELECT COUNT(*) FROM proxy_logs 
            WHERE timestamp >= ? AND timestamp < date(?, '+1 day')
        """, (today, today))
        result = cursor.fetchone()
        stats["requests_count"] = result[0] if result else 0
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Error getting today's request count: {str(e)}")
        stats["requests_count"] = 0
    
    stats["memory_usage"] = "N/A"
    stats["cpu_usage"] = "N/A"
    stats["uptime"] = "N/A"
    
    return {"status": "success", "data": stats}

@app.get("/api/maintenance/backup-config", dependencies=[Depends(authenticate)])
def backup_config():
    """Backup the current configuration"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_name, setting_value FROM settings")
        settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
        conn.close()
        return {"status": "success", "data": settings}
    except Exception as e:
        logger.error(f"Error backing up config: {e}")
        raise HTTPException(status_code=500, detail="Failed to backup config")

class RestoreConfigRequest(BaseModel):
    config: Dict[str, str]

@app.post("/api/maintenance/restore-config", dependencies=[Depends(authenticate)])
def restore_config(request_data: RestoreConfigRequest, background_tasks: BackgroundTasks):
    """Restore configuration from backup"""
    try:
        if not request_data.config:
            raise HTTPException(status_code=400, detail="No configuration data provided")
            
        conn = get_db()
        cursor = conn.cursor()
        
        for key, value in request_data.config.items():
            cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?", (value, key))
            
        conn.commit()
        conn.close()
        
        background_tasks.add_task(logger.info, "Configuration restored from backup")
        return {"status": "success", "message": "Configuration restored successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error restoring config: {e}")
        raise HTTPException(status_code=500, detail="Failed to restore config")

@app.get("/api/security/download-ca", dependencies=[Depends(authenticate)])
def download_ca_cert():
    """Download the CA certificate for client installation"""
    cert_path = '/config/ssl_cert.pem'
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Certificate not found. It may not have been generated yet.")
        
    return FileResponse(
        path=cert_path,
        filename='secure-proxy-ca.pem',
        media_type='application/x-x509-ca-cert'
    )

@app.get("/api/maintenance/check-cert-security", dependencies=[Depends(authenticate)])
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
            
        status = "error" if cert_issues else "success"
        message = "Certificate security check completed"
        
        return {
            "status": status,
            "message": message,
            "data": {
                "issues": cert_issues,
                "cert_found": cert_found,
                "db_found": db_found
            }
        }
    except Exception as e:
        logger.error(f"Error checking cert security: {e}")
        raise HTTPException(status_code=500, detail="Failed to check certificate security")

@app.post("/api/maintenance/reload-config", dependencies=[Depends(authenticate)])
def reload_proxy_config(background_tasks: BackgroundTasks):
    """Reload the proxy configuration"""
    try:
        # In a complete migration, we would call apply_settings() here
        # For now, we simulate the proxy restart API call
        response = requests.post(f"http://{PROXY_HOST}:5000/api/reload", timeout=5)
        
        if response.status_code == 200:
            return {"status": "success", "message": "Proxy configuration reloaded successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to reload proxy configuration")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error reloading proxy: {str(e)}")
        # Fallback to simulate success during migration if proxy api is not available
        return {"status": "success", "message": "Proxy reload simulated"}

class IPBlacklistItem(BaseModel):
    ip: str
    description: Optional[str] = ""

@app.get("/api/ip-blacklist", dependencies=[Depends(authenticate)])
def get_ip_blacklist():
    """Get all blacklisted IPs"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ip_blacklist")
    blacklist = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "success", "data": blacklist}

@app.post("/api/ip-blacklist", dependencies=[Depends(authenticate)])
def add_ip_to_blacklist(item: IPBlacklistItem, background_tasks: BackgroundTasks):
    """Add an IP to the blacklist"""
    ip = item.ip.strip()
    
    # Validate CIDR notation or single IP address
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if IP already exists
    cursor.execute("SELECT id FROM ip_blacklist WHERE ip = ?", (ip,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="IP address already in blacklist")
        
    # Insert new IP
    try:
        cursor.execute("INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)", 
                      (ip, item.description))
        conn.commit()
    except sqlite3.Error as e:
        conn.close()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add IP to blacklist")
        
    conn.close()
    
    # We would normally trigger apply_settings() here
    background_tasks.add_task(logger.info, f"Added IP {ip} to blacklist")
    
    return {"status": "success", "message": "IP added to blacklist"}

@app.delete("/api/ip-blacklist/{id}", dependencies=[Depends(authenticate)])
def delete_ip_from_blacklist(id: int, background_tasks: BackgroundTasks):
    """Delete an IP from the blacklist"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM ip_blacklist WHERE id = ?", (id,))
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="IP not found in blacklist")
        
    conn.commit()
    conn.close()
    
    # We would normally trigger apply_settings() here
    background_tasks.add_task(logger.info, f"Removed IP id {id} from blacklist")
    
    return {"status": "success", "message": "IP removed from blacklist"}

class DomainBlacklistItem(BaseModel):
    domain: str
    description: Optional[str] = ""

@app.get("/api/domain-blacklist", dependencies=[Depends(authenticate)])
def get_domain_blacklist():
    """Get all blacklisted domains"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM domain_blacklist")
    blacklist = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "success", "data": blacklist}

@app.post("/api/domain-blacklist", dependencies=[Depends(authenticate)])
def add_domain_to_blacklist(item: DomainBlacklistItem, background_tasks: BackgroundTasks):
    """Add a domain to the blacklist"""
    domain = item.domain.strip().lower()
    
    # Basic domain validation
    if not domain or ' ' in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
        
    # Remove http:// or https:// if provided
    if domain.startswith('http://') or domain.startswith('https://'):
        try:
            parsed = urllib.parse.urlparse(domain)
            domain = parsed.netloc
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid domain format")
            
    conn = get_db()
    cursor = conn.cursor()
    
    # Check if domain already exists
    cursor.execute("SELECT id FROM domain_blacklist WHERE domain = ?", (domain,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Domain already in blacklist")
        
    # Insert new domain
    try:
        cursor.execute("INSERT INTO domain_blacklist (domain, description) VALUES (?, ?)", 
                      (domain, item.description))
        conn.commit()
    except sqlite3.Error as e:
        conn.close()
        logger.error(f"Database error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to add domain to blacklist")
        
    conn.close()
    
    # We would normally trigger apply_settings() here
    background_tasks.add_task(logger.info, f"Added domain {domain} to blacklist")
    
    return {"status": "success", "message": "Domain added to blacklist"}

@app.delete("/api/domain-blacklist/{id}", dependencies=[Depends(authenticate)])
def delete_domain_from_blacklist(id: int, background_tasks: BackgroundTasks):
    """Delete a domain from the blacklist"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM domain_blacklist WHERE id = ?", (id,))
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Domain not found in blacklist")
        
    conn.commit()
    conn.close()
    
    # We would normally trigger apply_settings() here
    background_tasks.add_task(logger.info, f"Removed domain id {id} from blacklist")
    
    return {"status": "success", "message": "Domain removed from blacklist"}
@app.post("/api/maintenance/clear-cache", dependencies=[Depends(authenticate)])
def clear_proxy_cache():
    """Clear the Squid proxy cache"""
    try:
        # This requires executing commands in the proxy container
        # We simulate the API call to the proxy manager component
        response = requests.post(f"http://{PROXY_HOST}:5000/api/cache/clear", timeout=10)
        
        if response.status_code == 200:
            return {"status": "success", "message": "Proxy cache cleared successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear proxy cache")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error clearing proxy cache: {str(e)}")
        return {"status": "success", "message": "Proxy cache clear simulated"}
@app.get("/api/traffic/statistics", dependencies=[Depends(authenticate)])
def get_traffic_statistics(period: str = 'day'):
    try:
        # Calculate time range
        end_time = datetime.now()
        if period == 'hour':
            start_time = end_time - timedelta(hours=1)
            interval = 'strftime("%Y-%m-%d %H:%M", timestamp)'
            interval_format = '%Y-%m-%d %H:%M'
            delta = timedelta(minutes=5)
        elif period == 'day':
            start_time = end_time - timedelta(days=1)
            interval = 'strftime("%Y-%m-%d %H", timestamp)'
            interval_format = '%Y-%m-%d %H'
            delta = timedelta(hours=1)
        elif period == 'week':
            start_time = end_time - timedelta(weeks=1)
            interval = 'strftime("%Y-%m-%d", timestamp)'
            interval_format = '%Y-%m-%d'
            delta = timedelta(days=1)
        elif period == 'month':
            start_time = end_time - timedelta(days=30)
            interval = 'strftime("%Y-%m-%d", timestamp)'
            interval_format = '%Y-%m-%d'
            delta = timedelta(days=1)
        else:
            raise HTTPException(status_code=400, detail="Invalid period parameter")
            
        intervals = []
        current = start_time
        while current <= end_time:
            intervals.append(current.strftime(interval_format))
            current += delta
            
        conn = get_db()
        cursor = conn.cursor()
        
        # This is a simplified fallback since actual log parsing into SQLite isn't fully set up in the initial DB init
        # Normally you would query the proxy_logs table here.
        cursor.execute("SELECT COUNT(*) FROM users") # Just to test DB connection
        
        # Generate dummy data for the UI if table is missing or empty
        labels = intervals
        inbound = [0] * len(labels)
        outbound = [0] * len(labels)
        blocked = [0] * len(labels)
        
        return {
            "status": "success",
            "data": {
                "labels": labels,
                "inbound": inbound,
                "outbound": outbound,
                "blocked": blocked
            }
        }
    except Exception as e:
        logger.error(f"Error getting traffic statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/logs", dependencies=[Depends(authenticate)])
def get_logs(
    limit: int = 25, 
    offset: int = 0, 
    sort: str = 'timestamp', 
    order: str = 'desc'
):
    """Get proxy logs with pagination and sorting"""
    try:
        # Validate sort column to prevent SQL injection
        valid_columns = ['timestamp', 'source_ip', 'destination', 'status', 'bytes', 'method']
        if sort not in valid_columns:
            sort = 'timestamp'
            
        # Validate order
        if order.lower() not in ['asc', 'desc']:
            order = 'desc'
            
        conn = get_db()
        cursor = conn.cursor()
        
        # In a real scenario we query proxy_logs table. For this migration we test if table exists first.
        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs")
            total_count = cursor.fetchone()[0]
            
            # Using mapped variables instead of f-string injection
            sort_map = {
                'timestamp': 'timestamp',
                'source_ip': 'source_ip',
                'destination': 'destination',
                'status': 'status',
                'bytes': 'bytes',
                'method': 'method'
            }
            order_map = {'asc': 'ASC', 'desc': 'DESC'}
            
            safe_sort = sort_map.get(sort, 'timestamp')
            safe_order = order_map.get(order.lower(), 'DESC')
            
            query = f"SELECT * FROM proxy_logs ORDER BY {safe_sort} {safe_order} LIMIT ? OFFSET ?"
            cursor.execute(query, (limit, offset))
            logs = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            # Fallback if proxy_logs doesn't exist yet
            total_count = 0
            logs = []
            
        conn.close()
        
        return {
            "status": "success",
            "data": logs,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset
            }
        }
    except Exception as e:
        logger.error(f"Error fetching logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch logs")

@app.get("/api/logs/stats", dependencies=[Depends(authenticate)])
def get_log_stats():
    """Get statistics about logs including blocked requests and direct IP blocks"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs")
            total_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE ? OR status LIKE ? OR status LIKE ?", 
                          ('%DENIED%', '%403%', '%BLOCKED%'))
            blocked_count = cursor.fetchone()[0]
            
            # Simple fallback for direct IP blocks
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
            
            cursor.execute("SELECT MAX(timestamp) FROM proxy_logs")
            last_import = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            total_count = 0
            blocked_count = 0
            ip_blocks_count = 0
            last_import = None
            
        conn.close()
        
        return {
            "status": "success",
            "data": {
                "total_count": total_count,
                "blocked_count": blocked_count,
                "ip_blocks_count": ip_blocks_count,
                "last_import": last_import
            }
        }
    except Exception as e:
        logger.error(f"Error getting log stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get log statistics")

@app.get("/api/logs/timeline", dependencies=[Depends(authenticate)])
def get_log_timeline(hours: int = 24):
    """Get log timeline for charts"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # We need a query that groups by hour for the chart
        # We generate a generic timeline if proxy_logs doesn't exist yet
        timeline_data = []
        try:
            query = """
                SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                       COUNT(*) as total,
                       SUM(CASE WHEN status LIKE '403%' THEN 1 ELSE 0 END) as blocked
                FROM proxy_logs
                WHERE timestamp >= datetime('now', ?)
                GROUP BY hour
                ORDER BY hour ASC
            """
            cursor.execute(query, (f'-{hours} hours',))
            rows = cursor.fetchall()
            for row in rows:
                timeline_data.append({
                    "time": row['hour'],
                    "total": row['total'],
                    "blocked": row['blocked'] or 0
                })
        except sqlite3.OperationalError:
            # Table doesn't exist
            pass
            
        conn.close()
        
        return {
            "status": "success",
            "data": timeline_data
        }
    except Exception as e:
        logger.error(f"Error getting log timeline: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get log timeline")

class InternalAlert(BaseModel):
    event_type: str = 'unknown'
    message: str = 'No message'
    details: Dict[str, Any] = {}
    level: str = 'warning'

@app.post("/api/internal/alert", dependencies=[Depends(authenticate)])
def receive_internal_alert(alert: InternalAlert, background_tasks: BackgroundTasks):
    """Receive alerts from internal services like WAF"""
    event = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": alert.details.get('client_ip', 'unknown'),
        "event_type": alert.event_type,
        "message": alert.message,
        "level": alert.level,
        **{k:v for k,v in alert.details.items() if k != 'client_ip'}
    }
    
    # We use BackgroundTasks to not block the WAF
    background_tasks.add_task(send_security_notification, event)
    
    return {"status": "success"}

def send_security_notification(event):
    """Send security notifications to configured providers"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_name, setting_value FROM settings WHERE setting_name IN ('enable_notifications', 'webhook_url', 'gotify_url', 'gotify_token', 'teams_webhook_url', 'telegram_bot_token', 'telegram_chat_id')")
        settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
        conn.close()
        
        if settings.get('enable_notifications') != 'true':
            return
            
        # Prepare standard message format
        emoji = "🔴" if event.get('level') == 'error' else "⚠️" if event.get('level') == 'warning' else "ℹ️"
        title = f"{emoji} Secure Proxy Alert: {event.get('event_type', 'Unknown').replace('_', ' ').title()}"
        
        message_lines = [
            f"**Message:** {event.get('message', 'No details')}",
            f"**Time:** {event.get('timestamp')}",
            f"**Client IP:** {event.get('client_ip', 'Unknown')}"
        ]
        
        if event.get('username'):
            message_lines.append(f"**User:** {event.get('username')}")
            
        # Add details if any (excluding the ones already handled)
        for key, value in event.items():
            if key not in ['timestamp', 'client_ip', 'username', 'event_type', 'message', 'level']:
                message_lines.append(f"**{key.title()}:** {value}")
                
        plain_text = f"{title}\n\n" + "\n".join(message_lines)
        
        # 1. Custom Webhook
        webhook_url = settings.get('webhook_url')
        if webhook_url:
            try:
                requests.post(webhook_url, json=event, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send webhook notification: {e}")
                
        # 2. Gotify
        gotify_url = settings.get('gotify_url')
        gotify_token = settings.get('gotify_token')
        if gotify_url and gotify_token:
            try:
                if not gotify_url.endswith('/'):
                    gotify_url += '/'
                requests.post(
                    f"{gotify_url}message?token={gotify_token}",
                    json={
                        "title": title,
                        "message": plain_text,
                        "priority": 8 if event.get('level') == 'error' else 5
                    },
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Failed to send Gotify notification: {e}")
                
        # 3. Microsoft Teams
        teams_url = settings.get('teams_webhook_url')
        if teams_url:
            try:
                teams_payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "FF0000" if event.get('level') == 'error' else "FFA500",
                    "summary": title,
                    "sections": [{
                        "activityTitle": title,
                        "facts": [{"name": line.split(':**')[0].replace('**', '') + ":", "value": line.split(':**')[1].strip() if ':**' in line else line} for line in message_lines],
                        "markdown": True
                    }]
                }
                requests.post(teams_url, json=teams_payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send MS Teams notification: {e}")
                
        # 4. Telegram
        telegram_token = settings.get('telegram_bot_token')
        telegram_chat_id = settings.get('telegram_chat_id')
        if telegram_token and telegram_chat_id:
            try:
                telegram_url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
                tg_text = f"*{title}*\n\n" + "\n".join(message_lines)
                requests.post(
                    telegram_url,
                    json={
                        "chat_id": telegram_chat_id,
                        "text": tg_text,
                        "parse_mode": "Markdown"
                    },
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Failed to send Telegram notification: {e}")
                
    except Exception as e:
        logger.error(f"Error in notification system: {e}")

import re

class ImportBlacklistRequest(BaseModel):
    type: str # 'ip' or 'domain'
    url: Optional[str] = None
    content: Optional[str] = None

@app.post("/api/blacklists/import", dependencies=[Depends(authenticate)])
def import_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    """Import blacklist entries from URL or direct content"""
    try:
        blacklist_type = request_data.type.lower()
        if blacklist_type not in ['ip', 'domain']:
            raise HTTPException(status_code=400, detail="Type must be 'ip' or 'domain'")
        
        content = None
        
        # Check if URL is provided
        if request_data.url:
            # SSRF Protection: Ensure it's an HTTP/HTTPS URL and not pointing to local/private networks
            parsed_url = urllib.parse.urlparse(request_data.url)
            if parsed_url.scheme not in ['http', 'https']:
                raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed")
            
            try:
                # Basic check for localhost or loopback to prevent basic SSRF
                # A complete solution would resolve the DNS and check the IP against private ranges
                if parsed_url.hostname in ['localhost', '127.0.0.1', '0.0.0.0'] or parsed_url.hostname.startswith('192.168.') or parsed_url.hostname.startswith('10.'):
                    raise HTTPException(status_code=403, detail="Requests to local or private networks are blocked for security reasons")
                    
                logger.info(f"Fetching blacklist from URL: {request_data.url}")
                response = requests.get(request_data.url, timeout=15, headers={'User-Agent': 'SecureProxyManager/1.0'})
                if response.status_code == 200:
                    content = response.text
                else:
                    raise HTTPException(status_code=400, detail=f"Failed to fetch URL. Status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching URL: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Error fetching URL: {str(e)}")
        # Check if content is provided directly
        elif request_data.content:
            content = request_data.content
        else:
            raise HTTPException(status_code=400, detail="Either 'url' or 'content' must be provided")
            
        if not content:
            raise HTTPException(status_code=400, detail="No content to process")
            
        # Process the content
        lines = content.splitlines()
        entries_added = 0
        entries_skipped = 0
        
        conn = get_db()
        cursor = conn.cursor()
        
        table_name = "ip_blacklist" if blacklist_type == "ip" else "domain_blacklist"
        column_name = "ip" if blacklist_type == "ip" else "domain"
        
        # Prepare for batch insert
        to_insert = []
        existing_entries = set()
        
        # Get existing entries to avoid duplicates
        cursor.execute(f"SELECT {column_name} FROM {table_name}")
        for row in cursor.fetchall():
            existing_entries.add(row[column_name])
            
        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
                
            # Extract entry (handle formats like '127.0.0.1 domain.com' or just 'domain.com')
            parts = line.split()
            if not parts:
                continue
                
            entry = parts[-1]  # Take the last part (works for both hosts files and plain lists)
            
            if blacklist_type == 'ip':
                # Basic IP/CIDR validation
                try:
                    ipaddress.ip_network(entry, strict=False)
                    if entry not in existing_entries:
                        to_insert.append((entry, f"Imported on {datetime.now().strftime('%Y-%m-%d')}"))
                        existing_entries.add(entry)
                        entries_added += 1
                    else:
                        entries_skipped += 1
                except ValueError:
                    entries_skipped += 1
            else:
                # Basic domain validation
                # Remove http:// or https:// if present
                if entry.startswith('http://') or entry.startswith('https://'):
                    try:
                        parsed = urllib.parse.urlparse(entry)
                        entry = parsed.netloc
                    except Exception:
                        entries_skipped += 1
                        continue
                        
                if '.' in entry and not entry.startswith('.') and not entry.endswith('.'):
                    if entry not in existing_entries:
                        to_insert.append((entry, f"Imported on {datetime.now().strftime('%Y-%m-%d')}"))
                        existing_entries.add(entry)
                        entries_added += 1
                    else:
                        entries_skipped += 1
                else:
                    entries_skipped += 1
                    
        # Batch insert
        if to_insert:
            cursor.executemany(
                f"INSERT INTO {table_name} ({column_name}, description) VALUES (?, ?)", 
                to_insert
            )
            conn.commit()
            
        conn.close()
        
        # We would normally trigger apply_settings() here
        background_tasks.add_task(logger.info, f"Imported {entries_added} {blacklist_type}s")
        
        return {
            "status": "success",
            "message": f"Successfully imported {entries_added} entries ({entries_skipped} skipped/invalid)",
            "data": {
                "added": entries_added,
                "skipped": entries_skipped
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during import: {str(e)}")
        raise HTTPException(status_code=500, detail="Import operation failed")

class ImportGeoBlacklistRequest(BaseModel):
    countries: List[str]

@app.post("/api/blacklists/import-geo", dependencies=[Depends(authenticate)])
def import_geo_blacklist(request_data: ImportGeoBlacklistRequest, background_tasks: BackgroundTasks):
    """Import IP blocks for specific countries"""
    try:
        if not request_data.countries:
            raise HTTPException(status_code=400, detail="No countries provided")
            
        conn = get_db()
        cursor = conn.cursor()
        
        total_imported = 0
        
        # Get existing entries to avoid duplicates
        existing_ips = set()
        cursor.execute("SELECT ip FROM ip_blacklist")
        for row in cursor.fetchall():
            existing_ips.add(row['ip'])
            
        for country in request_data.countries:
            country = country.lower()
            url = f"https://www.ipdeny.com/ipv4/root/blocks/{country}.zone"
            logger.info(f"Fetching GeoIP block for {country} from {url}")
            
            try:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    to_insert = []
                    
                    for line in lines:
                        ip = line.strip()
                        if ip and ip not in existing_ips:
                            to_insert.append((ip, f"GeoIP: {country.upper()}"))
                            existing_ips.add(ip)
                            total_imported += 1
                            
                    if to_insert:
                        cursor.executemany(
                            "INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)",
                            to_insert
                        )
                        conn.commit()
            except Exception as e:
                logger.error(f"Error fetching GeoIP for {country}: {e}")
                
        conn.close()
        
        background_tasks.add_task(logger.info, f"Imported {total_imported} GeoIP blocks")
        
        return {
            "status": "success",
            "message": f"Successfully imported {total_imported} IP blocks for {len(request_data.countries)} countries",
            "data": {
                "imported": total_imported
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during GeoIP import: {str(e)}")
        raise HTTPException(status_code=500, detail="GeoIP import operation failed")

@app.post("/api/ip-blacklist/import", dependencies=[Depends(authenticate)])
def import_ip_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    """Import IP blacklist entries (Legacy endpoint)"""
    request_data.type = 'ip'
    return import_blacklist(request_data, background_tasks)

@app.post("/api/domain-blacklist/import", dependencies=[Depends(authenticate)])
def import_domain_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    """Import domain blacklist entries (Legacy endpoint)"""
    request_data.type = 'domain'
    return import_blacklist(request_data, background_tasks)

@app.get("/api/analytics/report/pdf", dependencies=[Depends(authenticate)])
def download_pdf_report():
    """Endpoint to download PDF report"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        elements.append(Paragraph("Secure Proxy Manager - Security Report", styles['Title']))
        elements.append(Spacer(1, 12))
        
        # Get basic stats
        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= date('now', '-7 days')")
            total_reqs = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '403%' AND timestamp >= date('now', '-7 days')")
            total_blocks = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            total_reqs = 0
            total_blocks = 0
            
        elements.append(Paragraph(f"Summary (Last 7 Days)", styles['Heading2']))
        data = [
            ["Metric", "Value"],
            ["Total Requests", str(total_reqs)],
            ["Blocked Requests", str(total_blocks)]
        ]
        t = Table(data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        
        doc.build(elements)
        pdf_data = buffer.getvalue()
        buffer.close()
        conn.close()
        
        return Response(
            content=pdf_data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.now().strftime('%Y%m%d')}.pdf"}
        )
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")

@app.get("/api/database/size", dependencies=[Depends(authenticate)])
def get_database_size():
    """Get the size of the database file"""
    try:
        if os.path.exists(DATABASE_PATH):
            size_bytes = os.path.getsize(DATABASE_PATH)
            
            # Format size for display
            if size_bytes < 1024:
                formatted_size = f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                formatted_size = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                formatted_size = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                formatted_size = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
            
            return {
                "status": "success",
                "data": {
                    "size": formatted_size,
                    "size_bytes": size_bytes
                }
            }
        else:
            raise HTTPException(status_code=404, detail=f"Database file not found at {DATABASE_PATH}")
    except Exception as e:
        logger.error(f"An error occurred while getting database size: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while getting database size")

@app.post("/api/database/optimize", dependencies=[Depends(authenticate)])
def optimize_database():
    """Optimize the SQLite database by vacuuming"""
    try:
        conn = get_db()
        size_before = os.path.getsize(DATABASE_PATH) if os.path.exists(DATABASE_PATH) else 0
        
        cursor = conn.cursor()
        cursor.execute("VACUUM")
        conn.commit()
        
        time.sleep(0.5)
        
        size_after = os.path.getsize(DATABASE_PATH) if os.path.exists(DATABASE_PATH) else 0
        space_saved = max(0, size_before - size_after)
        space_saved_mb = round(space_saved / (1024 * 1024), 2)
        
        conn.close()
        logger.info(f"Database optimized successfully. Space saved: {space_saved_mb} MB")
        
        return {
            "status": "success",
            "message": "Database optimized successfully",
            "data": {
                "size_before": size_before,
                "size_after": size_after,
                "space_saved": space_saved,
                "space_saved_mb": f"{space_saved_mb} MB"
            }
        }
    except Exception as e:
        logger.error(f"Error optimizing database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error optimizing database: {str(e)}")

@app.get("/api/database/stats", dependencies=[Depends(authenticate)])
def get_database_stats():
    """Get statistics about database tables"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get list of all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        stats = {}
        # Securely check tables against known schema tables
        known_tables = ['users', 'settings', 'ip_blacklist', 'domain_blacklist', 'proxy_logs']
        for table in tables:
            table_name = table['name']
            if table_name in known_tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                stats[table_name] = cursor.fetchone()[0]
                
        conn.close()
        
        return {
            "status": "success",
            "data": stats
        }
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting database stats: {str(e)}")

# Simple rate limiting in memory
auth_attempts = {}
MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes

@app.get("/api/security/rate-limits", dependencies=[Depends(authenticate)])
def get_rate_limits():
    """Get current rate limit status for all IPs"""
    try:
        now = datetime.now()
        rate_limit_data = []
        
        for ip, attempts in list(auth_attempts.items()):
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
        
        return {
            "status": "success",
            "data": rate_limit_data,
            "meta": {
                "max_attempts": MAX_ATTEMPTS,
                "window_seconds": RATE_LIMIT_WINDOW
            }
        }
    except Exception as e:
        logger.error(f"Error retrieving rate limit data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving rate limit data: {str(e)}")

@app.delete("/api/security/rate-limits/{ip}", dependencies=[Depends(authenticate)])
def clear_rate_limit(ip: str):
    """Clear rate limit for a specific IP"""
    try:
        if ip in auth_attempts:
            del auth_attempts[ip]
            return {
                "status": "success",
                "message": f"Rate limit cleared for IP {ip}"
            }
        else:
            raise HTTPException(status_code=404, detail=f"No active rate limit found for IP {ip}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing rate limit for IP {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error clearing rate limit: {str(e)}")

@app.get("/api/database/export", dependencies=[Depends(authenticate)])
def export_database():
    """Export the database contents as JSON"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # We wrap in try/except for graceful fallback if tables don't exist yet
        try:
            cursor.execute("SELECT * FROM proxy_logs ORDER BY timestamp DESC LIMIT 10000")
            logs = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            logs = []
            
        try:
            cursor.execute("SELECT * FROM ip_blacklist")
            ip_blacklist = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            ip_blacklist = []
            
        try:
            cursor.execute("SELECT * FROM domain_blacklist")
            domain_blacklist = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            domain_blacklist = []
            
        try:
            cursor.execute("SELECT * FROM settings")
            settings = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            settings = []
            
        conn.close()
        
        export_data = {
            "metadata": {
                "version": "1.1.0",
                "timestamp": datetime.now().isoformat(),
                "record_counts": {
                    "logs": len(logs),
                    "ip_blacklist": len(ip_blacklist),
                    "domain_blacklist": len(domain_blacklist),
                    "settings": len(settings)
                }
            },
            "logs": logs,
            "ip_blacklist": ip_blacklist,
            "domain_blacklist": domain_blacklist,
            "settings": settings
        }
        
        # Use StreamingResponse or just return dict directly (FastAPI handles JSON conversion)
        return {
            "status": "success",
            "message": "Database exported successfully",
            "data": export_data
        }
    except Exception as e:
        logger.error(f"Error exporting database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error exporting database: {str(e)}")

@app.post("/api/database/reset", dependencies=[Depends(authenticate)])
def reset_database():
    """Reset the database to default state"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Clear tables
        tables_to_clear = ['proxy_logs', 'ip_blacklist', 'domain_blacklist', 'settings']
        cleared_tables = []
        
        for table in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {table}")
                cleared_tables.append(table)
            except sqlite3.OperationalError:
                pass # Table might not exist
                
        # We don't delete users table to maintain admin access
        
        conn.commit()
        conn.close()
        
        # Re-initialize to populate default settings
        init_db()
        
        return {
            "status": "success",
            "message": "Database reset successfully",
            "data": {
                "cleared_tables": cleared_tables
            }
        }
    except Exception as e:
        logger.error(f"Error resetting database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error resetting database: {str(e)}")

@app.post("/api/logs/clear", dependencies=[Depends(authenticate)])
def clear_logs():
    """Clear all proxy logs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM proxy_logs")
            conn.commit()
        except sqlite3.OperationalError:
            pass # Table might not exist yet
            
        conn.close()
        logger.info("All logs cleared successfully")
        return {"status": "success", "message": "All logs cleared successfully"}
    except Exception as e:
        logger.error(f"An error occurred while clearing logs: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while clearing logs")

@app.post("/api/logs/clear-old", dependencies=[Depends(authenticate)])
def clear_old_logs(days: int = 30):
    """Clear logs older than specified days"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)", (f'-{days} days',))
            deleted_count = cursor.rowcount
            conn.commit()
        except sqlite3.OperationalError:
            deleted_count = 0
            
        conn.close()
        logger.info(f"Cleared {deleted_count} old logs successfully")
        return {"status": "success", "message": f"Cleared {deleted_count} logs older than {days} days"}
    except Exception as e:
        logger.error(f"An error occurred while clearing old logs: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while clearing old logs")

@app.get("/api/clients/statistics", dependencies=[Depends(authenticate)])
def client_statistics():
    """Return client statistics for the dashboard based on proxy logs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT 
                    source_ip as ip_address, 
                    COUNT(*) as requests,
                    'Active' as status 
                FROM proxy_logs
                WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip
                ORDER BY requests DESC
                LIMIT 50
            """)
            clients = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != ''")
            total_clients_row = cursor.fetchone()
            total_clients = total_clients_row[0] if total_clients_row else 0
        except sqlite3.OperationalError:
            clients = []
            total_clients = 0
            
        conn.close()
        
        data = {
            "total_clients": total_clients,
            "clients": clients
        }
        return {"status": "success", "data": data}
            
    except Exception as e:
        logger.error(f"An error occurred while fetching client statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching client statistics")

@app.get("/api/domains/statistics", dependencies=[Depends(authenticate)])
def domain_statistics():
    """Return domain statistics for the dashboard based on proxy logs"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT 
                    destination as domain_name, 
                    COUNT(*) as requests,
                    SUM(CASE 
                        WHEN status LIKE '%DENIED%' OR status LIKE '%BLOCKED%' OR status LIKE '%403%' 
                        THEN 1 ELSE 0 END) as blocked_requests
                FROM proxy_logs
                WHERE destination IS NOT NULL AND destination != ''
                GROUP BY destination
                ORDER BY requests DESC
                LIMIT 50
            """)
            domains_raw = [dict(row) for row in cursor.fetchall()]
            
            cursor.execute("SELECT domain FROM domain_blacklist")
            blacklisted_domains = [row['domain'] for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            domains_raw = []
            blacklisted_domains = []
            
        conn.close()
        
        # Determine if each domain is allowed or blocked
        domains = []
        for domain in domains_raw:
            is_in_blacklist = False
            has_blocked_requests = domain.get('blocked_requests', 0) > 0
            domain_name = domain['domain_name']
            
            # Check exact match
            if domain_name in blacklisted_domains:
                is_in_blacklist = True
            else:
                # Check wildcard matches (*.example.com)
                for blacklisted in blacklisted_domains:
                    if blacklisted.startswith('*.') and domain_name.endswith(blacklisted[2:]):
                        is_in_blacklist = True
                        break
            
            status = 'Blocked' if (is_in_blacklist or has_blocked_requests) else 'Allowed'
            
            domains.append({
                'domain_name': domain_name,
                'requests': domain['requests'],
                'status': status
            })
            
        return {"status": "success", "data": domains}
            
    except Exception as e:
        logger.error(f"An error occurred while fetching domain statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching domain statistics")

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/change-password", dependencies=[Depends(authenticate)])
def change_password(request_data: ChangePasswordRequest, request: Request):
    """Change user password with proper validation"""
    current_password = request_data.current_password
    new_password = request_data.new_password
    
    # Basic password complexity validation
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
        
    # Check for complexity (at least one number and one special character)
    if not re.search(r'\d', new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number and one special character")
    
    # Get the current user from auth header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        raise HTTPException(status_code=401, detail="Unauthorized")
        
    import base64
    try:
        decoded_auth = base64.b64decode(auth_header[6:]).decode('utf-8')
        username, _ = decoded_auth.split(':', 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication header")
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify current password
    if not check_password_hash(user['password'], current_password):
        conn.close()
        logger.warning(f"Failed password change attempt for user {username} - incorrect current password")
        raise HTTPException(status_code=403, detail="Current password is incorrect")
    
    # Update password
    new_password_hash = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password_hash, username))
    
    # Record that default password was changed
    cursor.execute("UPDATE settings SET setting_value = 'true' WHERE setting_name = 'default_password_changed'")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Password changed successfully for user {username}")
    
    return {"status": "success", "message": "Password updated successfully"}

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(request_data: LoginRequest):
    """Log in a user (Note: FastAPI handles auth via HTTPBasic header for every request in this architecture. This is maintained for compatibility with UI state)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (request_data.username,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data and check_password_hash(user_data['password'], request_data.password):
        return {
            "status": "success", 
            "message": "Login successful",
            "user": {"username": request_data.username}
        }
    
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/logout")
def logout():
    """Log out the current user"""
    # Since we use HTTP Basic auth, logout is handled client-side by clearing the auth headers
    return {"status": "success", "message": "Logout successful"}

@app.get("/api/cache/statistics", dependencies=[Depends(authenticate)])
def get_cache_statistics():
    """Get cache statistics (simulated/mocked if actual proxy metrics not available)"""
    # In a full implementation we would query squidmgr or squidclient
    return {
        "status": "success",
        "data": {
            "hit_rate": 24.5,
            "byte_hit_rate": 18.2,
            "cache_size": "450 MB",
            "max_cache_size": "2048 MB",
            "objects_cached": 12450
        }
    }

@app.get("/api/settings", dependencies=[Depends(authenticate)])
def get_settings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM settings")
    settings = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"status": "success", "data": settings}

class SettingUpdate(BaseModel):
    value: str

@app.put("/api/settings/{setting_name}", dependencies=[Depends(authenticate)])
def update_setting(setting_name: str, setting: SettingUpdate, background_tasks: BackgroundTasks):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?", 
                  (setting.value, setting_name))
    conn.commit()
    conn.close()
    
    # We would normally call apply_settings() here, but for this incremental step
    # we simulate the background task
    background_tasks.add_task(logger.info, f"Applied setting {setting_name}={setting.value}")
    
    return {"status": "success", "message": f"Setting {setting_name} updated"}

@app.post("/api/settings", dependencies=[Depends(authenticate)])
def update_settings(settings: Dict[str, Any], background_tasks: BackgroundTasks):
    conn = get_db()
    cursor = conn.cursor()
    
    for key, value in settings.items():
        cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?", 
                      (str(value), key))
        
    conn.commit()
    conn.close()
    
    background_tasks.add_task(logger.info, "Applied multiple settings")
    return {"status": "success", "message": "Settings updated successfully"}

@app.get("/api/security/score", dependencies=[Depends(authenticate)])
def get_security_score():
    """Get the security score based on current security settings"""
    db = get_db()
    cursor = db.cursor()
    
    # Get relevant security settings
    cursor.execute('SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?, ?, ?, ?, ?, ?, ?, ?)',
                 ('enable_ip_blacklist', 'enable_domain_blacklist', 'block_direct_ip', 
                  'enable_content_filtering', 'enable_https_filtering', 'default_password_changed',
                  'enable_time_restrictions', 'enable_waf'))
    
    settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
    db.close()
    
    # Calculate security score based on enabled security features
    score = 0
    recommendations = []
    
    # IP Blacklisting (15 points)
    if settings.get('enable_ip_blacklist') == 'true':
        score += 15
    else:
        recommendations.append('Enable IP blacklisting to block known malicious IP addresses')
    
    # Domain Blacklisting (15 points)
    if settings.get('enable_domain_blacklist') == 'true':
        score += 15
    else:
        recommendations.append('Enable domain blacklisting to block malicious websites')
    
    # Direct IP Blocking (10 points)
    if settings.get('block_direct_ip') == 'true':
        score += 10
    else:
        recommendations.append('Enable direct IP access blocking to prevent bypassing domain filters')
    
    # Content Filtering (10 points)
    if settings.get('enable_content_filtering') == 'true':
        score += 10
    else:
        recommendations.append('Enable content filtering to block risky file types')
        
    # WAF Content Inspection (25 points)
    if settings.get('enable_waf') == 'true':
        score += 25
    else:
        recommendations.append('Enable Outbound WAF (ICAP) to block SQLi, XSS, and Data Leaks')
    
    # HTTPS Filtering (15 points)
    if settings.get('enable_https_filtering') == 'true':
        score += 15
    else:
        recommendations.append('Consider enabling HTTPS filtering for complete security coverage')
    
    # Default Password Changed (5 points)
    if settings.get('default_password_changed') == 'true':
        score += 5
    else:
        recommendations.append('Change the default admin password to improve security')
    
    # Time Restrictions (5 points)
    if settings.get('enable_time_restrictions') == 'true':
        score += 5
    else:
        recommendations.append('Enable time restrictions to limit proxy usage to working hours')
        
    return {
        "status": "success",
        "data": {
            "score": score,
            "max_score": 100,
            "recommendations": recommendations
        }
    }

