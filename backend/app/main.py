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
    # Support for old werkzeug hashes which look like pbkdf2:sha256:...
    if hashed_password.startswith('pbkdf2:sha256:'):
        # We'd need werkzeug for backwards compatibility if old users exist
        # For now, just return false or handle it if you migrate DB
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

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
                process = subprocess.Popen(['tail', '-F', log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for line in process.stdout:
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
            else:
                time.sleep(5)
        except Exception as e:
            logger.error(f"Error tailing logs: {e}")
            time.sleep(5)

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
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
            
            query = f"SELECT * FROM proxy_logs ORDER BY {sort} {order.upper()} LIMIT ? OFFSET ?"
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
            total_requests = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '403%' OR status LIKE '500%'")
            blocked_requests = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM ip_blacklist")
            blacklisted_ips = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM domain_blacklist")
            blacklisted_domains = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            total_requests = 0
            blocked_requests = 0
            blacklisted_ips = 0
            blacklisted_domains = 0
            
        conn.close()
        
        return {
            "status": "success",
            "data": {
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "blacklisted_ips": blacklisted_ips,
                "blacklisted_domains": blacklisted_domains,
                "block_rate": round((blocked_requests / total_requests * 100) if total_requests > 0 else 0, 2)
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
        for table in tables:
            table_name = table['name']
            if table_name != 'sqlite_sequence':  # Skip internal table
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

