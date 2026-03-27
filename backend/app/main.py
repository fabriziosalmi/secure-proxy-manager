import logging
import sqlite3
import time
import threading
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pythonjsonlogger import jsonlogger
import logging.handlers

from .config import CORS_ALLOWED_ORIGINS
from .database import init_db, get_db
from .auth import validate_ws_token
from .websocket import manager, tail_logs_sync

# Configure main logger — respect LOG_LEVEL env var, default INFO in production
import os as _os
_log_level = getattr(logging, _os.environ.get('LOG_LEVEL', 'INFO').upper(), logging.INFO)
logging.basicConfig(level=_log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SIEM Syslog Logger setup
siem_logger = logging.getLogger('siem_logger')
siem_logger.setLevel(logging.INFO)


def setup_siem_logger():
    """Configure SIEM syslog forwarding based on settings."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT setting_name, setting_value FROM settings "
                "WHERE setting_name IN ('enable_siem_forwarding', 'siem_host', 'siem_port')"
            )
            settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
            siem_logger.handlers = []
            if settings.get('enable_siem_forwarding') == 'true' and settings.get('siem_host'):
                host = settings.get('siem_host')
                port = int(settings.get('siem_port', 514))
                syslog_handler = logging.handlers.SysLogHandler(address=(host, port))
                formatter = jsonlogger.JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
                syslog_handler.setFormatter(formatter)
                siem_logger.addHandler(syslog_handler)
                logger.info("SIEM forwarding configured successfully")
        except sqlite3.OperationalError:
            pass  # DB not ready yet
        conn.close()
    except Exception as e:
        logger.error(f"Failed to setup SIEM logger: {e}")


def ddns_scheduler_sync():
    """Background task to update DDNS periodically."""
    while True:
        try:
            logger.debug("Running DDNS scheduler check...")
        except Exception as e:
            logger.error(f"DDNS scheduler error: {e}")
        time.sleep(3600)


def log_retention_sync():
    """Background task to delete old logs based on configurable retention."""
    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()
            # Read retention setting (default 30 days)
            cursor.execute("SELECT setting_value FROM settings WHERE setting_name = 'log_retention_days'")
            row = cursor.fetchone()
            retention_days = int(row['setting_value']) if row and row['setting_value'] else 30
            if retention_days > 0:
                cursor.execute(
                    "DELETE FROM proxy_logs WHERE timestamp < datetime('now', ?)",
                    (f'-{retention_days} days',)
                )
                deleted = cursor.rowcount
                if deleted > 0:
                    conn.commit()
                    logger.info(f"Log retention: deleted {deleted} logs older than {retention_days} days")
            conn.close()
        except Exception as e:
            logger.error(f"Log retention error: {e}")
        time.sleep(3600)  # Run every hour


def blacklist_auto_refresh_sync():
    """Background task to re-download popular blocklists at configured interval."""
    import requests as _requests
    from .database import get_db, export_blacklists_to_files

    # Default popular lists to auto-refresh
    DEFAULT_IP_LISTS = [
        ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "ip"),
        ("https://www.spamhaus.org/drop/drop.txt", "ip"),
    ]
    DEFAULT_DOMAIN_LISTS = [
        ("https://github.com/fabriziosalmi/blacklists/releases/download/latest/blacklist.txt", "domain"),
    ]

    while True:
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT setting_value FROM settings WHERE setting_name = 'auto_refresh_hours'")
            row = cursor.fetchone()
            interval_hours = int(row['setting_value']) if row and row['setting_value'] else 24
            cursor.execute("SELECT setting_value FROM settings WHERE setting_name = 'auto_refresh_enabled'")
            row2 = cursor.fetchone()
            enabled = row2 and row2['setting_value'] == 'true'
            conn.close()

            if enabled and interval_hours > 0:
                logger.info(f"Auto-refresh: checking blocklists (interval={interval_hours}h)")
                headers = {'User-Agent': 'SecureProxyManager/AutoRefresh'}

                for url, list_type in DEFAULT_IP_LISTS + DEFAULT_DOMAIN_LISTS:
                    try:
                        resp = _requests.get(url, timeout=120, headers=headers)
                        if resp.status_code == 200:
                            conn = get_db()
                            cursor = conn.cursor()
                            table = "ip_blacklist" if list_type == "ip" else "domain_blacklist"
                            col = "ip" if list_type == "ip" else "domain"
                            # Get existing
                            cursor.execute(f"SELECT {col} FROM {table}")
                            existing = {r[col] for r in cursor.fetchall()}
                            # Parse and insert new
                            added = 0
                            to_insert = []
                            for line in resp.text.splitlines():
                                entry = line.strip()
                                if not entry or entry.startswith('#') or entry.startswith(';'):
                                    continue
                                parts = entry.split()
                                entry = parts[-1] if parts else entry
                                if entry not in existing:
                                    to_insert.append((entry, f"Auto-refresh {time.strftime('%Y-%m-%d')}"))
                                    existing.add(entry)
                                    added += 1
                            if to_insert:
                                cursor.executemany(f"INSERT OR IGNORE INTO {table} ({col}, description) VALUES (?, ?)", to_insert)
                                conn.commit()
                            conn.close()
                            if added > 0:
                                logger.info(f"Auto-refresh: {url[:50]}... → {added} new entries")
                    except Exception as e:
                        logger.warning(f"Auto-refresh failed for {url[:50]}: {e}")

                # Regenerate files
                export_blacklists_to_files()

            time.sleep(interval_hours * 3600)
        except Exception as e:
            logger.error(f"Auto-refresh error: {e}")
            time.sleep(3600)


# FastAPI App Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    setup_siem_logger()

    log_thread = threading.Thread(target=tail_logs_sync, daemon=True)
    log_thread.start()

    ddns_thread = threading.Thread(target=ddns_scheduler_sync, daemon=True)
    ddns_thread.start()

    retention_thread = threading.Thread(target=log_retention_sync, daemon=True)
    retention_thread.start()

    refresh_thread = threading.Thread(target=blacklist_auto_refresh_sync, daemon=True)
    refresh_thread.start()

    yield
    # Shutdown


# FastAPI App
app = FastAPI(title="Secure Proxy Manager API", lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Include routers ──────────────────────────────────────────────────────────
from .routers import auth_routes, blacklists, logs, settings, maintenance, database_routes, security, analytics  # noqa: E402

app.include_router(auth_routes.router)
app.include_router(blacklists.router)
app.include_router(logs.router)
app.include_router(settings.router)
app.include_router(maintenance.router)
app.include_router(database_routes.router)
app.include_router(security.router)
app.include_router(analytics.router)


# ── Health checks ────────────────────────────────────────────────────────────
@app.get("/health")
def health_check_legacy():
    return {"status": "healthy"}


@app.get("/api/health")
def health_check():
    return {"status": "healthy"}


# ── WebSocket ────────────────────────────────────────────────────────────────
@app.websocket("/api/ws/logs")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    if not token:
        await websocket.close(code=4001, reason="Authentication token required")
        return
    username = validate_ws_token(token)
    if username is None:
        await websocket.close(code=4003, reason="Invalid or already-used token")
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
