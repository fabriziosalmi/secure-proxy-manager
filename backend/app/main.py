import logging
import time
import threading
from typing import Optional
from contextlib import asynccontextmanager

import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from pythonjsonlogger import jsonlogger
import logging.handlers

from .config import CORS_ALLOWED_ORIGINS, DATABASE_PATH, PROXY_HOST, PROXY_PORT
from .database import init_db, get_db
from .auth import authenticate, validate_ws_token
from .websocket import manager, tail_logs_sync

# Configure main logger
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
                logger.info(f"SIEM forwarding configured to {host}:{port}")
        except Exception:
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
    import sqlite3
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
from .routers import auth_routes, blacklists, logs, settings, maintenance, database_routes, security, analytics

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
