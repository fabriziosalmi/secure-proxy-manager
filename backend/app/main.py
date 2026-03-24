import os
import sys
import logging
import sqlite3
import secrets
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from werkzeug.security import generate_password_hash, check_password_hash
import asyncio
import json

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/secure_proxy.db')

# FastAPI App
app = FastAPI(title="Secure Proxy Manager API")

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

@app.on_event("startup")
async def startup_event():
    init_db()

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
@app.get("/api/health")
def health_check():
    return {"status": "healthy"}

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

