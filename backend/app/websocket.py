import os
import time
import logging
import sqlite3
import asyncio
from typing import List
from datetime import datetime

from fastapi import WebSocket

from . import config

logger = logging.getLogger(__name__)


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
            except (ConnectionError, RuntimeError, OSError):
                pass  # Client disconnected


manager = ConnectionManager()


def tail_logs_sync():
    """Background task to tail squid logs and emit via websocket."""
    log_file = '/logs/access.log'

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        try:
            if os.path.exists(log_file):
                logger.info(f"Starting to tail log file: {log_file}")
                if os.path.getsize(log_file) == 0:
                    time.sleep(2)

                with open(log_file, 'r') as f:
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

                                client_ip = parts[2]
                                status = parts[3]
                                bytes_sent = int(parts[4]) if parts[4].isdigit() else 0
                                method = parts[5]
                                destination = parts[6]

                                log_entry = {
                                    "timestamp": dt.strftime('%Y-%m-%d %H:%M:%S'),
                                    "client_ip": client_ip,
                                    "status": status,
                                    "bytes": bytes_sent,
                                    "method": method,
                                    "destination": destination
                                }

                                # Persist log to database
                                try:
                                    local_conn = sqlite3.connect(config.DATABASE_PATH)
                                    local_cursor = local_conn.cursor()
                                    local_cursor.execute(
                                        "INSERT INTO proxy_logs (timestamp, source_ip, destination, status, bytes, unix_timestamp, method) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                        (log_entry["timestamp"], client_ip, destination, status, bytes_sent, timestamp_sec, method)
                                    )
                                    local_conn.commit()
                                    local_conn.close()
                                except sqlite3.Error as db_err:
                                    logger.error(f"Error saving log to DB: {db_err}")

                                if manager.active_connections:
                                    loop.run_until_complete(manager.broadcast(log_entry))
                            except (ValueError, IndexError, OSError) as e:
                                logger.debug(f"Log parse error: {e}")
                        logger.debug("Tailed log line (len=%d)", len(line))
            else:
                logger.warning(f"Log file {log_file} does not exist yet. Waiting...")
                time.sleep(5)
        except (OSError, IOError) as e:
            logger.error(f"Error tailing logs: {e}")
            time.sleep(5)
