import os
import time
import logging
import sqlite3
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from ..auth import authenticate
from .. import config
from ..database import get_db, init_db

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/database/size", dependencies=[Depends(authenticate)])
def get_database_size():
    try:
        if os.path.exists(config.DATABASE_PATH):
            size_bytes = os.path.getsize(config.DATABASE_PATH)
            if size_bytes < 1024:
                formatted_size = f"{size_bytes} bytes"
            elif size_bytes < 1024 * 1024:
                formatted_size = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                formatted_size = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                formatted_size = f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
            return {"status": "success", "data": {"size": formatted_size, "size_bytes": size_bytes}}
        else:
            raise HTTPException(status_code=404, detail=f"Database file not found at {config.DATABASE_PATH}")
    except Exception as e:
        logger.error(f"An error occurred while getting database size: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while getting database size")


@router.post("/api/database/optimize", dependencies=[Depends(authenticate)])
def optimize_database():
    try:
        conn = get_db()
        size_before = os.path.getsize(config.DATABASE_PATH) if os.path.exists(config.DATABASE_PATH) else 0
        cursor = conn.cursor()
        cursor.execute("VACUUM")
        conn.commit()
        time.sleep(0.5)
        size_after = os.path.getsize(config.DATABASE_PATH) if os.path.exists(config.DATABASE_PATH) else 0
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
    except sqlite3.Error as e:
        logger.error(f"Error optimizing database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error optimizing database: {str(e)}")


@router.get("/api/database/stats", dependencies=[Depends(authenticate)])
def get_database_stats():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        stats = {}
        known_tables = ['users', 'settings', 'ip_blacklist', 'domain_blacklist', 'proxy_logs']
        for table in tables:
            table_name = table['name']
            if table_name in known_tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                stats[table_name] = cursor.fetchone()[0]
        conn.close()
        return {"status": "success", "data": stats}
    except sqlite3.Error as e:
        logger.error(f"Error getting database stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting database stats: {str(e)}")


@router.get("/api/database/export", dependencies=[Depends(authenticate)])
def export_database():
    try:
        conn = get_db()
        cursor = conn.cursor()

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

        _SENSITIVE_KEYS = {
            'gotify_token', 'telegram_bot_token', 'webhook_url',
            'teams_webhook_url', 'siem_host', 'siem_port',
        }
        try:
            cursor.execute("SELECT * FROM settings")
            settings = []
            for row in cursor.fetchall():
                row_dict = dict(row)
                if row_dict.get('setting_name') in _SENSITIVE_KEYS:
                    row_dict['setting_value'] = '***REDACTED***'
                settings.append(row_dict)
        except sqlite3.OperationalError:
            settings = []

        conn.close()

        export_data = {
            "metadata": {
                "version": "1.3.0",
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

        return {"status": "success", "message": "Database exported successfully", "data": export_data}
    except sqlite3.Error as e:
        logger.error(f"Error exporting database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error exporting database: {str(e)}")


@router.post("/api/database/reset", dependencies=[Depends(authenticate)])
def reset_database():
    try:
        conn = get_db()
        cursor = conn.cursor()
        tables_to_clear = ['proxy_logs', 'ip_blacklist', 'domain_blacklist', 'settings']
        cleared_tables = []
        for table in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {table}")
                cleared_tables.append(table)
            except sqlite3.OperationalError:
                pass
        conn.commit()
        conn.close()
        init_db()
        return {"status": "success", "message": "Database reset successfully", "data": {"cleared_tables": cleared_tables}}
    except sqlite3.Error as e:
        logger.error(f"Error resetting database: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error resetting database: {str(e)}")
