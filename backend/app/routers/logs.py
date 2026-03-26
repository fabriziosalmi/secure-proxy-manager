import logging
import sqlite3
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException

from ..auth import authenticate
from ..database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/logs", dependencies=[Depends(authenticate)])
def get_logs(limit: int = 25, offset: int = 0, sort: str = 'timestamp', order: str = 'desc'):
    """Get proxy logs with pagination and sorting."""
    try:
        valid_columns = ['timestamp', 'source_ip', 'destination', 'status', 'bytes', 'method']
        if sort not in valid_columns:
            sort = 'timestamp'
        if order.lower() not in ['asc', 'desc']:
            order = 'desc'

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs")
            total_count = cursor.fetchone()[0]

            sort_map = {c: c for c in valid_columns}
            order_map = {'asc': 'ASC', 'desc': 'DESC'}
            safe_sort = sort_map.get(sort, 'timestamp')
            safe_order = order_map.get(order.lower(), 'DESC')

            query = f"SELECT * FROM proxy_logs ORDER BY {safe_sort} {safe_order} LIMIT ? OFFSET ?"
            cursor.execute(query, (limit, offset))

            raw_logs = cursor.fetchall()
            logs = []
            for row in raw_logs:
                row_dict = dict(row)
                logs.append({
                    "id": row_dict.get("id"),
                    "timestamp": row_dict.get("timestamp"),
                    "client_ip": row_dict.get("source_ip"),
                    "destination": row_dict.get("destination"),
                    "status": row_dict.get("status"),
                    "bytes": row_dict.get("bytes"),
                    "method": row_dict.get("method", "CONNECT")
                })
        except sqlite3.OperationalError:
            total_count = 0
            logs = []

        conn.close()

        return {
            "status": "success",
            "data": logs,
            "pagination": {"total": total_count, "limit": limit, "offset": offset}
        }
    except sqlite3.Error as e:
        logger.error(f"Error fetching logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch logs")


@router.get("/api/logs/stats", dependencies=[Depends(authenticate)])
def get_log_stats():
    """Get statistics about logs including blocked requests and direct IP blocks."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs")
            total_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE ? OR status LIKE ? OR status LIKE ?",
                          ('%DENIED%', '%403%', '%BLOCKED%'))
            blocked_count = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(*) FROM proxy_logs
                WHERE (status LIKE ? OR status LIKE ? OR status LIKE ?)
                AND (
                    (destination LIKE 'http://%.%.%.%' AND destination NOT LIKE 'http://%.%.%.%.%')
                    OR (destination LIKE 'https://%.%.%.%' AND destination NOT LIKE 'https://%.%.%.%.%')
                    OR destination LIKE '%.%.%.%'
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
    except sqlite3.Error as e:
        logger.error(f"Error getting log stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get log statistics")


@router.get("/api/logs/timeline", dependencies=[Depends(authenticate)])
def get_log_timeline(hours: int = 24):
    """Get log timeline for charts."""
    try:
        conn = get_db()
        cursor = conn.cursor()
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
            pass

        conn.close()
        return {"status": "success", "data": timeline_data}
    except sqlite3.Error as e:
        logger.error(f"Error getting log timeline: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get log timeline")


@router.post("/api/logs/clear", dependencies=[Depends(authenticate)])
def clear_logs():
    """Clear all proxy logs."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM proxy_logs")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        conn.close()
        logger.info("All logs cleared successfully")
        return {"status": "success", "message": "All logs cleared successfully"}
    except sqlite3.Error as e:
        logger.error(f"An error occurred while clearing logs: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while clearing logs")


@router.post("/api/logs/clear-old", dependencies=[Depends(authenticate)])
def clear_old_logs(days: int = 30):
    """Clear logs older than specified days."""
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
    except sqlite3.Error as e:
        logger.error(f"An error occurred while clearing old logs: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while clearing old logs")
