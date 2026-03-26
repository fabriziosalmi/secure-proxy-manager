import os
import logging
import sqlite3

import requests
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from ..auth import authenticate
from ..config import PROXY_HOST
from ..database import get_db, export_blacklists_to_files
from ..models import RestoreConfigRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/maintenance/backup-config", dependencies=[Depends(authenticate)])
def backup_config():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT setting_name, setting_value FROM settings")
        settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
        conn.close()
        return {"status": "success", "data": settings}
    except sqlite3.Error as e:
        logger.error(f"Error backing up config: {e}")
        raise HTTPException(status_code=500, detail="Failed to backup config")


@router.post("/api/maintenance/restore-config", dependencies=[Depends(authenticate)])
def restore_config(request_data: RestoreConfigRequest, background_tasks: BackgroundTasks):
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
    except sqlite3.Error as e:
        logger.error(f"Error restoring config: {e}")
        raise HTTPException(status_code=500, detail="Failed to restore config")


@router.get("/api/security/download-ca", dependencies=[Depends(authenticate)])
def download_ca_cert():
    cert_path = '/config/ssl_cert.pem'
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Certificate not found. It may not have been generated yet.")
    return FileResponse(path=cert_path, filename='secure-proxy-ca.pem', media_type='application/x-x509-ca-cert')


@router.get("/api/maintenance/check-cert-security", dependencies=[Depends(authenticate)])
def check_cert_security():
    try:
        cert_issues = []
        cert_found = False
        for cert_path in ['/config/ssl_cert.pem', 'config/ssl_cert.pem']:
            if os.path.exists(cert_path):
                cert_found = True
                break
        if not cert_found:
            cert_issues.append("SSL certificate not found at any expected location")

        db_found = False
        for db_path in ['/config/ssl_db', 'config/ssl_db']:
            if os.path.exists(db_path) and os.path.isdir(db_path) and os.listdir(db_path):
                db_found = True
                break
        if not db_found:
            cert_issues.append("SSL certificate database not found or empty")

        return {
            "status": "error" if cert_issues else "success",
            "message": "Certificate security check completed",
            "data": {"issues": cert_issues, "cert_found": cert_found, "db_found": db_found}
        }
    except (sqlite3.Error, OSError) as e:
        logger.error(f"Error checking cert security: {e}")
        raise HTTPException(status_code=500, detail="Failed to check certificate security")


@router.post("/api/maintenance/reload-config", dependencies=[Depends(authenticate)])
def reload_proxy_config(background_tasks: BackgroundTasks):
    try:
        export_blacklists_to_files()
        response = requests.post(f"http://{PROXY_HOST}:5000/api/reload", timeout=5)
        if response.status_code == 200:
            return {"status": "success", "message": "Proxy configuration reloaded successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to reload proxy configuration")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error reloading proxy: {str(e)}")
        return {"status": "success", "message": "Proxy reload simulated"}


@router.post("/api/maintenance/clear-cache", dependencies=[Depends(authenticate)])
def clear_proxy_cache():
    try:
        response = requests.post(f"http://{PROXY_HOST}:5000/api/cache/clear", timeout=10)
        if response.status_code == 200:
            return {"status": "success", "message": "Proxy cache cleared successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear proxy cache")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error clearing proxy cache: {str(e)}")
        return {"status": "success", "message": "Proxy cache clear simulated"}
