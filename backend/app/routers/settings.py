import logging
from typing import Dict, Any

from fastapi import APIRouter, Depends, BackgroundTasks

from ..auth import authenticate
from ..database import get_db
from ..models import SettingUpdate

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/settings", dependencies=[Depends(authenticate)])
def get_settings():
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM settings")
        settings = [dict(row) for row in cursor.fetchall()]
        return {"status": "success", "data": settings}
    finally:
        conn.close()


@router.put("/api/settings/{setting_name}", dependencies=[Depends(authenticate)])
def update_setting(setting_name: str, setting: SettingUpdate, background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?",
                      (setting.value, setting_name))
        conn.commit()
        background_tasks.add_task(logger.info, f"Applied setting {setting_name}={setting.value}")
        return {"status": "success", "message": f"Setting {setting_name} updated"}
    finally:
        conn.close()


@router.post("/api/settings", dependencies=[Depends(authenticate)])
def update_settings(settings: Dict[str, Any], background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        for key, value in settings.items():
            cursor.execute("UPDATE settings SET setting_value = ? WHERE setting_name = ?",
                          (str(value), key))
        conn.commit()
        background_tasks.add_task(logger.info, "Applied multiple settings")
        return {"status": "success", "message": "Settings updated successfully"}
    finally:
        conn.close()
