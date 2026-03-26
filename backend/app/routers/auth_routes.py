import re
import logging
import sqlite3
from datetime import datetime, timedelta

import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth import (
    authenticate, check_password_hash, generate_password_hash,
    auth_attempts, issue_ws_token,
)
from ..config import (
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_HOURS,
    MAX_ATTEMPTS, RATE_LIMIT_WINDOW,
)
from ..database import get_db
from ..models import LoginRequest, ChangePasswordRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/ws-token")
def get_ws_token(current_user: str = Depends(authenticate)):
    """Issue a short-lived one-time token to authenticate the WebSocket connection."""
    return {"token": issue_ws_token(current_user)}


@router.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    """Validate credentials and return a short-lived JWT access token."""
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now()

    if client_ip in auth_attempts:
        valid = [t for t in auth_attempts[client_ip] if (now - t).total_seconds() < RATE_LIMIT_WINDOW]
        auth_attempts[client_ip] = valid
        if len(valid) >= MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed attempts. Try again in {RATE_LIMIT_WINDOW // 60} minutes.",
            )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (req.username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password"], req.password):
        auth_attempts.setdefault(client_ip, []).append(now)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    auth_attempts.pop(client_ip, None)

    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    token = pyjwt.encode({"sub": req.username, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"token": token}


@router.post("/api/logout")
def logout():
    """Log out the current user (client-side handled)."""
    return {"status": "success", "message": "Logout successful"}


@router.post("/api/change-password", dependencies=[Depends(authenticate)])
def change_password(request_data: ChangePasswordRequest, request: Request):
    """Change user password with proper validation."""
    new_password = request_data.new_password

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")

    if not re.search(r'\d', new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number and one special character")

    # Extract username from auth header
    import base64
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        raise HTTPException(status_code=401, detail="Unauthorized")

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

    if not check_password_hash(user['password'], request_data.current_password):
        conn.close()
        logger.warning(f"Failed password change attempt for user {username} - incorrect current password")
        raise HTTPException(status_code=403, detail="Current password is incorrect")

    new_password_hash = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password_hash, username))
    cursor.execute("UPDATE settings SET setting_value = 'true' WHERE setting_name = 'default_password_changed'")

    conn.commit()
    conn.close()

    logger.info(f"Password changed successfully for user {username}")
    return {"status": "success", "message": "Password updated successfully"}
