import os
import base64
import logging
import sqlite3
import secrets
from typing import Optional, Dict, List
from datetime import datetime, timedelta

import bcrypt
import jwt as pyjwt
from fastapi import HTTPException, Header, Request, status

from . import config
from .config import (
    JWT_SECRET, JWT_ALGORITHM,
    MAX_ATTEMPTS, RATE_LIMIT_WINDOW,
)

logger = logging.getLogger(__name__)

# Rate limiting state (in-memory, reset on restart)
auth_attempts: Dict[str, List[datetime]] = {}

# One-time tokens for WebSocket authentication: {token: (username, expiry)}
ws_tokens: Dict[str, tuple] = {}

# JWT blacklist for logout (in-memory, cleared on restart — acceptable for homelab/SMB)
_jwt_blacklist: set = set()


def generate_password_hash(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def check_password_hash(hashed_password: str, user_password: str) -> bool:
    """Check hashed password. Supports bcrypt and legacy werkzeug hashes."""
    if hashed_password.startswith('pbkdf2:sha256:') or hashed_password.startswith('scrypt:'):
        env_password = os.environ.get('BASIC_AUTH_PASSWORD')
        if user_password == env_password:
            return True
        return False
    try:
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False


def _get_auth_db():
    """Get a DB connection for auth queries."""
    conn = sqlite3.connect(config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def authenticate(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> str:
    """Accept Bearer JWT (browser) or Basic Auth (backward-compat / tests)."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": 'Bearer realm="Secure Proxy Manager"'},
        )

    # Bearer JWT path
    if authorization.startswith("Bearer "):
        token = authorization[7:]
        if token in _jwt_blacklist:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            sub = payload.get("sub")
            if not isinstance(sub, str) or not sub:
                raise pyjwt.InvalidTokenError("missing sub")
            return sub
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except pyjwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Basic Auth path (backward-compat)
    if authorization.startswith("Basic "):
        # Use X-Forwarded-For if behind reverse proxy, fallback to direct IP
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        now = datetime.now()

        if client_ip in auth_attempts:
            valid = [t for t in auth_attempts[client_ip] if (now - t).total_seconds() < RATE_LIMIT_WINDOW]
            auth_attempts[client_ip] = valid
            if len(valid) >= MAX_ATTEMPTS:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many failed attempts. Try again in {RATE_LIMIT_WINDOW // 60} minutes.",
                )

        try:
            decoded = base64.b64decode(authorization[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        conn = _get_auth_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user or not check_password_hash(user["password"], password):
            auth_attempts.setdefault(client_ip, []).append(now)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )

        auth_attempts.pop(client_ip, None)
        return username

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": 'Bearer realm="Secure Proxy Manager"'},
    )


def invalidate_jwt(token: str):
    """Add a JWT to the blacklist (called on logout)."""
    _jwt_blacklist.add(token)
    # Prune blacklist periodically (keep last 1000 tokens)
    if len(_jwt_blacklist) > 1000:
        _jwt_blacklist.clear()


def issue_ws_token(username: str) -> str:
    """Issue a short-lived one-time token for WebSocket authentication."""
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    # Purge expired tokens
    expired_keys = [t for t, (_, exp) in list(ws_tokens.items()) if exp < now]
    for k in expired_keys:
        ws_tokens.pop(k, None)
    ws_tokens[token] = (username, now + timedelta(minutes=2))
    return token


def validate_ws_token(token: str) -> Optional[str]:
    """Validate and consume a one-time WebSocket token. Returns username or None."""
    token_data = ws_tokens.pop(token, None)
    if token_data is None:
        return None
    _username, expiry = token_data
    if datetime.now() > expiry:
        return None
    return _username
