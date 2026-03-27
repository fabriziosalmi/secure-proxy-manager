import os
import secrets
import logging

_logger = logging.getLogger(__name__)

# Version — single source of truth
APP_VERSION = "1.8.1"

# Database
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/secure_proxy.db')

# Proxy
PROXY_HOST = os.environ.get('PROXY_HOST', 'proxy')
PROXY_PORT = os.environ.get('PROXY_PORT', '3128')

# JWT — stable secret persisted to disk if not provided via env
_JWT_SECRET_FILE = os.path.join(os.path.dirname(DATABASE_PATH), '.jwt_secret')


def _get_stable_jwt_secret() -> str:
    """Return a JWT secret that survives container restarts."""
    env_secret = os.environ.get('SECRET_KEY')
    if env_secret:
        return env_secret
    # Try to load from disk
    try:
        if os.path.exists(_JWT_SECRET_FILE):
            with open(_JWT_SECRET_FILE, 'r') as f:
                secret = f.read().strip()
                if len(secret) >= 32:
                    return secret
    except OSError:
        pass
    # Generate and persist
    secret = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(_JWT_SECRET_FILE), exist_ok=True)
        with open(_JWT_SECRET_FILE, 'w') as f:
            f.write(secret)
        os.chmod(_JWT_SECRET_FILE, 0o600)
        _logger.info("Generated and persisted new JWT secret")
    except OSError:
        _logger.warning("Could not persist JWT secret to disk — tokens will invalidate on restart")
    return secret


JWT_SECRET = _get_stable_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

# Rate limiting
MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes

# CORS — reject wildcard to prevent open access in production
_cors_raw = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:8011,http://web:8011')
_cors_origins = [o.strip() for o in _cors_raw.split(',') if o.strip()]
if '*' in _cors_origins:
    _logger.warning("CORS_ALLOWED_ORIGINS contains '*' — rejecting wildcard for security. Use explicit origins.")
    _cors_origins = [o for o in _cors_origins if o != '*']
    if not _cors_origins:
        _cors_origins = ['http://localhost:8011']
CORS_ALLOWED_ORIGINS = _cors_origins


# ── Startup validation ────────────────────────────────────────────────────────
def validate_environment():
    """Log warnings for common misconfigurations."""
    issues = []
    db_dir = os.path.dirname(DATABASE_PATH)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except OSError:
            issues.append(f"Cannot create database directory: {db_dir}")
    if db_dir and os.path.exists(db_dir) and not os.access(db_dir, os.W_OK):
        issues.append(f"Database directory not writable: {db_dir}")
    if not os.environ.get('BASIC_AUTH_USERNAME'):
        issues.append("BASIC_AUTH_USERNAME not set — backend will fail to start")
    if not os.environ.get('BASIC_AUTH_PASSWORD'):
        issues.append("BASIC_AUTH_PASSWORD not set — backend will fail to start")
    if os.environ.get('SECRET_KEY', '').lower() in ('changeme', 'secret', 'password', ''):
        _logger.warning("SECRET_KEY is weak or default — consider setting a strong value")
    for issue in issues:
        _logger.warning(f"Config issue: {issue}")
    return issues
