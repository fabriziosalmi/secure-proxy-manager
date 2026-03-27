import os
import secrets
import logging

_logger = logging.getLogger(__name__)

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

# CORS
_cors_raw = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:8011,http://web:8011')
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_raw.split(',') if o.strip()]
