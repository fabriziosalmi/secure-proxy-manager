import os
import secrets

# Database
DATABASE_PATH = os.environ.get('DATABASE_PATH', '/data/secure_proxy.db')

# Proxy
PROXY_HOST = os.environ.get('PROXY_HOST', 'proxy')
PROXY_PORT = os.environ.get('PROXY_PORT', '3128')

# JWT
JWT_SECRET = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

# Rate limiting
MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes

# CORS
_cors_raw = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:8011,http://web:8011')
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_raw.split(',') if o.strip()]
