#!/bin/sh
set -eu

# Parse BACKEND_URL (e.g. http://backend:5000) into host and port
_backend="${BACKEND_URL:-http://backend:5000}"
_backend="${_backend#http://}"
_backend="${_backend#https://}"
BACKEND_HOST="${_backend%:*}"
BACKEND_PORT="${_backend##*:}"
export BACKEND_HOST BACKEND_PORT
export REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-120}"

# Substitute only our env vars into the nginx template.
# The explicit list prevents envsubst from corrupting nginx variables like $host.
envsubst '${BACKEND_HOST} ${BACKEND_PORT} ${REQUEST_TIMEOUT}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
