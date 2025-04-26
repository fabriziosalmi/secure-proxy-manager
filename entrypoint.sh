#!/bin/bash

# Ensure directories exist with proper permissions
mkdir -p /var/log/squid /var/cache/squid /etc/squid /var/lib/ssl_db
chown -R proxy:proxy /var/log/squid /var/cache/squid /var/lib/ssl_db
chmod -R 750 /var/log/squid /var/cache/squid /var/lib/ssl_db

# Comment out SSL bumping directives to avoid startup failures
for file in ssl_bump sslproxy_cert_error sslcrtd_program sslcrtd_children; do
  sed -i "/^$file /s/^/#/" /etc/squid/squid.conf || true
done

# Add debug output for troubleshooting
echo "Running entrypoint.sh"

# Verify squidclient is installed and executable
if ! command -v squidclient >/dev/null 2>&1; then
    echo "WARNING: squidclient is not installed, installing it now..."
    apt-get update && apt-get install -y squidclient
fi

# Initialize Squid cache if needed
if [ ! -d /var/cache/squid/00 ]; then
  echo "Running squid -z to initialize cache"
  /usr/sbin/squid -z
  echo "Cache initialization complete"
fi

# Ensure configuration files exist
echo "Checking configuration files"
for file in /etc/squid/blacklist_domains.txt /etc/squid/blacklist_ips.txt /etc/squid/allowed_direct_ips.txt /etc/squid/bad_user_agents.txt; do
  if [ ! -f "$file" ]; then
    echo "Creating empty file: $file"
    touch "$file"
    chown root:proxy "$file"
    chmod 644 "$file"
  fi
done

# Make sure the Squid configuration is valid
echo "Validating Squid configuration"
parse_output=$(/usr/sbin/squid -k parse -f /etc/squid/squid.conf 2>&1)
if [ $? -ne 0 ]; then
  echo "ERROR: Invalid Squid configuration"
  echo "$parse_output"
  exit 1
fi

# Cleanup any old Squid PID file to avoid "already running" errors
echo "Cleaning up old Squid PID file"
rm -f /var/run/squid.pid

# Commented out manual test run to prevent orphan processes
# echo "Testing Squid startup..."
# /usr/sbin/squid -N -d 1 -f /etc/squid/squid.conf &
# TEST_PID=$!
# sleep 2
# kill $TEST_PID 2>/dev/null || true
# echo "Squid test completed"

echo "Starting supervisord..."
exec "$@"