#!/bin/sh

# Ensure directories exist with proper permissions
mkdir -p /var/log/squid /var/cache/squid /etc/squid
chown -R squid:squid /var/log/squid /var/cache/squid
chmod -R 750 /var/log/squid /var/cache/squid

# Add debug output for troubleshooting
echo "Running entrypoint.sh"

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
    chown root:squid "$file"
    chmod 644 "$file"
  fi
done

# Make sure the Squid configuration is valid
echo "Validating Squid configuration"
/usr/sbin/squid -k parse -f /etc/squid/squid.conf
if [ $? -ne 0 ]; then
  echo "ERROR: Invalid Squid configuration"
  exit 1
fi

# Check if squid can start manually (test run)
echo "Testing Squid startup..."
/usr/sbin/squid -N -d 1 -f /etc/squid/squid.conf &
TEST_PID=$!
sleep 2
kill $TEST_PID 2>/dev/null || true
echo "Squid test completed"

echo "Starting supervisord..."
exec "$@"