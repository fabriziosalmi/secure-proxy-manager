#!/bin/sh

# Ensure directories exist with proper permissions
mkdir -p /var/log/squid /var/cache/squid /var/lib/ssl_db
chown -R squid:squid /var/log/squid /var/cache/squid /var/lib/ssl_db
chmod -R 750 /var/log/squid /var/cache/squid /var/lib/ssl_db

# Add debug output
echo "Initializing Squid cache"

# Initialize Squid cache if needed
if [ ! -d /var/cache/squid/00 ]; then
  echo "Running squid -z to initialize cache"
  /usr/sbin/squid -z
  echo "Cache initialization complete"
fi

# Check if security_file_certgen exists
if [ -f /usr/lib/squid/security_file_certgen ]; then
  echo "SSL helper found, initializing SSL database"
  # Initialize SSL database if needed
  if [ ! -f /var/lib/ssl_db/index.txt ]; then
    echo "Initializing SSL database"
    /usr/lib/squid/security_file_certgen -c -s /var/lib/ssl_db -M 4MB
    echo "SSL database initialization complete"
  fi
else
  echo "SSL helper not found, disabling SSL bumping in configuration"
  # Comment out SSL-related directives in squid.conf if the helper doesn't exist
  sed -i 's/^ssl_bump/#ssl_bump/g' /etc/squid/squid.conf
  sed -i 's/^sslproxy_cert_error/#sslproxy_cert_error/g' /etc/squid/squid.conf
  sed -i 's/^sslcrtd_program/#sslcrtd_program/g' /etc/squid/squid.conf
  sed -i 's/^sslcrtd_children/#sslcrtd_children/g' /etc/squid/squid.conf
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

echo "Starting supervisord..."
exec "$@"