#!/bin/sh

# Ensure directories exist with proper permissions
mkdir -p /var/log/squid /var/cache/squid
chown -R squid:squid /var/log/squid /var/cache/squid
chmod -R 750 /var/log/squid /var/cache/squid

# Initialize Squid cache if needed
if [ ! -d /var/cache/squid/00 ]; then
  echo "Initializing Squid cache..."
  squid -z -N
fi

# Execute the passed command (should be supervisord)
exec "$@"