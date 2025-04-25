#!/bin/bash
set -e

# Create cache directories if they don't exist
if [ ! -d /var/spool/squid ]; then
    mkdir -p /var/spool/squid
    chown -R squid:squid /var/spool/squid
fi

# Create log directories if they don't exist
if [ ! -d /var/log/squid ]; then
    mkdir -p /var/log/squid
    chown -R squid:squid /var/log/squid
fi

# Initialize the Squid cache directories
if [ ! -f /var/spool/squid/swap.state ]; then
    echo "Initializing Squid cache..."
    squid -z
fi

echo "Starting Squid proxy server..."
# Start Squid in the foreground
exec squid -N "$@"