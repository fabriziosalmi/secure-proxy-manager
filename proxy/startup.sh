#!/bin/bash

# Create directories for blacklists if they don't exist
mkdir -p /etc/squid/blacklists/ip
mkdir -p /etc/squid/blacklists/domain

# Create empty blacklist files if they don't exist
touch /etc/squid/blacklists/ip/local.txt
touch /etc/squid/blacklists/domain/local.txt

# Make sure Squid is not running
if [ -f /run/squid.pid ]; then
  echo "Terminating existing Squid process..."
  pid=$(cat /run/squid.pid)
  if ps -p $pid > /dev/null; then
    kill $pid
    sleep 2
  fi
  rm -f /run/squid.pid
fi

# Kill any squid processes that might be running
pkill -9 squid || true
sleep 2

# Configure iptables for transparent proxy
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128

# Apply custom configurations if they exist
if [ -f /config/custom_squid.conf ]; then
    cp /config/custom_squid.conf /etc/squid/squid.conf
fi

# Apply IP blacklists if they exist
if [ -f /config/ip_blacklist.txt ]; then
    cp /config/ip_blacklist.txt /etc/squid/blacklists/ip/local.txt
fi

# Apply domain blacklists if they exist
if [ -f /config/domain_blacklist.txt ]; then
    cp /config/domain_blacklist.txt /etc/squid/blacklists/domain/local.txt
fi

# Create log directory if it doesn't exist
mkdir -p /var/log/squid
chown -R proxy:proxy /var/log/squid

# Create and initialize Squid cache directories
echo "Initializing Squid cache directories..."
mkdir -p /var/spool/squid
chown -R proxy:proxy /var/spool/squid

# Initialize swap directories
/usr/sbin/squid -z

# Wait a moment to ensure initialization completes
sleep 2

# Start Squid in foreground mode
echo "Starting Squid proxy service..."
exec /usr/sbin/squid -N -d 1