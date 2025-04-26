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

# Check for all possible locations of the custom Squid configuration
echo "Checking for custom Squid configurations..."
if [ -f /config/custom_squid.conf ]; then
    echo "Found /config/custom_squid.conf - applying this configuration"
    cp /config/custom_squid.conf /etc/squid/squid.conf
elif [ -f /config/squid.conf ]; then
    echo "Found /config/squid.conf - applying this configuration"
    cp /config/squid.conf /etc/squid/squid.conf
elif [ -f /config/squid/squid.conf ]; then
    echo "Found /config/squid/squid.conf - applying this configuration"
    cp /config/squid/squid.conf /etc/squid/squid.conf
else
    echo "No custom configuration found - using default configuration"
    # Ensure default configuration has direct IP blocking enabled
    grep -q "direct_ip_url" /etc/squid/squid.conf || echo "Warning: Default configuration may be missing direct IP blocking rules!"
fi

# Copy blacklists from config volume
if [ -f /config/ip_blacklist.txt ]; then
    echo "Applying IP blacklist..."
    cp /config/ip_blacklist.txt /etc/squid/blacklists/ip/local.txt
fi

if [ -f /config/domain_blacklist.txt ]; then
    echo "Applying domain blacklist..."
    cp /config/domain_blacklist.txt /etc/squid/blacklists/domain/local.txt
fi

# Output the blacklists for debugging
echo "IP Blacklist contents:"
cat /etc/squid/blacklists/ip/local.txt
echo "Domain Blacklist contents:"
cat /etc/squid/blacklists/domain/local.txt

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

# Verify configuration contains direct IP blocking rules
echo "Verifying configuration contains direct IP blocking rules..."
if grep -q "direct_ip_url" /etc/squid/squid.conf && grep -q "http_access deny direct_ip" /etc/squid/squid.conf; then
    echo "✅ Configuration contains direct IP blocking rules"
else
    echo "⚠️ WARNING: Configuration may be missing direct IP blocking rules!"
    echo "Current http_access rules:"
    grep "http_access" /etc/squid/squid.conf
fi