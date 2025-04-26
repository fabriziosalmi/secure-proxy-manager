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
fi

# Ensure the configuration always contains direct IP blocking, even if not in the custom config
grep -q "direct_ip_url" /etc/squid/squid.conf
if [ $? -ne 0 ]; then
    echo "Adding missing direct IP blocking rules to configuration"
    cat >> /etc/squid/squid.conf << EOL

# Direct IP access detection - added by startup script
acl direct_ip_url url_regex -i ^https?://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]
acl direct_ipv6_host dstdom_regex -i ^\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]$

# Block direct IP access - added by startup script
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
EOL
fi

# Output the contents of the squid configuration
echo "Current Squid configuration:"
cat /etc/squid/squid.conf

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

# Validate Squid configuration before starting
echo "Validating Squid configuration syntax..."
if /usr/sbin/squid -k parse; then
    echo "✅ Squid configuration syntax is valid"
else
    echo "❌ Squid configuration has syntax errors, attempting to fix..."
    # Create a minimal working configuration if the current one is invalid
    if [ ! -f /etc/squid/squid.conf.backup ]; then
        cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    fi
    
    # Use a minimal default configuration
    cat > /etc/squid/squid.conf << EOL
http_port 3128
visible_hostname secure-proxy

acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl Safe_ports port 21
acl Safe_ports port 1025-65535

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost
http_access allow localnet
http_access deny all

cache_dir ufs /var/spool/squid 1000 16 256
coredump_dir /var/spool/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320

# Direct IP blocking - added by recovery script
acl direct_ip_url url_regex -i ^https?://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]
acl direct_ipv6_host dstdom_regex -i ^\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]$
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
EOL

    echo "⚠️ Applied a minimal working configuration to recover functionality"
fi

# Comprehensive configuration verification
echo "Verifying all UI settings are properly reflected in Squid configuration..."

# Verify direct IP blocking
if grep -q "acl direct_ip_url" /etc/squid/squid.conf && grep -q "acl direct_ip_host" /etc/squid/squid.conf; then
    echo "✅ Direct IP access blocking configuration found"
    
    # Also verify the http_access deny rules exist
    if grep -q "http_access deny direct_ip_url" /etc/squid/squid.conf && grep -q "http_access deny direct_ip_host" /etc/squid/squid.conf; then
        echo "✅ Direct IP access deny rules found"
    else
        echo "⚠️ Direct IP access deny rules missing, adding them"
        cat >> /etc/squid/squid.conf << EOL

# Block direct IP access - added by verification
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
EOL
    fi
else
    echo "⚠️ Direct IP access blocking configuration missing, adding it"
    cat >> /etc/squid/squid.conf << EOL

# Direct IP access detection - added by verification
acl direct_ip_url url_regex -i ^https?://([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]
acl direct_ipv6_host dstdom_regex -i ^\\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\\]$

# Block direct IP access - added by verification
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
EOL
fi

# Verify caching settings
if grep -q "cache_dir ufs /var/spool/squid" /etc/squid/squid.conf; then
    echo "✅ Cache size configuration found"
else
    echo "⚠️ Cache size configuration missing"
fi

if grep -q "maximum_object_size" /etc/squid/squid.conf; then
    echo "✅ Maximum object size configuration found"
else
    echo "⚠️ Maximum object size configuration missing"
fi

# Verify network access controls
if grep -q "acl localnet src" /etc/squid/squid.conf; then
    echo "✅ Local network access configuration found"
else
    echo "⚠️ Local network access configuration missing"
fi

# Verify IP/domain blacklists
if grep -q "acl ip_blacklist" /etc/squid/squid.conf; then
    echo "✅ IP blacklist configuration found"
else
    echo "⚠️ IP blacklist configuration missing"
fi

if grep -q "acl domain_blacklist" /etc/squid/squid.conf; then
    echo "✅ Domain blacklist configuration found"
else
    echo "⚠️ Domain blacklist configuration missing"
fi

# Verify direct IP blocking
if grep -q "acl direct_ip_url" /etc/squid/squid.conf && grep -q "acl direct_ip_host" /etc/squid/squid.conf; then
    echo "✅ Direct IP access blocking configuration found"
else
    echo "⚠️ Direct IP access blocking configuration missing"
fi

# Verify content filtering
if grep -q "acl blocked_extensions" /etc/squid/squid.conf; then
    echo "✅ Content filtering configuration found"
else
    echo "⚠️ Content filtering configuration may be disabled"
fi

# Verify time restrictions
if grep -q "acl allowed_hours time" /etc/squid/squid.conf; then
    echo "✅ Time restriction configuration found"
else
    echo "⚠️ Time restriction configuration may be disabled"
fi

# Verify performance settings
if grep -q "connect_timeout" /etc/squid/squid.conf; then
    echo "✅ Connection timeout configuration found"
else
    echo "⚠️ Connection timeout configuration missing"
fi

if grep -q "dns_timeout" /etc/squid/squid.conf; then
    echo "✅ DNS timeout configuration found"
else
    echo "⚠️ DNS timeout configuration missing"
fi

# Check for HTTP compression
if grep -q "zph_mode" /etc/squid/squid.conf; then
    echo "✅ HTTP compression configuration found"
else
    echo "⚠️ HTTP compression may be disabled"
fi

# Verify logging settings
if grep -q "debug_options" /etc/squid/squid.conf; then
    echo "✅ Logging level configuration found"
else
    echo "⚠️ Logging level configuration missing"
fi

# Verify that all http_access rules are in the configuration
echo "Verifying access control rules..."
grep "http_access" /etc/squid/squid.conf

# Start Squid in foreground mode
echo "Starting Squid proxy service with config:"
cat /etc/squid/squid.conf
echo "-------------------------------------"
exec /usr/sbin/squid -N -d 1