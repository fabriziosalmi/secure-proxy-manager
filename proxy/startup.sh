#!/bin/bash

# ── Helper functions ─────────────────────────────────────────────────────────

ensure_ip_blocking_rules() {
    local conf="$1"
    local needs_acls=false
    local needs_deny=false

    if ! grep -q "acl direct_ip_url" "$conf" || ! grep -q "acl direct_ip_host" "$conf"; then
        needs_acls=true
    fi
    if ! grep -q "http_access deny direct_ip_url" "$conf" || ! grep -q "http_access deny direct_ip_host" "$conf"; then
        needs_deny=true
    fi

    if $needs_acls || $needs_deny; then
        echo "Adding missing direct IP blocking rules..."
        cat >> "$conf" << 'EOL'

# ==== CRITICAL SECURITY RULES (auto-added by startup) ====
acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]
acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$

http_access allow ip_whitelist
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
# ==== END CRITICAL SECURITY RULES ====
EOL
        echo "Direct IP blocking rules added."
    else
        echo "Direct IP blocking rules already present."
    fi
}

verify_config_feature() {
    local label="$1"
    local pattern="$2"
    if grep -q "$pattern" /etc/squid/squid.conf; then
        echo "  [ok] $label"
    else
        echo "  [--] $label (may be disabled)"
    fi
}

# ── Directory setup ──────────────────────────────────────────────────────────

mkdir -p /etc/squid/blacklists/ip /etc/squid/blacklists/domain /etc/squid/whitelists/ip
mkdir -p /config/ssl_db
chmod 700 /config/ssl_db

# ── SSL certificates ────────────────────────────────────────────────────────

if [ ! -f /config/ssl_cert.pem ] || [ ! -f /config/ssl_key.pem ]; then
    echo "Generating SSL certificates for HTTPS filtering..."
    openssl genrsa -out /config/ssl_key.pem 2048
    openssl req -new -key /config/ssl_key.pem -x509 -days 3650 -out /config/ssl_cert.pem \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=SecureProxy/CN=secure-proxy.local"
    chmod 400 /config/ssl_key.pem
    chmod 444 /config/ssl_cert.pem
    echo "SSL certificates generated."
else
    echo "Using existing SSL certificates."
fi

if [ ! -d /config/ssl_db/db ] || [ -z "$(ls -A /config/ssl_db)" ]; then
    echo "Initializing SSL certificate database..."
    /usr/lib/squid/security_file_certgen -c -s /config/ssl_db -M 4MB
    echo "SSL certificate database initialized."
else
    echo "Using existing SSL certificate database."
fi

# ── Empty blacklist placeholders ─────────────────────────────────────────────

touch /etc/squid/blacklists/ip/local.txt
touch /etc/squid/blacklists/domain/local.txt
touch /etc/squid/whitelists/ip/local.txt

# ── Stop any existing Squid ──────────────────────────────────────────────────

if [ -f /run/squid.pid ]; then
    pid=$(cat /run/squid.pid)
    if ps -p $pid > /dev/null 2>&1; then
        kill $pid
        sleep 2
    fi
    rm -f /run/squid.pid
fi
pkill -15 squid 2>/dev/null || true
sleep 2

# ── iptables for transparent proxy ──────────────────────────────────────────

iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128

# ── Generate base Squid configuration ────────────────────────────────────────

echo "Setting up Squid configuration..."
cat > /etc/squid/squid.conf.base << 'EOL'
http_port 3128
visible_hostname secure-proxy

# Access control lists
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# SSL/HTTPS related ACLs
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl Safe_ports port 21
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777

# Blacklists and whitelists
acl ip_blacklist src "/etc/squid/blacklists/ip/local.txt"
acl ip_whitelist dst "/etc/squid/whitelists/ip/local.txt"
acl domain_blacklist dstdomain "/etc/squid/blacklists/domain/local.txt"

# Direct IP access detection
acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]
acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$

# HTTP method definitions
acl CONNECT method CONNECT

# Access rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow ip_whitelist
http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
http_access deny ip_blacklist
http_access deny domain_blacklist
http_access allow localnet
http_access allow localhost
http_access deny all

# Caching
cache_mem 256 MB
maximum_object_size_in_memory 512 KB
memory_replacement_policy lru
cache_replacement_policy heap LFUDA
cache_dir ufs /var/spool/squid 2000 16 256
maximum_object_size 100 MB
coredump_dir /var/spool/squid

# Internal DNS resolver (dnsmasq blackhole for blocked domains)
dns_nameservers dns

# ICAP WAF
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Client-Username
icap_preview_enable on
icap_preview_size 1024
icap_service service_req reqmod_precache bypass=0 icap://waf:1344/waf
adaptation_access service_req allow all

# Logging
debug_options ALL,2
access_log daemon:/var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log stdio:/var/log/squid/store.log

# Timeouts
connect_timeout 30 seconds
dns_timeout 5 seconds

refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
EOL

# ── Apply custom config or fall back to base ─────────────────────────────────

if [ -f /config/custom_squid.conf ]; then
    echo "Applying custom configuration from /config/custom_squid.conf"
    cp /config/custom_squid.conf /etc/squid/squid.conf
elif [ -f /config/squid.conf ]; then
    echo "Applying configuration from /config/squid.conf"
    cp /config/squid.conf /etc/squid/squid.conf
elif [ -f /config/squid/squid.conf ]; then
    echo "Applying configuration from /config/squid/squid.conf"
    cp /config/squid/squid.conf /etc/squid/squid.conf
else
    echo "No custom configuration found, using base configuration."
    cp /etc/squid/squid.conf.base /etc/squid/squid.conf
fi

# ── Ensure critical security rules are present ──────────────────────────────

ensure_ip_blocking_rules /etc/squid/squid.conf

# ── Copy blacklists from config volume ───────────────────────────────────────

[ -f /config/ip_blacklist.txt ]     && cp /config/ip_blacklist.txt /etc/squid/blacklists/ip/local.txt
[ -f /config/ip_whitelist.txt ]     && cp /config/ip_whitelist.txt /etc/squid/whitelists/ip/local.txt
[ -f /config/domain_blacklist.txt ] && cp /config/domain_blacklist.txt /etc/squid/blacklists/domain/local.txt

# ── Prepare directories and permissions ──────────────────────────────────────

mkdir -p /var/log/squid /var/spool/squid /run/squid /var/run/squid /var/log/supervisor
chown -R proxy:proxy /var/log/squid /var/spool/squid /run/squid /var/run/squid
chmod 755 /run/squid /var/run/squid
touch /run/squid/squid.pid /run/squid.pid
chown proxy:proxy /run/squid/squid.pid /run/squid.pid

# ── Initialize swap directories ─────────────────────────────────────────────

su - proxy -s /bin/bash -c "/usr/sbin/squid -z"
sleep 2

# ── Validate configuration ──────────────────────────────────────────────────

echo "Validating Squid configuration..."
if /usr/sbin/squid -k parse; then
    echo "Configuration syntax is valid."
else
    echo "Configuration has errors, falling back to base..."
    [ ! -f /etc/squid/squid.conf.backup ] && cp /etc/squid/squid.conf /etc/squid/squid.conf.backup
    cp /etc/squid/squid.conf.base /etc/squid/squid.conf
    ensure_ip_blocking_rules /etc/squid/squid.conf
fi

# ── Final verification ──────────────────────────────────────────────────────

echo "Configuration verification:"
verify_config_feature "Direct IP blocking"      "acl direct_ip_url"
verify_config_feature "Cache configuration"      "cache_dir ufs"
verify_config_feature "Local network access"     "acl localnet src"
verify_config_feature "IP blacklist"             "acl ip_blacklist"
verify_config_feature "Domain blacklist"         "acl domain_blacklist"
verify_config_feature "Connection timeout"       "connect_timeout"
verify_config_feature "DNS timeout"              "dns_timeout"
verify_config_feature "Logging"                  "debug_options"

# ── Start supervisor ────────────────────────────────────────────────────────

echo "Starting supervisor..."
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
