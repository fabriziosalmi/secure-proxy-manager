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

# ── Read dynamic settings from backend DB (via config files written on save) ─

SQUID_PORT="${PROXY_PORT:-3128}"
SQUID_CACHE_MB="${PROXY_CACHE_SIZE_MB:-2000}"
SQUID_MEM_MB="${PROXY_MEMORY_CACHE_MB:-256}"

# Allow override via /config/squid_settings.env (written by backend on settings save)
if [ -f /config/squid_settings.env ]; then
    # shellcheck source=/dev/null
    . /config/squid_settings.env
fi

echo "Squid settings: port=${SQUID_PORT} cache=${SQUID_CACHE_MB}MB mem=${SQUID_MEM_MB}MB extra_ssl=${EXTRA_SSL_PORTS:-none}"

# ── Generate base Squid configuration ────────────────────────────────────────

# Ensure error-pages directory exists (in case COPY was skipped or volume mounted)
mkdir -p /etc/squid/error-pages

echo "Setting up Squid configuration..."
cat > /etc/squid/squid.conf.base << CONFEOF
http_port ${SQUID_PORT}
visible_hostname secure-proxy
pid_filename /run/squid/squid.pid

# Access control lists
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16
acl localnet src fc00::/7
acl localnet src fe80::/10

# SSL/HTTPS related ACLs
acl SSL_ports port 443
acl SSL_ports port 8443
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
# Domain blocking is handled at L3 by dnsmasq (DNS blackhole → 0.0.0.0)
# Only IP blocking remains at L7 in Squid
acl ip_blacklist src "/etc/squid/blacklists/ip/local.txt"
acl ip_whitelist dst "/etc/squid/whitelists/ip/local.txt"

# Direct IP access detection
acl direct_ip_url url_regex -i ^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
acl direct_ip_host dstdom_regex -i ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$
acl direct_ipv6_url url_regex -i ^https?://\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]
acl direct_ipv6_host dstdom_regex -i ^\[[:0-9a-fA-F]+(:[:0-9a-fA-F]*)+\]$

# HTTP method definitions
acl CONNECT method CONNECT

# Local network destinations (proxy UI, backend — should not be blocked as "direct IP")
# NOTE: 172.16.0.0/12 intentionally excluded — Docker internal networks use that range
acl local_dst dst 10.0.0.0/8 192.168.0.0/16
acl local_dst_url url_regex -i ^https?://192\.168\. ^https?://10\.

# Block dangerous HTTP methods
acl Dangerous_methods method PUT DELETE PATCH TRACE TRACK
http_access deny Dangerous_methods

# Access rules
http_access deny !Safe_ports
http_access allow CONNECT local_dst
http_access deny CONNECT !SSL_ports

# Allow whitelisted + local network destinations before blocking direct IPs
http_access allow ip_whitelist
http_access allow local_dst
http_access allow local_dst_url

http_access deny direct_ip_url
http_access deny direct_ip_host
http_access deny direct_ipv6_url
http_access deny direct_ipv6_host
http_access deny CONNECT direct_ip_host
http_access deny CONNECT direct_ipv6_host
http_access deny ip_blacklist
# domain_blacklist removed — handled by dnsmasq DNS blackhole at L3
http_access allow localnet
http_access allow localhost
http_access deny all

# Caching
cache_mem ${SQUID_MEM_MB} MB
maximum_object_size_in_memory 512 KB
memory_replacement_policy lru
cache_replacement_policy heap LFUDA
cache_dir ufs /var/spool/squid ${SQUID_CACHE_MB} 16 256
maximum_object_size 100 MB
coredump_dir /var/spool/squid

# Connection performance tuning
client_persistent_connections on
server_persistent_connections on
pipeline_prefetch on
dns_v4_first on
request_body_max_size 10 MB
reply_body_max_size 200 MB
max_filedesc 65535

# Refresh patterns — base (conservative)
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

# Allow cache manager for stats (squidclient mgr:info)
cachemgr_passwd none info menu

# Custom branded error pages
error_directory /etc/squid/error-pages

# ICAP WAF
icap_enable on
icap_send_client_ip on
icap_send_client_username on
icap_client_username_encode off
icap_client_username_header X-Client-Username
icap_preview_enable on
icap_preview_size 4096
icap_service service_req reqmod_precache bypass=0 icap://waf:1344/waf
adaptation_access service_req allow all
icap_service service_resp respmod_precache bypass=1 icap://waf:1344/waf
adaptation_access service_resp allow all

# Logging
debug_options ALL,2
access_log daemon:/var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log stdio:/var/log/squid/store.log

# Timeouts
connect_timeout 30 seconds
dns_timeout 5 seconds

# ── Protocol Hardening ───────────────────────────────────────────────────────

# Strip internal topology from outbound requests
via off
forwarded_for delete
request_header_access X-Forwarded-For deny all

# Inject HSTS on all proxied responses (force HTTPS on clients)
reply_header_add Strict-Transport-Security "max-age=31536000; includeSubDomains" all


# Strip Expect: 100-continue (anti-smuggling)
request_header_access Expect deny all

# Strip non-standard outbound headers (reduce attack surface)
request_header_access X-Forwarded-Host deny all
request_header_access X-Forwarded-Proto deny all
request_header_access Proxy-Connection deny all

# Limit request body size (10MB default, prevents exfiltration of large dumps)
request_body_max_size 10 MB

# Limit request header size (prevents header-based buffer overflow/exfil)
request_header_max_size 64 KB

CONFEOF

# ── Apply generated config, then append custom extras ────────────────────────

cp /etc/squid/squid.conf.base /etc/squid/squid.conf

# Append custom directives (extras only — do NOT override the entire config).
# Migration: if old custom_squid.conf exists, rename to custom_squid_extra.conf.
if [ -f /config/custom_squid.conf ] && [ ! -f /config/custom_squid_extra.conf ]; then
    echo "Migrating custom_squid.conf → custom_squid_extra.conf (append-only mode)"
    mv /config/custom_squid.conf /config/custom_squid_extra.conf
fi
if [ -f /config/custom_squid_extra.conf ]; then
    echo "Appending custom directives from /config/custom_squid_extra.conf"
    echo "" >> /etc/squid/squid.conf
    echo "# ── Custom extras (from custom_squid_extra.conf) ──" >> /etc/squid/squid.conf
    cat /config/custom_squid_extra.conf >> /etc/squid/squid.conf
fi

# ── Ensure critical security rules are present ──────────────────────────────

ensure_ip_blocking_rules /etc/squid/squid.conf

# ── Extra SSL Ports (from Settings > extra_ssl_ports) ──────────────────────
if [ -n "$EXTRA_SSL_PORTS" ]; then
    echo "Adding extra SSL ports: $EXTRA_SSL_PORTS"
    for p in $EXTRA_SSL_PORTS; do
        # Validate: must be a number 1-65535
        if echo "$p" | grep -qE '^[0-9]+$' && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; then
            if ! grep -q "acl SSL_ports port $p" /etc/squid/squid.conf; then
                sed -i "/^acl SSL_ports port 8443/a acl SSL_ports port $p" /etc/squid/squid.conf
                echo "  Added SSL_port $p"
            fi
        else
            echo "  Skipping invalid port: $p"
        fi
    done
fi

# ── GUI IP Whitelist Override ──────────────────────────────────────────────
if [ -n "$GUI_IP_WHITELIST" ]; then
    echo "Adding GUI IP whitelist for $GUI_IP_WHITELIST"
    sed -i "/^# Access rules/i acl gui_override dst $GUI_IP_WHITELIST\nhttp_access allow gui_override\nhttp_access allow CONNECT gui_override\n" /etc/squid/squid.conf 2>/dev/null || true
fi

# ── SSL Bump (HTTPS Inspection) — conditional on toggle file ─────────────

if [ -f /config/ssl_bump_enabled ]; then
    echo "SSL Bump ENABLED — injecting HTTPS interception config"

    # Replace http_port with https_port + ssl-bump
    sed -i 's/^http_port 3128$/http_port 3128 ssl-bump \\\n  cert=\/config\/ssl_cert.pem \\\n  key=\/config\/ssl_key.pem \\\n  generate-host-certificates=on \\\n  dynamic_cert_mem_cache_size=4MB/' /etc/squid/squid.conf

    # Add ssl_bump directives before the first http_access line
    SSL_BUMP_BLOCK=$(cat <<'SSLEOF'

# ── SSL Bump (HTTPS Inspection) ────────────────────────────────────────────
sslcrtd_program /usr/lib/squid/security_file_certgen -s /config/ssl_db -M 4MB
sslcrtd_children 3 startup=1 idle=1

# Peek at TLS ClientHello to get SNI, then bump (intercept) the connection
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Upstream TLS certificate verification — only allow errors for the
# locally-generated proxy CA, not arbitrary invalid/expired certs.
# sslproxy_cert_error deny all   (default — Squid rejects bad upstream certs)
# Note: removed blanket DONT_VERIFY_PEER to prevent MITM on upstream connections.

SSLEOF
)
    # Insert before the first "http_access" line
    sed -i "/^http_access/i\\${SSL_BUMP_BLOCK}" /etc/squid/squid.conf 2>/dev/null || \
        echo "$SSL_BUMP_BLOCK" >> /etc/squid/squid.conf

    echo "SSL Bump config injected. WAF can now inspect HTTPS content."
else
    echo "SSL Bump disabled (no /config/ssl_bump_enabled file)"
fi

# ── Aggressive Caching (toggle via settings) ────────────────────────────────

if [ -f /config/aggressive_caching_enabled ]; then
    echo "Aggressive caching ENABLED — adding override-expire refresh patterns"
    cat >> /etc/squid/squid.conf << 'CACHEEOF'

# ── Aggressive caching (override-expire for static assets) ──
refresh_pattern -i \.(jpg|jpeg|png|gif|ico|svg|webp|woff|woff2|ttf|eot|css|js)$ 10080 90% 518400 override-expire override-lastmod reload-into-ims
refresh_pattern -i \.(rpm|deb|tar|gz|bz2|xz|zip|tgz|pkg)$ 1440 90% 10080 override-expire
refresh_pattern -i \.(mp4|mp3|avi|mkv|flac|ogg|webm)$ 10080 80% 518400 override-expire
CACHEEOF
else
    echo "Aggressive caching disabled (default conservative refresh patterns)"
fi

# ── Cache Bypass Domains (from settings) ────────────────────────────────────

if [ -f /config/cache_bypass_domains.txt ] && [ -s /config/cache_bypass_domains.txt ]; then
    echo "Cache bypass domains found — adding no_cache rules"
    echo "" >> /etc/squid/squid.conf
    echo "# ── Cache bypass domains ──" >> /etc/squid/squid.conf
    echo "acl cache_bypass_domains dstdomain \"/config/cache_bypass_domains.txt\"" >> /etc/squid/squid.conf
    echo "cache deny cache_bypass_domains" >> /etc/squid/squid.conf
    echo "Cache bypass configured for $(wc -l < /config/cache_bypass_domains.txt) domains"
fi

# ── Proxy Authentication (Basic Auth for proxy users) ──────────────────────

if [ -f /config/proxy_auth_enabled ]; then
    echo "Proxy authentication ENABLED — requiring Basic Auth for proxy access"
    # Create password file if it doesn't exist (admin user same as dashboard)
    if [ ! -f /config/proxy_users.htpasswd ]; then
        if [ -n "$BASIC_AUTH_USERNAME" ] && [ -n "$BASIC_AUTH_PASSWORD" ]; then
            htpasswd -bc /config/proxy_users.htpasswd "$BASIC_AUTH_USERNAME" "$BASIC_AUTH_PASSWORD" 2>/dev/null || \
                echo "${BASIC_AUTH_USERNAME}:$(openssl passwd -apr1 "$BASIC_AUTH_PASSWORD")" > /config/proxy_users.htpasswd
            echo "Created proxy auth file with admin user"
        fi
    fi
    if [ -f /config/proxy_users.htpasswd ]; then
        cat >> /etc/squid/squid.conf << 'AUTHEOF'

# ── Proxy Authentication (Basic Auth) ──
auth_param basic program /usr/lib/squid/basic_ncsa_auth /config/proxy_users.htpasswd
auth_param basic realm Secure Proxy Manager
auth_param basic credentialsttl 8 hours
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED
http_access deny !authenticated
AUTHEOF
        echo "Proxy auth configured with $(wc -l < /config/proxy_users.htpasswd) users"
    fi
else
    echo "Proxy authentication disabled (open for localnet)"
fi

# ── Content Filtering (block downloads by file extension) ──────────────────

if [ -f /config/content_filtering_enabled ] && [ -f /config/blocked_file_types.txt ] && [ -s /config/blocked_file_types.txt ]; then
    echo "Content filtering ENABLED — blocking file types"
    echo "" >> /etc/squid/squid.conf
    echo "# ── Content filtering (blocked file extensions) ──" >> /etc/squid/squid.conf
    echo "acl blocked_extensions urlpath_regex \"/config/blocked_file_types.txt\"" >> /etc/squid/squid.conf
    echo "http_access deny blocked_extensions" >> /etc/squid/squid.conf
    echo "Content filtering configured for $(wc -l < /config/blocked_file_types.txt) extensions"
else
    echo "Content filtering disabled"
fi

# ── Time-Based Access Restrictions ─────────────────────────────────────────

if [ -f /config/time_restrictions_enabled ] && [ -f /config/time_restrictions.conf ]; then
    echo "Time-based access restrictions ENABLED"
    . /config/time_restrictions.conf
    # Parse HH:MM into HH and MM
    START_H=$(echo "$TIME_START" | cut -d: -f1)
    START_M=$(echo "$TIME_START" | cut -d: -f2)
    END_H=$(echo "$TIME_END" | cut -d: -f1)
    END_M=$(echo "$TIME_END" | cut -d: -f2)
    cat >> /etc/squid/squid.conf << TIMEEOF

# ── Time-based access restrictions ──
acl allowed_hours time MTWHFAS ${START_H}:${START_M}-${END_H}:${END_M}
http_access deny !allowed_hours localnet
TIMEEOF
    echo "Access allowed only ${TIME_START}-${TIME_END}"
else
    echo "Time-based access restrictions disabled"
fi

# ── Bandwidth Throttling (Squid delay_pools) ──────────────────────────────

if [ -f /config/bandwidth_limits_enabled ] && [ -f /config/bandwidth_limits.conf ]; then
    echo "Bandwidth throttling ENABLED"
    . /config/bandwidth_limits.conf
    # Convert Mbps to bytes/sec for aggregate, Kbps to bytes/sec for per-user
    AGG_BYTES=$(( ${BW_LIMIT_MBPS:-100} * 125000 ))
    USER_BYTES=${BW_PER_USER_KBPS:-0}
    if [ "$USER_BYTES" -gt 0 ] 2>/dev/null; then
        USER_BYTES=$(( USER_BYTES * 125 ))
    else
        USER_BYTES=-1
    fi
    cat >> /etc/squid/squid.conf << BWEOF

# ── Bandwidth throttling ──
delay_pools 1
delay_class 1 2
delay_access 1 allow localnet
delay_parameters 1 ${AGG_BYTES}/${AGG_BYTES} ${USER_BYTES}/${USER_BYTES}
BWEOF
    echo "Bandwidth: aggregate=${BW_LIMIT_MBPS}Mbps per-user=${BW_PER_USER_KBPS}Kbps"
else
    echo "Bandwidth throttling disabled"
fi

# ── Offline Mode / Serve Stale Cache ────────────────────────────────────────

if [ -f /config/offline_mode_enabled ]; then
    echo "Offline mode ENABLED — serving stale cached content"
    cat >> /etc/squid/squid.conf << 'OFFEOF'

# ── Offline mode: serve stale cache when origin is unreachable ──
offline_mode on
refresh_pattern . 525600 100% 525600 override-expire override-lastmod reload-into-ims ignore-reload ignore-no-store ignore-private
OFFEOF
fi

# ── Inject dnsmasq as DNS resolver (resolve container IP dynamically) ────────

# DNS: use dnsmasq for domain blackhole. Resolve WAF IP at boot time
# and replace the hostname in ICAP config so Squid doesn't need DNS for WAF.
DNS_IP=$(getent hosts dns 2>/dev/null | awk '{print $1}')
WAF_IP=$(getent hosts waf 2>/dev/null | awk '{print $1}')

if [ -n "$DNS_IP" ]; then
    if ! grep -q "dns_nameservers" /etc/squid/squid.conf; then
        # Ensure newline before appending (fixes concatenation with last line)
        echo "" >> /etc/squid/squid.conf
        echo "dns_nameservers $DNS_IP" >> /etc/squid/squid.conf
    fi
    echo "DNS resolver: dnsmasq at $DNS_IP"
fi

# Replace 'waf' hostname with resolved IP in ICAP config (avoid DNS loop)
if [ -n "$WAF_IP" ]; then
    sed -i "s|icap://waf:|icap://$WAF_IP:|g" /etc/squid/squid.conf
    echo "ICAP WAF: resolved waf → $WAF_IP"
fi

# ── Custom error pages (only for ACL denies, not replacing all errors) ────────

if [ -f /etc/squid/error-pages/ERR_ACCESS_DENIED ] && ! grep -q "deny_info" /etc/squid/squid.conf; then
    echo "deny_info ERR_ACCESS_DENIED all" >> /etc/squid/squid.conf
    # Copy our custom page as the default Squid error page location
    cp /etc/squid/error-pages/ERR_ACCESS_DENIED /usr/share/squid/errors/en/ERR_ACCESS_DENIED 2>/dev/null || true
    echo "Custom block page enabled for ACL denies"
fi

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
