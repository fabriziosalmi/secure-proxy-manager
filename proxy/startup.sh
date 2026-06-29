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

# Safe-source: validate a config file contains only KEY=VALUE assignments and
# comments before sourcing it. Rejects files with shell-execution characters
# (semicolons, backticks, $(), pipes, redirects, etc.) to prevent code injection
# from a shared/writable /config volume.
safe_source() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return 0
    fi
    # Reject any line that is not blank, a comment, or a simple KEY=VALUE assignment
    if grep -Pv '^\s*(#.*)?$|^\s*[A-Za-z_][A-Za-z0-9_]*=[^;`|&<>$()\n]*\s*$' "$file" > /dev/null 2>&1; then
        echo "WARNING: Refusing to source $file — contains unsafe content (non-assignment lines detected)"
        return 1
    fi
    # Reject the presence of any dangerous shell characters anywhere in the file
    if grep -Pq '[;`|&<>]|\$\(|\$\{' "$file" 2>/dev/null; then
        echo "WARNING: Refusing to source $file — contains dangerous shell characters"
        return 1
    fi
    # shellcheck source=/dev/null
    . "$file"
}

# ── Directory setup ──────────────────────────────────────────────────────────

mkdir -p /etc/squid/blacklists/ip /etc/squid/blacklists/domain /etc/squid/whitelists/ip
mkdir -p /config/ssl_db
# ssl_db must be writable by the proxy user (squid SSL bump) and readable by
# the backend health checker — 750 with proxy ownership is the safe minimum.
chown proxy:proxy /config/ssl_db
chmod 750 /config/ssl_db

# ── SSL certificates ────────────────────────────────────────────────────────

# Reject the CA private key that was historically committed to this repository.
# Any deployment still carrying it shares one public keypair with every other
# user of the project, so anyone with the repo could forge certificates and MITM
# all SSL-bumped TLS. If we detect that exact keypair (matched by modulus, so it
# survives PEM re-encoding), delete it and the cert DB it signed so a fresh,
# unique CA is generated below.
KNOWN_BAD_KEY_MODULUS_SHA256="b3443bfd0d20cec31e7a87eb77d7ebd6864253037091c69bf1d069368e089c31"
if [ -f /config/ssl_key.pem ]; then
    current_modulus_sha256="$(openssl rsa -in /config/ssl_key.pem -noout -modulus 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    if [ "$current_modulus_sha256" = "$KNOWN_BAD_KEY_MODULUS_SHA256" ]; then
        echo "SECURITY: detected the known-compromised committed CA key — deleting and regenerating a unique CA." >&2
        rm -f /config/ssl_key.pem /config/ssl_cert.pem
        rm -rf /config/ssl_db/* 2>/dev/null || true
    fi
fi

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
# Idempotent: -C checks whether the rule already exists before -A appends it, so
# a `docker restart` (which reuses the netns) does not stack duplicate REDIRECT
# rules on every boot.

iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 3128
iptables -t nat -C PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3128

# ── Generate Squid configuration ─────────────────────────────────────────────
. /usr/local/bin/generate_squid_conf.sh

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
    # Sanitize: keep only characters valid in IP addresses, CIDR notation, and
    # list separators (digits, dots, slashes, commas, spaces). This prevents
    # injection of shell metacharacters into the sed command.
    GUI_IP_WHITELIST_SAFE=$(printf '%s' "$GUI_IP_WHITELIST" | tr -cd '0-9./,: ')
    if [ -z "$GUI_IP_WHITELIST_SAFE" ]; then
        echo "WARNING: GUI_IP_WHITELIST contained no valid IP characters after sanitization — skipping"
    else
        echo "Adding GUI IP whitelist for $GUI_IP_WHITELIST_SAFE"
        sed -i "/^# Access rules/i acl gui_override dst $GUI_IP_WHITELIST_SAFE\nhttp_access allow gui_override\nhttp_access allow CONNECT gui_override\n" /etc/squid/squid.conf 2>/dev/null || true
    fi
fi

# ── Egress destination allowlist (default-deny) — conditional on toggle ──────
# When /config/egress_default_deny exists, a localnet client may reach ONLY
# destinations in the allowlists (IP/CIDR via `dst`, domain via `dstdomain`);
# anything else falls through to the final "deny all". This flips the forward
# proxy from default-allow-destination to default-deny-destination — the basis
# for a sovereign / EU-strict egress. Trusted sources (ip_whitelist) and local
# infrastructure (local_dst) are allowed earlier and are unaffected.
# The allowlist files always exist (managed by the backend + watchdog); only the
# enforcement rule is gated by the toggle, so removing the toggle restores the
# prior default-allow behaviour.
mkdir -p /etc/squid/allowlists/dst_ip /etc/squid/allowlists/dst_domain
touch /etc/squid/allowlists/dst_ip/local.txt /etc/squid/allowlists/dst_domain/local.txt

if [ -f /config/egress_default_deny ]; then
    echo "Egress default-deny ENABLED — localnet reaches only allowlisted destinations"
    # ACLs: destination IP/CIDR allowlist + destination domain allowlist. Inject
    # once, at the first "acl CONNECT" (Squid evaluates the first matching
    # http_access rule, so the first rule block is authoritative).
    sed -i '0,/^acl CONNECT method CONNECT$/s|^acl CONNECT method CONNECT$|acl CONNECT method CONNECT\nacl egress_dst_allow_ip dst "/etc/squid/allowlists/dst_ip/local.txt"\nacl egress_dst_allow_dom dstdomain "/etc/squid/allowlists/dst_domain/local.txt"|' /etc/squid/squid.conf
    # Deny any localnet client whose destination is in neither allowlist,
    # immediately before the first catch-all "http_access allow localnet".
    sed -i '0,/^http_access allow localnet$/s|^http_access allow localnet$|http_access deny localnet !egress_dst_allow_ip !egress_dst_allow_dom\nhttp_access allow localnet|' /etc/squid/squid.conf

    # FAIL-CLOSED VERIFICATION. The toggle promises default-deny egress; a silent
    # default-allow (e.g. if the anchors above drifted and the sed no-op'd) would
    # be a security regression, not a cosmetic one. If the precise deny rule did
    # not land, retry with a whitespace-tolerant anchor; if it still isn't there,
    # neutralise the catch-all localnet allow so non-allowlisted egress falls
    # through to the final "http_access deny all" (hard fail-closed) rather than
    # leaking open.
    DENY_RULE='http_access deny localnet !egress_dst_allow_ip !egress_dst_allow_dom'
    if ! grep -qF "$DENY_RULE" /etc/squid/squid.conf; then
        echo "WARNING: egress deny rule not injected via primary anchor — applying tolerant fallback"
        grep -qF 'acl egress_dst_allow_ip dst' /etc/squid/squid.conf || \
            sed -i 's|^[[:space:]]*acl CONNECT method CONNECT.*|&\nacl egress_dst_allow_ip dst "/etc/squid/allowlists/dst_ip/local.txt"\nacl egress_dst_allow_dom dstdomain "/etc/squid/allowlists/dst_domain/local.txt"|' /etc/squid/squid.conf
        # Insert the deny immediately before any localnet allow (leading/internal
        # whitespace and trailing tokens tolerated). "&" re-emits the matched
        # allow line after.
        sed -i "s|^[[:space:]]*http_access[[:space:]]\\+allow[[:space:]]\\+localnet.*|${DENY_RULE}\\n&|" /etc/squid/squid.conf
    fi
    if ! grep -qF "$DENY_RULE" /etc/squid/squid.conf; then
        echo "CRITICAL: could not enforce egress default-deny — denying ALL localnet egress (fail-closed)"
        sed -i 's|^[[:space:]]*http_access[[:space:]]\+allow[[:space:]]\+localnet.*|http_access deny localnet  # egress default-deny: enforcement injection failed — fail-closed|' /etc/squid/squid.conf
    else
        echo "Egress default-deny enforcement rule verified present"
    fi
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
    safe_source /config/time_restrictions.conf
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
    safe_source /config/bandwidth_limits.conf
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
# Initial copy at startup; the watchdog (below) keeps them in sync at runtime.

[ -f /config/ip_blacklist.txt ]     && cp /config/ip_blacklist.txt /etc/squid/blacklists/ip/local.txt
[ -f /config/ip_whitelist.txt ]     && cp /config/ip_whitelist.txt /etc/squid/whitelists/ip/local.txt
[ -f /config/domain_blacklist.txt ] && cp /config/domain_blacklist.txt /etc/squid/blacklists/domain/local.txt
[ -f /config/dst_allow_ip.txt ]     && cp /config/dst_allow_ip.txt /etc/squid/allowlists/dst_ip/local.txt
[ -f /config/dst_allow_domain.txt ] && cp /config/dst_allow_domain.txt /etc/squid/allowlists/dst_domain/local.txt

# ── Blacklist watchdog (live reload + log readability) ───────────────────────
# The watchdog is shipped as /usr/local/bin/blacklist_watchdog.py and is
# registered statically in squid-supervisor.conf, so supervisord starts it on
# boot. It keeps /config blacklist files synced into the Squid ACL dirs (live
# reload via `squid -k reconfigure`) and re-asserts 0644 on the Squid logs so
# the backend container can tail them. Nothing to generate here at runtime.

# ── Prepare directories and permissions ──────────────────────────────────────

mkdir -p /var/log/squid /var/spool/squid /run/squid /var/run/squid /var/log/supervisor
chown -R proxy:proxy /var/log/squid /var/spool/squid /run/squid /var/run/squid
# Log files must be world-readable so the backend container (different UID)
# can tail access.log for analytics without requiring a shared group or
# elevated privileges.
chmod 755 /var/log/squid
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
