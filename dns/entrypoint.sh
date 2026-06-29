#!/bin/sh
# Inject upstream DNS servers from env vars (defaults: malware-blocking resolvers)
DNS1="${DNS_UPSTREAM_1:-1.1.1.3}"
DNS2="${DNS_UPSTREAM_2:-9.9.9.9}"
DNS3="${DNS_UPSTREAM_3:-8.8.8.8}"

PROXY_IP="${PROXY_IP:-}"

# Helper function to compile dnsmasq.conf dynamically based on toggles
build_dnsmasq_conf() {
    echo "Building dnsmasq configuration..."
    # Build a single merged config in /tmp (container filesystem is read-only)
    cp /etc/dnsmasq.conf /tmp/dnsmasq.conf

    cat >> /tmp/dnsmasq.conf << EOF

# ── Runtime (injected by entrypoint) ──
server=${DNS1}
server=${DNS2}
server=${DNS3}
EOF

    # WPAD auto-discovery: resolve wpad.* to the proxy/web container
    if [ -n "$PROXY_IP" ]; then
        cat >> /tmp/dnsmasq.conf << EOF
# WPAD auto-proxy discovery
address=/wpad/${PROXY_IP}
address=/wpad.local/${PROXY_IP}
address=/wpad.lan/${PROXY_IP}
EOF
        echo "WPAD: wpad/wpad.local/wpad.lan → ${PROXY_IP}"
    fi

    # SafeSearch enforcement (DNS override)
    if [ -f /config/safesearch_enabled ]; then
        cat >> /tmp/dnsmasq.conf << EOF

# ── SafeSearch (forced via DNS) ──
address=/forcesafesearch.google.com/216.239.38.120
cname=www.google.com,forcesafesearch.google.com
cname=www.google.co.uk,forcesafesearch.google.com
cname=www.google.de,forcesafesearch.google.com
cname=www.google.fr,forcesafesearch.google.com
cname=www.google.es,forcesafesearch.google.com
cname=www.google.it,forcesafesearch.google.com
cname=www.google.ca,forcesafesearch.google.com
cname=www.google.com.au,forcesafesearch.google.com
cname=www.google.com.br,forcesafesearch.google.com
cname=www.google.co.jp,forcesafesearch.google.com
cname=www.bing.com,strict.bing.com
cname=duckduckgo.com,safe.duckduckgo.com
EOF
        echo "SafeSearch: ENABLED (Google, Bing, DuckDuckGo)"
    else
        echo "SafeSearch: disabled"
    fi

    # YouTube Restricted Mode (DNS override)
    if [ -f /config/youtube_restricted_enabled ]; then
        cat >> /tmp/dnsmasq.conf << EOF

# ── YouTube Restricted Mode (forced via DNS) ──
cname=www.youtube.com,restrict.youtube.com
cname=m.youtube.com,restrict.youtube.com
cname=youtubei.googleapis.com,restrict.youtube.com
cname=youtube.googleapis.com,restrict.youtube.com
cname=www.youtube-nocookie.com,restrict.youtube.com
EOF
        echo "YouTube Restricted Mode: ENABLED"
    else
        echo "YouTube Restricted Mode: disabled"
    fi

    echo "Upstream DNS: ${DNS1}, ${DNS2}, ${DNS3}"

    # Best-effort: create an empty addn-hosts blocklist so dnsmasq doesn't warn
    touch /config/dnsmasq.d/blocklist.hosts 2>/dev/null || true
    BLOCK_COUNT=$(grep -c "^0.0.0.0 " /config/dnsmasq.d/blocklist.hosts 2>/dev/null || true)
    echo "Blocklist: ${BLOCK_COUNT:-0} entries"
}

# Background watchdog to watch configuration and blocklist changes
watch_dnsmasq() {
    # Wait for dnsmasq to start initially
    sleep 3
    local last_hosts_mtime=0
    local last_reload_mtime=0
    local last_safesearch_mtime=0
    local last_youtube_mtime=0

    # Get initial mtimes
    [ -f "/config/dnsmasq.d/blocklist.hosts" ] && last_hosts_mtime=$(stat -c %Y "/config/dnsmasq.d/blocklist.hosts" 2>/dev/null || stat -f %m "/config/dnsmasq.d/blocklist.hosts" 2>/dev/null || echo 0)
    [ -f "/config/.reload-dns" ] && last_reload_mtime=$(stat -c %Y "/config/.reload-dns" 2>/dev/null || stat -f %m "/config/.reload-dns" 2>/dev/null || echo 0)
    [ -f "/config/safesearch_enabled" ] && last_safesearch_mtime=$(stat -c %Y "/config/safesearch_enabled" 2>/dev/null || stat -f %m "/config/safesearch_enabled" 2>/dev/null || echo 0)
    [ -f "/config/youtube_restricted_enabled" ] && last_youtube_mtime=$(stat -c %Y "/config/youtube_restricted_enabled" 2>/dev/null || stat -f %m "/config/youtube_restricted_enabled" 2>/dev/null || echo 0)

    echo "[watchdog] Started dnsmasq sidecar watch loop"

    while true; do
        sleep 2

        # 1. Check blocklist.hosts
        local cur_hosts_mtime=0
        [ -f "/config/dnsmasq.d/blocklist.hosts" ] && cur_hosts_mtime=$(stat -c %Y "/config/dnsmasq.d/blocklist.hosts" 2>/dev/null || stat -f %m "/config/dnsmasq.d/blocklist.hosts" 2>/dev/null || echo 0)
        if [ "$cur_hosts_mtime" -ne "$last_hosts_mtime" ]; then
            last_hosts_mtime=$cur_hosts_mtime
            echo "[watchdog] blocklist.hosts changed, sending SIGHUP to dnsmasq..."
            killall -HUP dnsmasq 2>/dev/null || true
        fi

        # 2. Check .reload-dns trigger
        local cur_reload_mtime=0
        [ -f "/config/.reload-dns" ] && cur_reload_mtime=$(stat -c %Y "/config/.reload-dns" 2>/dev/null || stat -f %m "/config/.reload-dns" 2>/dev/null || echo 0)
        if [ "$cur_reload_mtime" -ne "$last_reload_mtime" ]; then
            last_reload_mtime=$cur_reload_mtime
            echo "[watchdog] .reload-dns triggered, sending SIGHUP to dnsmasq..."
            killall -HUP dnsmasq 2>/dev/null || true
        fi

        # 3. Check SafeSearch/YouTube toggles
        local cur_safesearch_mtime=0
        [ -f "/config/safesearch_enabled" ] && cur_safesearch_mtime=$(stat -c %Y "/config/safesearch_enabled" 2>/dev/null || stat -f %m "/config/safesearch_enabled" 2>/dev/null || echo 0)
        local cur_youtube_mtime=0
        [ -f "/config/youtube_restricted_enabled" ] && cur_youtube_mtime=$(stat -c %Y "/config/youtube_restricted_enabled" 2>/dev/null || stat -f %m "/config/youtube_restricted_enabled" 2>/dev/null || echo 0)

        if [ "$cur_safesearch_mtime" -ne "$last_safesearch_mtime" ] || [ "$cur_youtube_mtime" -ne "$last_youtube_mtime" ]; then
            last_safesearch_mtime=$cur_safesearch_mtime
            last_youtube_mtime=$cur_youtube_mtime
            echo "[watchdog] SafeSearch/YouTube toggle changed, restarting dnsmasq process..."
            killall dnsmasq 2>/dev/null || true
        fi
    done
}

# Start background watchdog
watch_dnsmasq &

# Ensure query log directory and file exist with correct permissions
mkdir -p /var/log
touch /var/log/dnsmasq.log
chmod 0644 /var/log/dnsmasq.log

# Foreground loop to restart dnsmasq process on configuration toggle trigger
while true; do
    build_dnsmasq_conf
    
    echo "Starting dnsmasq..."
    dnsmasq --no-daemon --log-queries --log-facility=/var/log/dnsmasq.log --conf-file=/tmp/dnsmasq.conf
    
    echo "dnsmasq process exited, restarting in 1 second..."
    sleep 1
done
