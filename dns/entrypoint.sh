#!/bin/sh
# Inject upstream DNS servers from env vars (defaults: malware-blocking resolvers)
DNS1="${DNS_UPSTREAM_1:-1.1.1.3}"
DNS2="${DNS_UPSTREAM_2:-9.9.9.9}"
DNS3="${DNS_UPSTREAM_3:-8.8.8.8}"

PROXY_IP="${PROXY_IP:-}"

# How often the SafeSearch and YouTube enforcement targets are resolved again
# while dnsmasq runs (see targets_moved).
ENFORCE_REFRESH="${SAFESEARCH_REFRESH_SECONDS:-3600}"
case "$ENFORCE_REFRESH" in
    ''|*[!0-9]*) echo "WARNING: SAFESEARCH_REFRESH_SECONDS=$ENFORCE_REFRESH is not a number of seconds; using 3600" >&2
                 ENFORCE_REFRESH=3600 ;;
esac

# ipv4_set NAME: the IPv4 addresses of NAME from the first upstream resolver
# that has any; fails when none answers. dnsmasq follows a cname= only to a
# name it knows locally (hosts, host-record, DHCP); a target set with
# address= or left to upstream does not count, so a cname= alone answered the
# CNAME with no address and every client failed to connect (SafeSearch made
# www.google.com unreachable). The enforcement targets are therefore resolved
# here and declared with host-record=.
ipv4_set() {
    for _srv in "$DNS1" "$DNS2" "$DNS3"; do
        _set=$(dig +short +time=2 +tries=1 "$1" A @"$_srv" 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
        if [ -n "$_set" ]; then
            echo "$_set"
            return 0
        fi
    done
    return 1
}

# enforce_target NAME FALLBACK LABEL: a host-record= for NAME, on its first
# upstream address, else FALLBACK. With neither the target is pinned to
# 0.0.0.0: the service is blocked rather than left unfiltered while its
# enforcement is on, until a refresh resolves it.
enforce_target() {
    _ip=$(ipv4_set "$1" | head -1)
    [ -n "$_ip" ] || _ip="$2"
    if [ -z "$_ip" ]; then
        echo "WARNING: $3: $1 did not resolve; blocked (0.0.0.0) until it does (checked every ${ENFORCE_REFRESH}s)" >&2
        _ip=0.0.0.0
    fi
    echo "host-record=$1,$_ip"
}

# targets_moved: true when every enforcement target in the running config
# answered and at least one address in use is no longer among its answers
# (the Bing and DuckDuckGo targets sit on CDNs, and a target pinned to
# 0.0.0.0 at start has an answer now). A target with no answer keeps the
# running config as it is.
targets_moved() {
    _moved=0
    for _line in $(grep '^host-record=' /tmp/dnsmasq.conf 2>/dev/null); do
        _rec=${_line#host-record=}
        _set=$(ipv4_set "${_rec%%,*}") || return 1
        echo "$_set" | grep -qxF "${_rec#*,}" || _moved=1
    done
    [ "$_moved" = 1 ]
}

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
# 216.239.38.120 is the address Google documents for forcesafesearch.
$(enforce_target forcesafesearch.google.com 216.239.38.120 SafeSearch)
$(enforce_target strict.bing.com "" SafeSearch)
$(enforce_target safe.duckduckgo.com "" SafeSearch)
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
# 216.239.38.120 is the address Google documents for restrict.youtube.com.
$(enforce_target restrict.youtube.com 216.239.38.120 "YouTube Restricted Mode")
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

    local since_refresh=0

    echo "[watchdog] Started dnsmasq sidecar watch loop"

    while true; do
        sleep 2

        # 0. Re-resolve the SafeSearch/YouTube enforcement targets
        since_refresh=$((since_refresh + 2))
        if [ "$since_refresh" -ge "$ENFORCE_REFRESH" ]; then
            since_refresh=0
            if targets_moved; then
                echo "[watchdog] a SafeSearch/YouTube target address changed, restarting dnsmasq process..."
                killall dnsmasq 2>/dev/null || true
            fi
        fi

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

# /var/log is the shared ./logs bind-mount, owned by a different UID than this
# container (the proxy creates those files as its own user). With cap_drop: ALL
# even root is subject to DAC checks, so writing there needs CAP_DAC_OVERRIDE
# (added to the dns service) AND dnsmasq must stay root to keep that capability —
# dropping to an unprivileged user would lose it and fail with "cannot open log
# …: Permission denied". (CI masks this by chmod a+rwX on ./logs; real deploys
# keep restrictive perms — this is the host-independent fix.)
mkdir -p /var/log
touch /var/log/dnsmasq.log 2>/dev/null || true
chmod 0644 /var/log/dnsmasq.log 2>/dev/null || true

# Foreground loop to restart dnsmasq process on configuration toggle trigger
while true; do
    build_dnsmasq_conf

    echo "Starting dnsmasq..."
    # --user=root: keep CAP_DAC_OVERRIDE so dnsmasq can write its query log on
    # the shared, differently-owned ./logs mount (the container is already root).
    dnsmasq --no-daemon --user=root --log-queries --log-facility=/var/log/dnsmasq.log --conf-file=/tmp/dnsmasq.conf
    
    echo "dnsmasq process exited, restarting in 1 second..."
    sleep 1
done
