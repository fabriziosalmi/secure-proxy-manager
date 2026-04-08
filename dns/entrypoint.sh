#!/bin/sh
# Inject upstream DNS servers from env vars (defaults: malware-blocking resolvers)
DNS1="${DNS_UPSTREAM_1:-1.1.1.3}"
DNS2="${DNS_UPSTREAM_2:-9.9.9.9}"
DNS3="${DNS_UPSTREAM_3:-8.8.8.8}"

PROXY_IP="${PROXY_IP:-}"

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

# ── SafeSearch enforcement (DNS override) ──────────────────────────────────
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

# ── YouTube Restricted Mode (DNS override) ────────────────────────────────
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

# Count blocklist entries for logging
BLOCK_COUNT=0
if [ -f /config/dnsmasq.d/blocklist.conf ]; then
    BLOCK_COUNT=$(grep -c "^address=" /config/dnsmasq.d/blocklist.conf 2>/dev/null || echo 0)
fi
echo "Blocklist: ${BLOCK_COUNT} entries"

exec dnsmasq --no-daemon --log-facility=- --conf-file=/tmp/dnsmasq.conf
