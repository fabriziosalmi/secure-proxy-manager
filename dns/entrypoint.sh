#!/bin/sh
# Inject upstream DNS servers from env vars (defaults: malware-blocking resolvers)
DNS1="${DNS_UPSTREAM_1:-1.1.1.3}"
DNS2="${DNS_UPSTREAM_2:-9.9.9.9}"
DNS3="${DNS_UPSTREAM_3:-8.8.8.8}"

PROXY_IP="${PROXY_IP:-}"

cat >> /etc/dnsmasq.conf << EOF
server=${DNS1}
server=${DNS2}
server=${DNS3}
EOF

# WPAD auto-discovery: resolve wpad.* to the proxy/web container
if [ -n "$PROXY_IP" ]; then
    cat >> /etc/dnsmasq.conf << EOF
# WPAD auto-proxy discovery
address=/wpad/${PROXY_IP}
address=/wpad.local/${PROXY_IP}
address=/wpad.lan/${PROXY_IP}
EOF
    echo "WPAD: wpad/wpad.local/wpad.lan → ${PROXY_IP}"
fi

echo "Upstream DNS: ${DNS1}, ${DNS2}, ${DNS3}"
exec dnsmasq --no-daemon --log-facility=-
