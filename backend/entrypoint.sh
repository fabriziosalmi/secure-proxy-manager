#!/bin/sh
set -e

# Fix permissions on mounted volumes before dropping to proxyuser.
# Host-mounted dirs (./data, ./config, ./logs) may be root-owned.

for dir in /data /logs; do
    if [ -d "$dir" ]; then
        chown -R proxyuser:proxyuser "$dir" 2>/dev/null || chmod -R 777 "$dir" 2>/dev/null || true
    fi
done

# Ensure dnsmasq.d exists and is writable
mkdir -p /config/dnsmasq.d 2>/dev/null || true
chmod 777 /config/dnsmasq.d 2>/dev/null || true

# Drop to proxyuser
exec gosu proxyuser "$@"
