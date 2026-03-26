# Pin: alpine 3.21.3
FROM alpine:3.21.3

RUN apk --no-cache add dnsmasq bind-tools

# Base config
COPY dnsmasq.conf /etc/dnsmasq.conf

# Blocklist dir — backend writes dnsmasq-blocklist.conf here on reload
RUN mkdir -p /config/dnsmasq.d

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 53/udp 53/tcp

HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
    CMD nslookup localhost 127.0.0.1 > /dev/null 2>&1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
