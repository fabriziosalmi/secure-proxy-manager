# Pin: ubuntu 22.04 jammy (LTS)
FROM ubuntu:22.04

RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::BrokenProxy true;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --fix-missing \
    squid-openssl \
    squid-common \
    iproute2 \
    iptables \
    net-tools \
    procps \
    curl \
    openssl \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/squid/blacklists/ip /etc/squid/blacklists/domain /config /usr/share/squid/icons

COPY squid.conf /etc/squid/squid.conf
COPY startup.sh /startup.sh
COPY blacklist_watchdog.py /usr/local/bin/blacklist_watchdog.py
# Staged outside /etc/squid because that path is a tmpfs at runtime (which would
# overmount and wipe a baked-in copy). startup.sh installs these into
# /etc/squid/error-pages on boot.
COPY error-pages/ /opt/squid-error-pages/
COPY squid-supervisor.conf /etc/supervisor/conf.d/

RUN chmod +x /startup.sh /usr/local/bin/blacklist_watchdog.py

RUN mkdir -p /run/squid /var/run/squid && chown -R proxy:proxy /run/squid /var/run/squid

EXPOSE 3128

ENTRYPOINT ["/startup.sh"]
