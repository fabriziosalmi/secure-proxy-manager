# Pin: ubuntu 22.04 jammy (LTS)
FROM ubuntu:22.04

# Squid ships from the Ubuntu security pocket, so the package REVISION (e.g.
# 5.9-0ubuntu0.22.04.7), not the upstream "5.9", is what carries CVE fixes.
#
# SQUID_MIN_VERSION is the floor the build will accept. The post-install check
# below fails the build if the installed squid is older — so an unpatched proxy
# image can never be published. Bump it whenever jammy ships a new Squid CVE fix.
#   .7 = fix for CVE-2026-47729 (Squidbleed, FTP-gateway out-of-bounds read).
#
# APT_REFRESH busts the apt layer cache. Buildx/GHA cache would otherwise reuse a
# stale apt layer and reinstall the OLD squid even after Ubuntu publishes a fix;
# CI passes a changing value so each publish re-pulls the security index.
ARG SQUID_MIN_VERSION=5.9-0ubuntu0.22.04.7
ARG APT_REFRESH=2026-06-29

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
    && squid_v="$(dpkg-query -W -f='${Version}' squid-openssl)" \
    && echo "squid-openssl installed: $squid_v (require >= $SQUID_MIN_VERSION)" \
    && if ! dpkg --compare-versions "$squid_v" ge "$SQUID_MIN_VERSION"; then \
         echo "FATAL: squid-openssl $squid_v is older than $SQUID_MIN_VERSION (CVE-2026-47729 Squidbleed unpatched) — refusing to build an unpatched proxy image"; \
         exit 1; \
       fi \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/squid/blacklists/ip /etc/squid/blacklists/domain /config /usr/share/squid/icons

COPY squid.conf /etc/squid/squid.conf
COPY startup.sh /startup.sh
COPY generate_squid_conf.sh /usr/local/bin/generate_squid_conf.sh
COPY blacklist_watchdog.py /usr/local/bin/blacklist_watchdog.py
# Staged outside /etc/squid because that path is a tmpfs at runtime (which would
# overmount and wipe a baked-in copy). startup.sh installs these into
# /etc/squid/error-pages on boot.
COPY error-pages/ /opt/squid-error-pages/
COPY squid-supervisor.conf /etc/supervisor/conf.d/

RUN chmod +x /startup.sh /usr/local/bin/blacklist_watchdog.py /usr/local/bin/generate_squid_conf.sh

RUN mkdir -p /run/squid /var/run/squid && chown -R proxy:proxy /run/squid /var/run/squid

EXPOSE 3128

ENTRYPOINT ["/startup.sh"]
