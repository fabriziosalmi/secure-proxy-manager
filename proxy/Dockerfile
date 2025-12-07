FROM ubuntu:22.04

RUN echo "Acquire::http::Pipeline-Depth 0;" > /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::BrokenProxy true;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get update && \
    apt-get install -y --fix-missing \
    squid \
    squid-common \
    iproute2 \
    iptables \
    net-tools \
    procps \
    curl \
    nano \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create directories for blacklists
RUN mkdir -p /etc/squid/blacklists/ip
RUN mkdir -p /etc/squid/blacklists/domain
RUN mkdir -p /config

# Create directory for icons if it doesn't exist
RUN mkdir -p /usr/share/squid/icons

# Copy config files
COPY squid.conf /etc/squid/squid.conf
COPY startup.sh /startup.sh

# Configure supervisor
COPY squid-supervisor.conf /etc/supervisor/conf.d/

# Make startup script executable
RUN chmod +x /startup.sh

# Expose Squid proxy port
EXPOSE 3128

# Set the startup script as entrypoint
ENTRYPOINT ["/startup.sh"]