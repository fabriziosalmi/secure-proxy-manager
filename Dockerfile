FROM ubuntu:latest

# Install Squid and other necessary packages
RUN apt-get update && \
    apt-get install -y squid netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Create cache and log directories and set permissions
RUN mkdir -p /var/spool/squid /var/log/squid && \
    chown -R squid:squid /var/spool/squid /var/log/squid

# Copy the entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Create directory for blacklist files
RUN mkdir -p /etc/squid/blacklists

# Expose Squid port
EXPOSE 3128

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
