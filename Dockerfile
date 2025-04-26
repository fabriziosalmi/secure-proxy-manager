FROM alpine:3.15

# Install required packages
RUN apk update && \
    apk add --no-cache \
    squid \
    sudo \
    python3 \
    py3-pip \
    supervisor \
    curl \
    # Additional dependencies for potential Python module compilation
    gcc \
    python3-dev \
    musl-dev \
    linux-headers

# Install Python dependencies from requirements.txt
COPY flask_backend/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Create necessary directories and set permissions
RUN mkdir -p /var/log/squid /var/cache/squid /etc/squid && \
    chown -R squid:squid /var/log/squid /var/cache/squid && \
    chmod -R 750 /var/log/squid /var/cache/squid

# Create empty blacklist files if they don't exist
RUN touch /etc/squid/blacklist_domains.txt /etc/squid/blacklist_ips.txt \
    /etc/squid/allowed_direct_ips.txt /etc/squid/bad_user_agents.txt && \
    chown root:squid /etc/squid/*.txt && \
    chmod 644 /etc/squid/*.txt

# Set up Squid configuration
COPY squid_config/squid.conf /etc/squid/squid.conf
RUN chown root:squid /etc/squid/squid.conf && \
    chmod 644 /etc/squid/squid.conf

# Initialize Squid cache
RUN squid -z -N

# Copy application files
WORKDIR /app
COPY flask_backend /app/flask_backend
COPY dashboard /app/dashboard

# Ensure proper permissions for app files
RUN chmod -R 755 /app

# Set up supervisor to manage processes
COPY supervisord.conf /etc/supervisord.conf

# Copy and set up entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV RUNNING_IN_DOCKER=true
ENV SQUID_CONFIG_DIR=/etc/squid
ENV DASHBOARD_DIR=/app/dashboard

# Expose ports
# 3128 for Squid proxy
# 5000 for Flask dashboard
EXPOSE 3128 5000

# Healthcheck to verify the application is running properly
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Set entrypoint and cmd
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]