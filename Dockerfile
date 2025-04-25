FROM alpine:3.15

# Install required packages
RUN apk update && \
    apk add --no-cache \
    squid \
    python3 \
    py3-pip \
    supervisor \
    curl

# Install Python dependencies from requirements.txt
COPY flask_backend/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Create necessary directories and set permissions
RUN mkdir -p /var/log/squid /var/cache/squid && \
    chown -R squid:squid /var/log/squid /var/cache/squid && \
    chmod -R 750 /var/log/squid /var/cache/squid

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

# Set up supervisor to manage processes
COPY supervisord.conf /etc/supervisord.conf

# Copy and set up entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

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