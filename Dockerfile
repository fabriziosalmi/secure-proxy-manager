FROM ubuntu:latest

# Install Squid
RUN apt-get update && \
    apt-get install -y squid && \
    rm -rf /var/lib/apt/lists/*

# Create cache directory and set permissions
RUN mkdir -p /var/spool/squid && \
    chown -R squid:squid /var/spool/squid

# Copy the generated squid.conf file
COPY squid.conf /etc/squid/squid.conf

# Initialize the cache directory
RUN squid -z

# Expose Squid port
EXPOSE 3128

# Start Squid in the foreground
CMD ["squid", "-N"]
