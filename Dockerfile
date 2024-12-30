FROM ubuntu:latest

RUN apt-get update && apt-get install -y squid wget curl dnsutils net-tools && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /squid-config /data/blocklists /data/ssl
WORKDIR /

# Copy configuration files and scripts
COPY squid-config/ /squid-config/
COPY config.yaml /config.yaml
COPY data/ssl/ /data/ssl/

# Copy scripts
COPY  squid-config/generate_squid_conf.sh  /squid-config/

# Set script executable permissions
RUN chmod +x /squid-config/generate_squid_conf.sh


# Run configuration generation
RUN /squid-config/generate_squid_conf.sh

# Expose Squid ports
EXPOSE 3128
EXPOSE 3129

# Start Squid
CMD ["squid", "-N", "-d1"]
