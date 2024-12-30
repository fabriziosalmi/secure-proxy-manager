FROM ubuntu:latest

RUN apt-get update && apt-get install -y squid wget curl dnsutils net-tools jq && \
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
RUN echo "DEBUG: config.yaml content:"
RUN cat /config.yaml
RUN sources_json_dns=$(jq -c ".blocklists.dns.sources" /config.yaml)
RUN echo "DEBUG: sources_json for dns: $sources_json_dns"
RUN local_file_dns=$(jq -r '.blocklists.dns.local_file' "$CONFIG_YAML")
RUN echo "DEBUG: local_file_dns : $local_file_dns"
RUN sources_json_ip=$(jq -c ".blocklists.ip.sources" /config.yaml)
RUN echo "DEBUG: sources_json for ip: $sources_json_ip"
RUN local_file_ip=$(jq -r '.blocklists.ip.local_file' "$CONFIG_YAML")
RUN echo "DEBUG: local_file_ip : $local_file_ip"

RUN /squid-config/generate_squid_conf.sh

# Expose Squid ports
EXPOSE 3128
EXPOSE 3129

# Start Squid
CMD ["squid", "-N", "-d1"]
