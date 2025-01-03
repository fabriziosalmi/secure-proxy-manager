FROM ubuntu:latest

# Install Squid and dependencies
RUN apt-get update && apt-get install -y squid

# Copy configuration files
COPY squid.conf /etc/squid/squid.conf
COPY ip_blacklist*.txt /etc/squid/
COPY dns_blacklist*.txt /etc/squid/
COPY owasp.rules /etc/squid/owasp.rules
COPY vpn_ips*.txt /etc/squid/
COPY tor_ips*.txt /etc/squid/
COPY cloudflare_ips*.txt /etc/squid/
COPY aws_ips*.txt /etc/squid/
COPY microsoft_ips*.txt /etc/squid/
COPY google_ips*.txt /etc/squid/

# Expose Squid ports
EXPOSE 3128
EXPOSE 3129

# Start Squid
CMD ["squid", "-N"]
