FROM ubuntu:latest

# Install Squid and dependencies
RUN apt-get update && apt-get install -y squid

# Copy configuration files
COPY squid.conf /etc/squid/squid.conf
COPY ip_blacklist*.txt /etc/squid/
COPY dns_blacklist*.txt /etc/squid/
COPY temp_squid_files/owasp.rules /etc/squid/owasp.rules
COPY temp_squid_files/vpn_ips*.txt /etc/squid/
COPY temp_squid_files/tor_ips*.txt /etc/squid/
COPY temp_squid_files/cloudflare_ips*.txt /etc/squid/
COPY temp_squid_files/aws_ips*.txt /etc/squid/
COPY temp_squid_files/microsoft_ips*.txt /etc/squid/
COPY temp_squid_files/google_ips*.txt /etc/squid/


# Expose Squid ports
EXPOSE 3128
EXPOSE 3129

# Start Squid
CMD ["squid", "-N"]
