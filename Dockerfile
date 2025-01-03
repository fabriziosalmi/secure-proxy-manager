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

# Install python and dependencies for download
RUN apt-get update && apt-get install -y python3 python3-pip
COPY requirements.txt /
RUN pip3 install -r /requirements.txt


# Expose Squid ports
EXPOSE 3128
EXPOSE 3129

# Start Squid
CMD ["squid", "-N"]
