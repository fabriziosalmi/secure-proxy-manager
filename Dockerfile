# Dockerfile Example: Squid with Blacklists from External Sources

FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y squid curl && \
    rm -rf /var/lib/apt/lists/*

# Create directories for blacklists and logs
RUN mkdir -p /etc/squid/blacklists /var/log/squid

# Retrieve example domain blacklists (at least 5 sources)
RUN curl -s -o /etc/squid/blacklists/domain_1.txt https://mirror1.malwaredomains.com/files/justdomains && \
    curl -s -o /etc/squid/blacklists/domain_2.txt https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts && \
    curl -s -o /etc/squid/blacklists/domain_3.txt https://someonewhocares.org/hosts/zero/hosts && \
    curl -s -o /etc/squid/blacklists/domain_4.txt https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains/output/domains/ACTIVE/list && \
    curl -s -o /etc/squid/blacklists/domain_5.txt https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt && \
    cat /etc/squid/blacklists/domain_*.txt > /etc/squid/blacklists/blacklist_fqdn.txt && \
    rm /etc/squid/blacklists/domain_*.txt

# Retrieve example IP blacklists (at least 5 sources)
RUN curl -s -o /etc/squid/blacklists/ip_1.txt https://www.spamhaus.org/drop/drop.lasso && \
    curl -s -o /etc/squid/blacklists/ip_2.txt https://www.spamhaus.org/drop/edrop.lasso && \
    curl -s -o /etc/squid/blacklists/ip_3.txt https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt && \
    curl -s -o /etc/squid/blacklists/ip_4.txt https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset && \
    curl -s -o /etc/squid/blacklists/ip_5.txt https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt && \
    cat /etc/squid/blacklists/ip_*.txt > /etc/squid/blacklists/blacklist_ip.txt && \
    rm /etc/squid/blacklists/ip_*.txt

# Copy Squid configuration
COPY squid.conf /etc/squid/squid.conf

# Expose Squid port
EXPOSE 3128

# Run Squid in the foreground
CMD ["squid", "-f", "/etc/squid/squid.conf", "-NYCd", "1"]
