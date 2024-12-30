FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    squid \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python library for requests
RUN pip3 install requests

RUN mkdir /app

COPY config.yaml /app/
COPY parse_config.py /app/
COPY squid.conf.template /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
RUN mkdir -p /etc/squid

WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
