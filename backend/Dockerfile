# Pin: python 3.11.12 slim bookworm (2025-04)
FROM python:3.11.12-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Install curl (healthcheck) + gosu (privilege drop in entrypoint)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl gosu && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r proxyuser && \
    useradd -r -g proxyuser -s /bin/bash -d /home/proxyuser proxyuser && \
    mkdir -p /home/proxyuser && \
    chown -R proxyuser:proxyuser /home/proxyuser

RUN mkdir -p /data /logs /config/dnsmasq.d && \
    chown -R proxyuser:proxyuser /data /logs /config /app

COPY --chown=proxyuser:proxyuser . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Entrypoint fixes volume permissions then drops to proxyuser
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000", "--proxy-headers", "--forwarded-allow-ips", "*"]
