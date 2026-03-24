FROM python:3.11-slim

WORKDIR /app

# Install dependencies with specific order to handle dependencies correctly
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install curl for healthcheck (Docker CLI removed for security)
RUN apt-get update && \
    apt-get install -y --no-install-recommends --fix-missing curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r proxyuser && \
    useradd -r -g proxyuser -s /bin/bash -d /home/proxyuser proxyuser && \
    mkdir -p /home/proxyuser && \
    chown -R proxyuser:proxyuser /home/proxyuser

# Create necessary directories with proper permissions
RUN mkdir -p /data /logs /config && \
    chown -R proxyuser:proxyuser /data /logs /config /app

# Copy application code
COPY --chown=proxyuser:proxyuser . .

# Switch to non-root user for running the application
USER proxyuser

# Set secure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Healthcheck to ensure service is running properly
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run the API server with Uvicorn (production-ready ASGI server)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000", "--proxy-headers", "--forwarded-allow-ips", "*"]