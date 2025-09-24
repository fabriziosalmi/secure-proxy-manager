FROM python:3.11-slim

WORKDIR /app

# Install dependencies with specific order to handle dependencies correctly
COPY requirements.txt .
RUN pip install --no-cache-dir werkzeug==2.2.3 && \
    pip install --no-cache-dir -r requirements.txt

# Install Docker CLI for container management
RUN apt-get update && \
    apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli && \
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
# But we'll need to run as root for Docker CLI access
# USER proxyuser

# Set secure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Healthcheck to ensure service is running properly
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Run the API server with Gunicorn (production-ready WSGI server)
# Bind to 0.0.0.0:5000 to match healthcheck and docker-compose expectations
# Use 2 workers and 2 threads for light concurrency; adjust as needed
CMD ["gunicorn", "-w", "2", "--threads", "2", "-b", "0.0.0.0:5000", "app.app:app", "--timeout", "90"]