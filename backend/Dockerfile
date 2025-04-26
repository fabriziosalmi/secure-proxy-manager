FROM python:3.11-slim

WORKDIR /app

# Install dependencies with specific order to handle dependencies correctly
COPY requirements.txt .
RUN pip install --no-cache-dir werkzeug==2.2.3 && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /data /logs /config

# Run the API server
CMD ["python", "app/app.py"]