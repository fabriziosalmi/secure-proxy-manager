# Stage 1: Build React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /frontend
COPY ./frontend-new/package*.json ./
RUN npm ci
COPY ./frontend-new/ ./
RUN npm run build

# Stage 2: Python Backend
FROM python:3.11-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY ./ui/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security
RUN groupadd -r appuser && \
    useradd -r -g appuser -s /bin/bash -d /home/appuser appuser && \
    mkdir -p /home/appuser && \
    chown -R appuser:appuser /home/appuser

# Create necessary directories with proper permissions
RUN mkdir -p /logs /data /config && \
    chown -R appuser:appuser /logs /data /config /app

# Copy application code
COPY --chown=appuser:appuser ./ui /app

# Copy built frontend from builder stage
COPY --chown=appuser:appuser --from=frontend-builder /frontend/dist /app/dist

# Switch to non-root user
USER appuser

# Set secure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FRONTEND_DIST=/app/dist

# Expose the port
EXPOSE 8011

# Run the application
CMD ["python", "app.py"]