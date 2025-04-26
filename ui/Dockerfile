FROM python:3.11-slim

WORKDIR /app

# Install Flask with compatible dependencies
RUN pip install --no-cache-dir flask==2.0.1 werkzeug==2.0.1 flask-basicauth==0.2.0 requests==2.28.2 python-dotenv==1.0.0

# Copy application code
COPY . .

# Create log directory
RUN mkdir -p /logs

# Expose the port
EXPOSE 8011

# Run the application
CMD ["python", "app.py"]