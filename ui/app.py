# Import workaround for Werkzeug compatibility issue
from markupsafe import escape
from flask import redirect, url_for

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_basicauth import BasicAuth
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import logging
import time
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configure Basic Auth
app.config['BASIC_AUTH_USERNAME'] = os.environ.get('BASIC_AUTH_USERNAME', 'admin')
app.config['BASIC_AUTH_PASSWORD'] = os.environ.get('BASIC_AUTH_PASSWORD', 'admin')
app.config['BASIC_AUTH_FORCE'] = True
basic_auth = BasicAuth(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/logs/ui.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Backend API configuration
BACKEND_URL = os.environ.get('BACKEND_URL', 'http://backend:5000')
API_AUTH = (app.config['BASIC_AUTH_USERNAME'], app.config['BASIC_AUTH_PASSWORD'])
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))  # Increased timeout from 10 to 30 seconds
MAX_RETRIES = int(os.environ.get('MAX_RETRIES', 5))  # Increased from 3 to 5 maximum retries
BACKOFF_FACTOR = float(os.environ.get('BACKOFF_FACTOR', 1.0))  # Increased from 0.5 to 1.0 backoff factor
RETRY_WAIT_AFTER_STARTUP = int(os.environ.get('RETRY_WAIT_AFTER_STARTUP', 10))  # Wait time after startup

# Startup flag to ensure backend is available
backend_available = False

# Configure requests session with retry logic
def get_requests_session():
    session = requests.Session()
    
    # Configure retry strategy with exponential backoff
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP status codes
        allowed_methods=["GET", "POST", "PUT", "DELETE"],  # Retry for these methods
        raise_on_status=False  # Don't raise exception on status codes that are not retry-able
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

# Function to check backend availability with exponential backoff
def wait_for_backend(max_attempts=10):
    """
    Wait for backend to become available with exponential backoff
    """
    global backend_available
    
    if backend_available:
        return True
        
    session = get_requests_session()
    wait_time = 1  # Initial wait time in seconds
    
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Attempting to connect to backend (attempt {attempt}/{max_attempts})")
            resp = session.get(f"{BACKEND_URL}/health", timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                logger.info("Backend service is available")
                backend_available = True
                return True
            else:
                logger.warning(f"Backend returned status code {resp.status_code}, retrying...")
        except requests.RequestException as e:
            logger.warning(f"Backend connection attempt {attempt} failed: {str(e)}")
        
        # Wait with exponential backoff before next attempt
        if attempt < max_attempts:
            logger.info(f"Waiting {wait_time} seconds before next attempt...")
            time.sleep(wait_time)
            wait_time = min(wait_time * 2, 60)  # Double the wait time, max 60 seconds
    
    logger.error(f"Failed to connect to backend after {max_attempts} attempts")
    return False

# Try to connect to backend at startup
if RETRY_WAIT_AFTER_STARTUP > 0:
    logger.info(f"Waiting {RETRY_WAIT_AFTER_STARTUP} seconds before initial backend connection attempt...")
    time.sleep(RETRY_WAIT_AFTER_STARTUP)

# Initial backend connection attempt
wait_for_backend()

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses to protect against common web vulnerabilities"""
    # Remove server header
    response.headers['Server'] = 'Secure-Proxy-UI'
    
    # Add basic security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",  
        "style-src 'self' 'unsafe-inline'",  
        "img-src 'self' data:",
        "font-src 'self'",  
        "connect-src 'self'",
        "frame-ancestors 'self'",
        "form-action 'self'",
        "base-uri 'self'"
    ]
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)
    
    # Add Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add Feature Policy / Permissions Policy
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    return response

# Routes
@app.route('/')
@basic_auth.required
def index():
    """Dashboard page"""
    return render_template('index.html', active_page='dashboard')

@app.route('/settings')
@basic_auth.required
def settings():
    """Settings page"""
    return render_template('settings.html', active_page='settings')

@app.route('/blacklists')
@basic_auth.required
def blacklists():
    """Blacklists page"""
    return render_template('blacklists.html', active_page='blacklists')

@app.route('/logs')
@basic_auth.required
def logs():
    """Logs page"""
    return render_template('logs.html', active_page='logs')

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon"""
    return app.send_static_file('favicon.ico')

# API Proxy routes
@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@basic_auth.required
def api_proxy(path):
    """Proxy requests to the backend API with retry logic"""
    global backend_available
    
    url = f"{BACKEND_URL}/api/{path}"
    session = get_requests_session()
    
    # Ensure backend is available before proceeding
    if not backend_available and not wait_for_backend(max_attempts=3):
        # If backend is still not available after retrying, return a user-friendly error
        logger.error(f"Backend service unavailable when attempting to access {path}")
        return jsonify({
            "status": "error",
            "message": "Backend service is currently unavailable. Please try again later.",
            "retry_info": "The system will automatically retry connecting to the backend service."
        }), 503
    
    try:
        # Set up headers to include in the request
        headers = {}
        
        # CSRF token forwarding removed
        
        if request.method == 'GET':
            resp = session.get(url, auth=API_AUTH, params=request.args, headers=headers, timeout=REQUEST_TIMEOUT)
        elif request.method == 'POST':
            resp = session.post(url, auth=API_AUTH, json=request.get_json(), headers=headers, timeout=REQUEST_TIMEOUT)
        elif request.method == 'PUT':
            resp = session.put(url, auth=API_AUTH, json=request.get_json(), headers=headers, timeout=REQUEST_TIMEOUT)
        elif request.method == 'DELETE':
            resp = session.delete(url, auth=API_AUTH, headers=headers, timeout=REQUEST_TIMEOUT)
        
        # Handle 401 Unauthorized responses explicitly
        if resp.status_code == 401:
            logger.error(f"Authentication failed with backend API: {resp.text}")
            return jsonify({
                "status": "error",
                "message": "Authentication failed with backend API. Please check backend credentials.",
                "backend_response": resp.text[:200]  # Limit response size
            }), 500
            
        # Check if the response is valid JSON before trying to parse it
        try:
            response_data = resp.json()
            return jsonify(response_data), resp.status_code
        except json.JSONDecodeError as json_err:
            logger.error(f"Backend returned invalid JSON: {str(json_err)}")
            # Return the raw response and status code for debugging
            return jsonify({
                "status": "error", 
                "message": f"Backend returned invalid JSON: {str(json_err)}",
                "raw_response": resp.text[:500],  # Include start of raw response for debugging
                "status_code": resp.status_code
            }), 500
            
    except requests.exceptions.ConnectionError as e:
        # Mark backend as unavailable to trigger a check on next request
        backend_available = False
        
        logger.error(f"Connection error with backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": "Backend service is temporarily unavailable. The system will automatically retry.",
            "error_details": str(e)
        }), 503
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout connecting to backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": "Request to backend service timed out. Please try again later.",
            "error_details": str(e)
        }), 504  # Gateway Timeout
    except requests.RequestException as e:
        logger.error(f"Error connecting to backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Error connecting to backend: {str(e)}",
            "retry_info": f"Attempted {MAX_RETRIES} retries with {BACKOFF_FACTOR} backoff factor"
        }), 503  # Return 503 Service Unavailable
    except Exception as e:
        logger.error(f"Unexpected error proxying request to backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Unexpected error proxying request to backend: {str(e)}"
        }), 500

# Health check endpoint
@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration"""
    # Simple health check that doesn't require authentication
    return jsonify({"status": "healthy", "service": "secure-proxy-ui"}), 200

# Backend availability check
@app.route('/api/check-backend')
def check_backend():
    """Check if backend service is available"""
    session = get_requests_session()
    try:
        resp = session.get(f"{BACKEND_URL}/health", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return jsonify({"status": "available", "message": "Backend service is available"}), 200
        else:
            return jsonify({"status": "unavailable", "message": f"Backend service returned status {resp.status_code}"}), 503
    except requests.RequestException as e:
        return jsonify({"status": "unavailable", "message": f"Backend service is not available: {str(e)}"}), 503

@app.route('/api/clients/statistics', methods=['GET'])
@basic_auth.required
def client_statistics():
    """Return client statistics for the dashboard"""
    url = f"{BACKEND_URL}/api/clients/statistics"
    session = get_requests_session()
    
    try:
        resp = session.get(url, auth=API_AUTH, timeout=REQUEST_TIMEOUT)
        
        # MODIFICATION: Removed mock data generation block
        # The original block that checked for resp.status_code == 404 and returned mock data has been removed.
            
        try:
            # Attempt to parse the response as JSON, regardless of status code initially
            # The frontend will handle non-200 responses appropriately
            return jsonify(resp.json()), resp.status_code
        except ValueError: # Handles cases where resp.json() fails (e.g., empty or non-JSON response)
            # If parsing fails, and it was a 404 or other client/server error,
            # return a generic error.
            # For successful status codes with unparsable content, this also provides a clear error.
            app.logger.error(f"Failed to parse JSON response from backend for {url}. Status: {resp.status_code}, Response: {resp.text[:200]}")
            return jsonify({"status": "error", "message": "Failed to parse backend response"}), 500
            
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request to backend failed for {url}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 503

@app.route('/api/domains/statistics', methods=['GET'])
@basic_auth.required
def domain_statistics():
    """Return domain statistics for the dashboard"""
    url = f"{BACKEND_URL}/api/domains/statistics"
    session = get_requests_session()
    
    try:
        resp = session.get(url, auth=API_AUTH, timeout=REQUEST_TIMEOUT)
        
        # MODIFICATION: Remove mock data generation block
            
        try:
            # Attempt to parse the response as JSON, regardless of status code initially
            return jsonify(resp.json()), resp.status_code
        except ValueError: # Handles cases where resp.json() fails
            app.logger.error(f"Failed to parse JSON response from backend for {url}. Status: {resp.status_code}, Response: {resp.text[:200]}")
            return jsonify({"status": "error", "message": "Failed to parse backend response"}), 500
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching domain statistics: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error fetching domain statistics: {str(e)}"
        }), 503

@app.route('/api/maintenance/download-cert', methods=['GET'])
@basic_auth.required
def download_certificate():
    """Special handler for certificate download that properly passes through the file"""
    url = f"{BACKEND_URL}/api/maintenance/download-cert"
    session = get_requests_session()
    
    try:
        # Get the certificate file from the backend as raw bytes (stream=True)
        resp = session.get(url, auth=API_AUTH, timeout=REQUEST_TIMEOUT, stream=True)
        
        if resp.status_code == 200:
            # Forward the response with the same headers
            from flask import Response
            response = Response(resp.iter_content(chunk_size=1024))
            
            # Copy relevant headers from the backend response
            response.headers['Content-Type'] = resp.headers.get('Content-Type', 'application/x-pem-file')
            response.headers['Content-Disposition'] = resp.headers.get('Content-Disposition', 'attachment; filename=secure-proxy-ca.pem')
            
            return response
        else:
            # If the backend returned an error, convert it to a user-friendly message
            logger.error(f"Error downloading certificate. Status: {resp.status_code}, Response: {resp.text[:200]}")
            try:
                error_data = resp.json()
                return jsonify(error_data), resp.status_code
            except:
                return jsonify({
                    "status": "error",
                    "message": f"Error downloading certificate. Status code: {resp.status_code}"
                }), resp.status_code
                
    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading certificate: {str(e)}")
        return jsonify({
            "status": "error",
            "message": f"Error downloading certificate: {str(e)}"
        }), 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8011)