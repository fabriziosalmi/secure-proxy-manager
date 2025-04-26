# Import workaround for Werkzeug compatibility issue
from werkzeug.utils import escape, redirect, url_quote

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_basicauth import BasicAuth
import os
import requests
import json
import logging

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'secure-proxy-default-key')

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
    
    # Add Content Security Policy with allowances for CDN resources
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com",  # Allow CDN scripts
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",  # Allow CDN styles
        "img-src 'self' data:",
        "font-src 'self' https://cdnjs.cloudflare.com",  # Allow Font Awesome fonts
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

@app.route('/about')
@basic_auth.required
def about():
    """About page"""
    return render_template('about.html', active_page='about')

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon"""
    return app.send_static_file('favicon.ico')

# API Proxy routes
@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@basic_auth.required
def api_proxy(path):
    """Proxy requests to the backend API"""
    url = f"{BACKEND_URL}/api/{path}"
    
    try:
        if request.method == 'GET':
            resp = requests.get(url, auth=API_AUTH, params=request.args)
        elif request.method == 'POST':
            resp = requests.post(url, auth=API_AUTH, json=request.get_json())
        elif request.method == 'PUT':
            resp = requests.put(url, auth=API_AUTH, json=request.get_json())
        elif request.method == 'DELETE':
            resp = requests.delete(url, auth=API_AUTH)
        
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
            
    except requests.RequestException as e:
        logger.error(f"Error connecting to backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Error connecting to backend: {str(e)}"
        }), 500
    except Exception as e:
        logger.error(f"Unexpected error proxying request to backend: {str(e)}")
        return jsonify({
            "status": "error", 
            "message": f"Unexpected error proxying request to backend: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8011)