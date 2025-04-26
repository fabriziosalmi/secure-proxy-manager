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
        
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logger.error(f"Error proxying request to backend: {str(e)}")
        return jsonify({"status": "error", "message": f"Backend API error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8011)