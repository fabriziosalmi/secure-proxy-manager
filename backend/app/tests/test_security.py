import unittest
import sys
import os
import sqlite3
import json
import time
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, auth_attempts, MAX_ATTEMPTS, RATE_LIMIT_WINDOW

class SecureProxyTestCase(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        # Use in-memory database for testing
        app.config['DATABASE'] = ':memory:'
        self.app = app.test_client()
        
        # Clear rate limit attempts for each test
        auth_attempts.clear()
        
    def test_rate_limiting(self):
        """Test that rate limiting correctly blocks excessive login attempts"""
        # Set up test credentials
        test_credentials = "Basic YWRtaW46aW52YWxpZHBhc3N3b3Jk"  # admin:invalidpassword in base64
        
        # Make requests just under the rate limit
        for i in range(MAX_ATTEMPTS - 1):
            response = self.app.get('/api/status', 
                                   headers={'Authorization': test_credentials})
            self.assertEqual(response.status_code, 401)  # Unauthorized but not rate limited
        
        # Rate limit should not be triggered yet
        response = self.app.get('/api/status')
        self.assertEqual(response.status_code, 401)  # Still just unauthorized
        
        # One more request should trigger rate limiting
        response = self.app.get('/api/status', 
                               headers={'Authorization': test_credentials})
        self.assertEqual(response.status_code, 401)  # Now rate limited
        
        # Admin should still be able to check rate limits even when rate limited
        valid_credentials = "Basic YWRtaW46YWRtaW4="  # admin:admin in base64
        response = self.app.get('/api/security/rate-limits', 
                               headers={'Authorization': valid_credentials})
        self.assertEqual(response.status_code, 200)
        
        # Verify rate limit data contains our test client
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        
        # Find our client in the rate-limited IPs
        test_client_ip = '127.0.0.1'
        rate_limited_ips = [entry['ip'] for entry in data['data'] if entry['is_blocked']]
        self.assertIn(test_client_ip, rate_limited_ips)
    
    def test_csrf_protection(self):
        """Test that CSRF protection correctly validates tokens"""
        # Log in first
        valid_credentials = "Basic YWRtaW46YWRtaW4="  # admin:admin in base64
        
        # GET request to get a CSRF token
        response = self.app.get('/api/settings', 
                               headers={'Authorization': valid_credentials})
        self.assertEqual(response.status_code, 200)
        
        # Extract CSRF token from response headers
        csrf_token = response.headers.get('X-CSRF-Token')
        self.assertIsNotNone(csrf_token)
        
        # Make a PUT request with the valid CSRF token
        response = self.app.put('/api/settings/log_level', 
                               headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': csrf_token,
                                   'Content-Type': 'application/json'
                               },
                               json={'value': 'info'})
        self.assertEqual(response.status_code, 200)
        
        # Make a PUT request with an invalid CSRF token
        response = self.app.put('/api/settings/log_level', 
                               headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': 'invalid-token',
                                   'Content-Type': 'application/json'
                               },
                               json={'value': 'debug'})
        self.assertEqual(response.status_code, 403)  # Should be forbidden
        
    def test_password_validation(self):
        """Test password validation rejects weak passwords"""
        # Log in first
        valid_credentials = "Basic YWRtaW46YWRtaW4="  # admin:admin in base64
        
        # GET request to get a CSRF token
        response = self.app.get('/api/settings', 
                               headers={'Authorization': valid_credentials})
        csrf_token = response.headers.get('X-CSRF-Token')
        
        # Test weak password (too short)
        response = self.app.post('/api/change-password',
                                headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': csrf_token,
                                   'Content-Type': 'application/json'
                                },
                                json={
                                    'current_password': 'admin',
                                    'new_password': 'weak'
                                })
        self.assertEqual(response.status_code, 400)
        
        # Test password without special characters
        response = self.app.post('/api/change-password',
                                headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': csrf_token,
                                   'Content-Type': 'application/json'
                                },
                                json={
                                    'current_password': 'admin',
                                    'new_password': 'password123'
                                })
        self.assertEqual(response.status_code, 400)
        
        # Test password without numbers
        response = self.app.post('/api/change-password',
                                headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': csrf_token,
                                   'Content-Type': 'application/json'
                                },
                                json={
                                    'current_password': 'admin',
                                    'new_password': 'Password!'
                                })
        self.assertEqual(response.status_code, 400)
        
        # Test strong password (meets requirements)
        response = self.app.post('/api/change-password',
                                headers={
                                   'Authorization': valid_credentials,
                                   'X-CSRF-Token': csrf_token,
                                   'Content-Type': 'application/json'
                                },
                                json={
                                    'current_password': 'admin',
                                    'new_password': 'StrongPassword123!'
                                })
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()