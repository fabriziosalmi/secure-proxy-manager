import unittest
import json
import os
import sys
from unittest.mock import patch, MagicMock

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

# Set env vars before importing app
os.environ['BASIC_AUTH_USERNAME'] = 'admin'
os.environ['BASIC_AUTH_PASSWORD'] = 'admin'
os.environ['SECRET_KEY'] = 'test_secret'

from app.app import app, init_db, get_db

class SecurityTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Setup in-memory db
        with app.app_context():
            # Mock database path to use in-memory
            with patch('app.app.DATABASE_PATH', ':memory:'):
                init_db()

    def test_input_validation_ip(self):
        # Test invalid IP
        response = self.client.post('/api/ip-blacklist', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='}, # admin:admin
            json={'ip': 'invalid-ip'}
        )
        self.assertEqual(response.status_code, 400)
        
        # Test valid IP
        response = self.client.post('/api/ip-blacklist', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='},
            json={'ip': '1.2.3.4', 'description': 'test'}
        )
        self.assertEqual(response.status_code, 200)

    def test_input_validation_domain(self):
        # Test invalid domain
        response = self.client.post('/api/domain-blacklist', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='},
            json={'domain': '-invalid-domain'}
        )
        self.assertEqual(response.status_code, 400)
        
        # Test valid domain
        response = self.client.post('/api/domain-blacklist', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='},
            json={'domain': 'example.com', 'description': 'test'}
        )
        self.assertEqual(response.status_code, 200)

    def test_settings_update(self):
        # Test update setting
        response = self.client.put('/api/settings/log_level', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='},
            json={'value': 'debug'}
        )
        self.assertEqual(response.status_code, 200)
        
        # Test invalid setting value
        response = self.client.put('/api/settings/log_level', 
            headers={'Authorization': 'Basic YWRtaW46YWRtaW4='},
            json={'value': 'invalid'}
        )
        # validate_setting returns False, so it should be 400
        # In app.py: if not validate_setting(...): return ..., 400
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
