"""
Integration Test Scenarios
"""

import unittest
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from maat_cross_lang_crypto import MaatCrossLangCrypto


class TestIntegration(unittest.TestCase):
    
    def test_api_response_encryption(self):
        """Test encrypting API responses"""
        print("📝 Testing API response encryption...")
        
        # Simulate API response
        api_response = {
            'status': 'success',
            'data': {
                'users': [
                    {'id': 1, 'name': 'John Doe'},
                    {'id': 2, 'name': 'Jane Smith'}
                ]
            },
            'timestamp': '2024-01-01T12:00:00Z'
        }
        
        password = 'api-encryption-key'
        json_data = json.dumps(api_response)
        
        # Encrypt the response
        encrypted = MaatCrossLangCrypto.encrypt(json_data, password)
        
        # Decrypt and verify
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        parsed_response = json.loads(decrypted)
        
        self.assertEqual(parsed_response['status'], 'success')
        self.assertEqual(len(parsed_response['data']['users']), 2)
        
        print("  ✅ API response encryption works")

    def test_database_field_encryption(self):
        """Test encrypting database fields"""
        print("📝 Testing database field encryption...")
        
        # Simulate sensitive database fields
        sensitive_data = [
            'john.doe@example.com',
            '555-123-4567',
            '123 Main St, City, State 12345',
            'SSN: 123-45-6789'
        ]
        
        password = 'db-field-encryption-key'
        encrypted_fields = []
        
        # Encrypt each field
        for data in sensitive_data:
            encrypted = MaatCrossLangCrypto.encrypt(data, password)
            encrypted_fields.append(encrypted)
        
        # Decrypt and verify each field
        for i, encrypted in enumerate(encrypted_fields):
            decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
            self.assertEqual(decrypted, sensitive_data[i])
        
        print("  ✅ Database field encryption works")

    def test_microservice_communication(self):
        """Test encrypting data between microservices"""
        print("📝 Testing microservice communication...")
        
        # Service A encrypts data to send to Service B
        service_a_data = {
            'request_id': 'req-123-456',
            'user_context': {
                'user_id': 789,
                'roles': ['admin', 'user']
            },
            'payload': {
                'action': 'process_payment',
                'amount': 99.99
            }
        }
        
        password = 'microservice-comm-key'
        encrypted_message = MaatCrossLangCrypto.encrypt(
            json.dumps(service_a_data), 
            password
        )
        
        # Service B decrypts the message
        decrypted_message = MaatCrossLangCrypto.decrypt(encrypted_message, password)
        service_b_data = json.loads(decrypted_message)
        
        self.assertEqual(service_b_data['request_id'], 'req-123-456')
        self.assertEqual(service_b_data['payload']['amount'], 99.99)
        
        print("  ✅ Microservice communication works")

    def test_session_data_encryption(self):
        """Test encrypting session data"""
        print("📝 Testing session data encryption...")
        
        # Simulate session data
        session_data = {
            'user_id': 456,
            'username': 'johndoe',
            'login_time': '2024-01-01T10:00:00Z',
            'preferences': {
                'theme': 'dark',
                'language': 'en'
            },
            'permissions': ['read', 'write', 'delete']
        }
        
        password = 'session-encryption-key'
        
        # Encrypt session data
        encrypted_session = MaatCrossLangCrypto.encrypt(
            json.dumps(session_data),
            password
        )
        
        # Decrypt session data
        decrypted_session = MaatCrossLangCrypto.decrypt(encrypted_session, password)
        parsed_session = json.loads(decrypted_session)
        
        self.assertEqual(parsed_session['user_id'], 456)
        self.assertEqual(parsed_session['username'], 'johndoe')
        self.assertEqual(len(parsed_session['permissions']), 3)
        
        print("  ✅ Session data encryption works")


if __name__ == '__main__':
    print("🔄 Running Python Integration Tests...\n")
    unittest.main(verbosity=2)