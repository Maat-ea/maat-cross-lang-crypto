"""
Cross-Language Compatibility Tests
"""

import unittest
import json
import base64
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from maat_cross_lang_crypto import MaatCrossLangCrypto


class TestCompatibility(unittest.TestCase):
    
    def test_data_structure_consistency(self):
        """Test that encrypted data structure is consistent"""
        print("📝 Testing data structure consistency...")
        
        password = 'structure-test'
        data = 'Test data for structure validation'
        
        encrypted = MaatCrossLangCrypto.encrypt(data, password)
        structure = self._parse_encrypted_data(encrypted)
        
        # Validate required fields
        required_fields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data']
        for field in required_fields:
            self.assertIn(field, structure)
            self.assertTrue(structure[field])  # Not empty
        
        # Validate field values
        self.assertEqual(structure['v'], '1.0.0')
        self.assertEqual(structure['alg'], 'AES-256-GCM')
        self.assertEqual(structure['kdf'], 'PBKDF2-SHA256')
        
        print("  ✅ Data structure is consistent")

    def test_known_test_vectors(self):
        """Test with known test vectors"""
        print("📝 Testing with known test vectors...")
        
        test_vectors = [
            {
                'password': 'test123',
                'data': 'Hello World',
                'options': {'iterations': 10000}
            },
            {
                'password': 'secure-key-456', 
                'data': '{"test": "json", "value": 42}',
                'options': {'iterations': 25000}
            }
        ]
        
        for i, vector in enumerate(test_vectors):
            with self.subTest(vector=i):
                encrypted = MaatCrossLangCrypto.encrypt(
                    vector['data'],
                    vector['password'],
                    vector['options']
                )
                decrypted = MaatCrossLangCrypto.decrypt(encrypted, vector['password'])
                self.assertEqual(decrypted, vector['data'])
        
        print("  ✅ Test vectors work correctly")

    def test_django_integration(self):
        """Test Django-style usage"""
        print("📝 Testing Django-style usage...")
        
        # Simulate Django settings
        config = {
            'crypto_key': 'django-test-key-12345',
            'options': {'iterations': 75000}
        }
        
        user_data = json.dumps({
            'user_id': 12345,
            'email': 'user@example.com',
            'permissions': ['read', 'write']
        })
        
        # Encrypt like Django would
        encrypted = MaatCrossLangCrypto.encrypt(
            user_data, 
            config['crypto_key'], 
            config['options']
        )
        
        # Decrypt like Django would
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, config['crypto_key'])
        parsed_user = json.loads(decrypted)
        
        self.assertEqual(parsed_user['user_id'], 12345)
        
        print("  ✅ Django-style integration works")

    def test_cross_language_structure(self):
        """Test that our structure matches what other languages expect"""
        print("📝 Testing cross-language structure...")
        
        password = 'cross-lang-test'
        data = 'Cross-language compatibility test'
        
        encrypted = MaatCrossLangCrypto.encrypt(data, password)
        structure = self._parse_encrypted_data(encrypted)
        
        # Test that base64 fields decode to correct lengths
        iv_bytes = base64.b64decode(structure['iv'])
        salt_bytes = base64.b64decode(structure['salt'])
        tag_bytes = base64.b64decode(structure['tag'])
        
        self.assertEqual(len(iv_bytes), 12)   # 96 bits
        self.assertEqual(len(salt_bytes), 16) # 128 bits
        self.assertEqual(len(tag_bytes), 16)  # 128 bits
        
        print("  ✅ Cross-language structure is correct")

    def _parse_encrypted_data(self, encrypted: str) -> dict:
        """Parse encrypted data structure"""
        json_str = base64.b64decode(encrypted).decode('utf-8')
        return json.loads(json_str)


if __name__ == '__main__':
    print("🌐 Running Python Compatibility Tests...\n")
    unittest.main(verbosity=2)