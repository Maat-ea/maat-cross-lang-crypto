"""
Basic Python Crypto Tests
"""

import unittest
import sys
import os

# Add the parent directory to the path to import our module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from maat_cross_lang_crypto import MaatCrossLangCrypto


class TestMaatCrossLangCrypto(unittest.TestCase):
    
    def test_basic_encrypt_decrypt(self):
        """Test basic encryption and decryption functionality"""
        print("📝 Testing basic encrypt/decrypt...")
        
        password = 'test-password-123'
        original_data = 'Hello, World!'
        
        encrypted = MaatCrossLangCrypto.encrypt(original_data, password)
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        
        self.assertEqual(decrypted, original_data)
        print("  ✅ Basic encryption/decryption works")

    def test_different_data_types(self):
        """Test encryption with different data types"""
        print("📝 Testing different data types...")
        
        password = 'test-password-456'
        test_cases = [
            'Simple string',
            '{"json": "data", "number": 42}',
            'Special chars: äöü ñ 中文 🚀',
            'Multi\nline\ntext\nwith\nbreaks',
            '   whitespace   test   ',
            '1234567890'
        ]
        
        for i, data in enumerate(test_cases):
            with self.subTest(test_case=i):
                encrypted = MaatCrossLangCrypto.encrypt(data, password)
                decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
                self.assertEqual(decrypted, data)
        
        print("  ✅ Different data types work")

    def test_custom_options(self):
        """Test encryption with custom options"""
        print("📝 Testing custom options...")
        
        password = 'test-password-789'
        data = 'Custom options test'
        
        custom_options = {
            'iterations': 50000,
            'key_length': 32,
            'iv_length': 12,
            'salt_length': 16
        }
        
        encrypted = MaatCrossLangCrypto.encrypt(data, password, custom_options)
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        
        self.assertEqual(decrypted, data)
        
        # Verify the options were used
        import json
        import base64
        json_str = base64.b64decode(encrypted).decode('utf-8')
        parsed_data = json.loads(json_str)
        self.assertEqual(parsed_data['iter'], custom_options['iterations'])
        
        print("  ✅ Custom options work")

    def test_error_handling(self):
        """Test error handling for invalid inputs"""
        print("📝 Testing error handling...")
        
        # Test empty inputs
        with self.assertRaises(ValueError):
            MaatCrossLangCrypto.encrypt('', 'password')
        
        with self.assertRaises(ValueError):
            MaatCrossLangCrypto.encrypt('data', '')
        
        with self.assertRaises(ValueError):
            MaatCrossLangCrypto.decrypt('', 'password')
        
        with self.assertRaises(ValueError):
            MaatCrossLangCrypto.decrypt('invalid', 'password')
        
        # Test wrong password
        encrypted = MaatCrossLangCrypto.encrypt('test', 'password1')
        with self.assertRaises(RuntimeError):
            MaatCrossLangCrypto.decrypt(encrypted, 'password2')
        
        print("  ✅ Error handling works")

    def test_key_generation(self):
        """Test cryptographic key generation"""
        print("📝 Testing key generation...")
        
        key1 = MaatCrossLangCrypto.generate_key()
        key2 = MaatCrossLangCrypto.generate_key()
        
        # Keys should be different
        self.assertNotEqual(key1, key2)
        
        # Test custom key lengths
        short_key = MaatCrossLangCrypto.generate_key(16)
        long_key = MaatCrossLangCrypto.generate_key(64)
        
        import base64
        self.assertEqual(len(base64.b64decode(short_key)), 16)
        self.assertEqual(len(base64.b64decode(long_key)), 64)
        
        print("  ✅ Key generation works")

    def test_version_info(self):
        """Test version information"""
        print("📝 Testing version info...")
        
        version = MaatCrossLangCrypto.version()
        
        self.assertIn('version', version)
        self.assertIn('algorithm', version)
        self.assertEqual(version['algorithm'], 'AES-256-GCM')
        self.assertIn('library', version)
        
        print("  ✅ Version info works")


if __name__ == '__main__':
    print("🧪 Running Python Crypto Tests...\n")
    unittest.main(verbosity=2)