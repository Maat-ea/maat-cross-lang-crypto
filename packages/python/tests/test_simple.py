"""
Simple test to verify basic functionality
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def test_basic_functionality():
    """Quick test of basic encrypt/decrypt"""
    try:
        from maat_cross_lang_crypto import MaatCrossLangCrypto
        
        print("🧪 Quick Python Test...")
        
        password = 'test-password'
        data = 'Hello World!'
        
        print(f'Original data: {data}')
        
        encrypted = MaatCrossLangCrypto.encrypt(data, password)
        print(f'Encrypted: {encrypted[:50]}...')
        
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        print(f'Decrypted: {decrypted}')
        
        if data == decrypted:
            print('✅ Basic Python test passed!')
            return True
        else:
            print('❌ Basic Python test failed!')
            return False
            
    except Exception as e:
        print(f'❌ Test error: {e}')
        return False


if __name__ == '__main__':
    success = test_basic_functionality()
    sys.exit(0 if success else 1)