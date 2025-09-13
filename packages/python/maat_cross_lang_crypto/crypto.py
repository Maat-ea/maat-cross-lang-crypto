"""
Cross-Language Encryption Package - Python Implementation
FIXED VERSION - Works with cryptography library
"""

import json
import base64
import secrets
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class MaatCrossLangCrypto:
    VERSION = '1.0.0'
    ALGORITHM = 'aes-256-gcm'
    KDF = 'pbkdf2'
    HASH = 'sha256'
    
    DEFAULT_OPTIONS = {
        'iterations': 100000,
        'key_length': 32,    # 256 bits
        'iv_length': 12,     # 96 bits for GCM
        'salt_length': 16,   # 128 bits
        'tag_length': 16     # 128 bits
    }

    @classmethod
    def encrypt(cls, data: str, password: str, options: Optional[Dict[str, Any]] = None) -> str:
        """
        Encrypts data with password using AES-256-GCM
        
        Args:
            data: Data to encrypt
            password: Password for encryption
            options: Optional encryption parameters
            
        Returns:
            Base64 encoded encrypted data with metadata
            
        Raises:
            ValueError: Invalid input parameters
            RuntimeError: Encryption failed due to cryptographic errors
        """
        # Merge options with defaults
        opts = {**cls.DEFAULT_OPTIONS, **(options or {})}
        
        # Input validation
        if not data or not isinstance(data, str):
            raise ValueError('Data must be a non-empty string')
        if not password or not isinstance(password, str):
            raise ValueError('Password must be a non-empty string')

        try:
            # Generate random salt and IV
            salt = secrets.token_bytes(opts['salt_length'])
            iv = secrets.token_bytes(opts['iv_length'])

            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=opts['key_length'],
                salt=salt,
                iterations=opts['iterations'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))

            # Encrypt data using AEAD
            aesgcm = AESGCM(key)
            encrypted_data = aesgcm.encrypt(iv, data.encode('utf-8'), None)
            
            # Split encrypted data and auth tag
            ciphertext = encrypted_data[:-opts['tag_length']]
            tag = encrypted_data[-opts['tag_length']:]

            # Create metadata structure
            encrypted_payload = {
                'v': cls.VERSION,
                'alg': 'AES-256-GCM',
                'kdf': 'PBKDF2-SHA256',
                'iter': opts['iterations'],
                'iv': base64.b64encode(iv).decode('ascii'),
                'salt': base64.b64encode(salt).decode('ascii'),
                'tag': base64.b64encode(tag).decode('ascii'),
                'data': base64.b64encode(ciphertext).decode('ascii')
            }

            # Return base64 encoded JSON
            json_str = json.dumps(encrypted_payload, separators=(',', ':'))
            return base64.b64encode(json_str.encode('utf-8')).decode('ascii')

        except Exception as e:
            raise RuntimeError(f'Encryption failed: {str(e)}') from e

    @classmethod
    def decrypt(cls, encrypted_data: str, password: str) -> str:
        """
        Decrypts data with password
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            password: Password for decryption
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: Invalid input parameters or data format
            RuntimeError: Decryption failed due to cryptographic errors
        """
        # Input validation
        if not encrypted_data or not isinstance(encrypted_data, str):
            raise ValueError('Encrypted data must be a non-empty string')
        if not password or not isinstance(password, str):
            raise ValueError('Password must be a non-empty string')

        # Validate base64 format before attempting to decode
        try:
            # Check if the input is valid base64
            base64.b64decode(encrypted_data.encode('ascii'), validate=True)
        except Exception as e:
            raise ValueError('Invalid encrypted data format') from e

        try:
            # Parse base64 encoded JSON
            json_str = base64.b64decode(encrypted_data.encode('ascii')).decode('utf-8')
            parsed_data = json.loads(json_str)
        except (json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error) as e:
            raise ValueError('Invalid encrypted data format') from e

        # Validate structure and version
        cls._validate_encrypted_data(parsed_data)

        # Extract components
        try:
            iv = base64.b64decode(parsed_data['iv'].encode('ascii'))
            salt = base64.b64decode(parsed_data['salt'].encode('ascii'))
            tag = base64.b64decode(parsed_data['tag'].encode('ascii'))
            ciphertext = base64.b64decode(parsed_data['data'].encode('ascii'))
        except Exception as e:
            raise ValueError('Invalid base64 data in encrypted payload') from e

        try:
            # Derive key using same parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # Fixed for AES-256
                salt=salt,
                iterations=parsed_data['iter'],
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))

            # Decrypt data
            aesgcm = AESGCM(key)
            # Reconstruct the encrypted data with auth tag
            encrypted_with_tag = ciphertext + tag
            decrypted_bytes = aesgcm.decrypt(iv, encrypted_with_tag, None)
            
            return decrypted_bytes.decode('utf-8')

        except Exception as e:
            raise RuntimeError(f'Decryption failed: {str(e)}') from e

    @classmethod
    def generate_key(cls, length: int = 32) -> str:
        """
        Generates a cryptographically secure random key
        
        Args:
            length: Key length in bytes (default: 32)
            
        Returns:
            Base64 encoded random key
            
        Raises:
            ValueError: Invalid key length
        """
        if not isinstance(length, int) or length < 16 or length > 64:
            raise ValueError('Key length must be an integer between 16 and 64 bytes')
        
        return base64.b64encode(secrets.token_bytes(length)).decode('ascii')

    @classmethod
    def version(cls) -> Dict[str, str]:
        """
        Get version information
        
        Returns:
            Version and algorithm info
        """
        return {
            'version': cls.VERSION,
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256',
            'library': 'cross-lang-crypto-python'
        }

    @classmethod
    def _validate_encrypted_data(cls, data: Dict[str, Any]) -> None:
        """
        Validates encrypted data structure
        
        Args:
            data: Parsed encrypted data
            
        Raises:
            ValueError: Invalid data structure
        """
        required_fields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data']
        
        for field in required_fields:
            if field not in data or not data[field]:
                raise ValueError(f'Missing required field: {field}')

        if data['alg'] != 'AES-256-GCM':
            raise ValueError(f'Unsupported algorithm: {data["alg"]}')

        if data['kdf'] != 'PBKDF2-SHA256':
            raise ValueError(f'Unsupported KDF: {data["kdf"]}')

        if not isinstance(data['iter'], int) or data['iter'] < 10000:
            raise ValueError('Invalid iteration count')


# Test the implementation if run directly
if __name__ == '__main__':
    print('🧪 Testing Python implementation...')
    
    try:
        password = 'test-password'
        data = 'Hello World!'
        
        print(f'Original data: {data}')
        
        encrypted = MaatCrossLangCrypto.encrypt(data, password)
        print(f'Encrypted: {encrypted[:50]}...')
        
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        print(f'Decrypted: {decrypted}')
        
        if data == decrypted:
            print('✅ Basic Python test passed!')
        else:
            print('❌ Basic Python test failed!')
            
    except Exception as e:
        print(f'❌ Test error: {e}')


# Django integration (Optional)
def create_django_setting():
    """
    Example Django settings integration
    """
    return {
        'CROSS_LANG_CRYPTO': {
            'DEFAULT_KEY': 'your-encryption-key-here',
            'DEFAULT_OPTIONS': {
                'iterations': 100000,
            }
        }
    }


# Flask integration (Optional)
def create_flask_extension():
    """
    Example Flask extension
    """
    class FlaskMaatCrossLangCrypto:
        def __init__(self, app=None):
            self.app = app
            if app is not None:
                self.init_app(app)

        def init_app(self, app):
            app.config.setdefault('CROSS_LANG_CRYPTO_KEY', None)
            app.extensions = getattr(app, 'extensions', {})
            app.extensions['cross_lang_crypto'] = MaatCrossLangCrypto

        def encrypt(self, data, password=None):
            if password is None:
                password = self.app.config['CROSS_LANG_CRYPTO_KEY']
            return MaatCrossLangCrypto.encrypt(data, password)

        def decrypt(self, encrypted_data, password=None):
            if password is None:
                password = self.app.config['CROSS_LANG_CRYPTO_KEY']
            return MaatCrossLangCrypto.decrypt(encrypted_data, password)

    return FlaskMaatCrossLangCrypto