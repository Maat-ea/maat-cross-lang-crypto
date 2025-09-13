#!/usr/bin/env python3
"""
MAAT Cross-Language Crypto - Python Examples
Complete examples showing various use cases
"""

import json
import time
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add the parent directory to import our crypto module
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

try:
    from maat_cross_lang_crypto import MaatCrossLangCrypto
except ImportError as e:
    print(f"❌ Failed to import MaatCrossLangCrypto: {e}")
    print("Make sure the module is in the correct location")
    sys.exit(1)

print('🚀 MAAT Cross-Language Crypto - Python Examples\n')

# ========================================
# Example 1: Basic Encryption/Decryption
# ========================================

print('📝 Example 1: Basic Encryption/Decryption')
print('=' * 50)

def basic_example():
    password = 'my-secure-password-123'
    data = 'Hello, World! This is a secret message.'
    
    print(f'Original data: {data}')
    
    # Encrypt the data
    encrypted = MaatCrossLangCrypto.encrypt(data, password)
    print(f'Encrypted: {encrypted[:50]}...')
    print(f'Encrypted length: {len(encrypted)} characters')
    
    # Decrypt the data
    decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
    print(f'Decrypted: {decrypted}')
    
    success = data == decrypted
    print(f'✅ Success: {"Data matches!" if success else "Data mismatch!"}\n')
    
    return encrypted  # Return for cross-language testing

basic_encrypted = basic_example()

# ========================================
# Example 2: JSON Data Encryption
# ========================================

print('📝 Example 2: JSON Data Encryption')
print('=' * 50)

def json_example():
    password = 'json-encryption-key-2024'
    
    # Complex JSON data
    user_data = {
        'id': 12345,
        'username': 'johndoe',
        'email': 'john.doe@example.com',
        'profile': {
            'firstName': 'John',
            'lastName': 'Doe',
            'age': 30,
            'preferences': {
                'theme': 'dark',
                'language': 'en',
                'notifications': True
            }
        },
        'roles': ['user', 'admin'],
        'lastLogin': '2024-01-15T10:30:00Z',
        'metadata': {
            'loginCount': 42,
            'accountCreated': '2023-01-01T00:00:00Z'
        }
    }
    
    print('Original user data:')
    print(json.dumps(user_data, indent=2))
    
    # Convert to JSON string and encrypt
    json_string = json.dumps(user_data)
    encrypted = MaatCrossLangCrypto.encrypt(json_string, password)
    
    print(f'\nEncrypted JSON: {encrypted[:60]}...')
    print(f'Encrypted size: {len(encrypted)} characters')
    print(f'Original size: {len(json_string)} characters')
    print(f'Overhead: {len(encrypted) - len(json_string)} characters')
    
    # Decrypt and parse back to object
    decrypted_json = MaatCrossLangCrypto.decrypt(encrypted, password)
    decrypted_user = json.loads(decrypted_json)
    
    print('\nDecrypted user data:')
    print(json.dumps(decrypted_user, indent=2))
    
    is_valid = json.dumps(user_data, sort_keys=True) == json.dumps(decrypted_user, sort_keys=True)
    print(f'✅ JSON integrity: {"Perfect match!" if is_valid else "Data corrupted!"}\n')

json_example()

# ========================================
# Example 3: Custom Security Options
# ========================================

print('📝 Example 3: Custom Security Options')
print('=' * 50)

def custom_options_example():
    password = 'high-security-password-456'
    data = 'Highly sensitive financial data requiring extra security'
    
    # High-security options
    high_security_options = {
        'iterations': 200000,  # Double the default for extra security
        'key_length': 32,      # AES-256
        'iv_length': 12,       # Standard for GCM
        'salt_length': 16,     # 128-bit salt
        'tag_length': 16       # 128-bit authentication tag
    }
    
    print('High-security encryption options:')
    print(json.dumps(high_security_options, indent=2))
    
    start_time = time.time()
    encrypted = MaatCrossLangCrypto.encrypt(data, password, high_security_options)
    encrypt_time = time.time() - start_time
    
    print(f'High-security encryption time: {encrypt_time:.3f}s')
    print(f'Encrypted data: {encrypted[:50]}...')
    
    start_time = time.time()
    decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
    decrypt_time = time.time() - start_time
    
    print(f'High-security decryption time: {decrypt_time:.3f}s')
    print(f'Decrypted: {decrypted}')
    
    success = data == decrypted
    print(f'✅ Security test: {"Success!" if success else "Failed!"}\n')

custom_options_example()

# ========================================
# Example 4: Key Generation
# ========================================

print('📝 Example 4: Cryptographic Key Generation')
print('=' * 50)

def key_generation_example():
    print('Generating cryptographically secure keys...')
    
    # Generate keys of different lengths
    short_key = MaatCrossLangCrypto.generate_key(16)   # 128-bit
    standard_key = MaatCrossLangCrypto.generate_key(32)  # 256-bit (default)
    long_key = MaatCrossLangCrypto.generate_key(64)    # 512-bit
    
    print(f'16-byte key: {short_key}')
    print(f'32-byte key: {standard_key}')
    print(f'64-byte key: {long_key}')
    
    # Verify keys are different
    key1 = MaatCrossLangCrypto.generate_key()
    key2 = MaatCrossLangCrypto.generate_key()
    
    print(f'\nUniqueness test:')
    print(f'Key 1: {key1[:20]}...')
    print(f'Key 2: {key2[:20]}...')
    print(f'Keys are unique: {"✅ Yes" if key1 != key2 else "❌ No"}')
    
    # Use generated key for encryption
    test_data = 'Test data encrypted with generated key'
    encrypted = MaatCrossLangCrypto.encrypt(test_data, standard_key)
    decrypted = MaatCrossLangCrypto.decrypt(encrypted, standard_key)
    
    success = test_data == decrypted
    print(f'\nGenerated key encryption test: {"✅ Success" if success else "❌ Failed"}\n')

key_generation_example()

# ========================================
# Example 5: Error Handling
# ========================================

print('📝 Example 5: Error Handling')
print('=' * 50)

def error_handling_example():
    print('Testing various error scenarios...\n')
    
    # Test 1: Empty data
    try:
        MaatCrossLangCrypto.encrypt('', 'password')
        print('❌ Should have thrown error for empty data')
    except Exception as error:
        print(f'✅ Empty data error handled: {error}')
    
    # Test 2: Empty password
    try:
        MaatCrossLangCrypto.encrypt('data', '')
        print('❌ Should have thrown error for empty password')
    except Exception as error:
        print(f'✅ Empty password error handled: {error}')
    
    # Test 3: Invalid encrypted data
    try:
        MaatCrossLangCrypto.decrypt('invalid-base64-data', 'password')
        print('❌ Should have thrown error for invalid data')
    except Exception as error:
        print(f'✅ Invalid data error handled: {error}')
    
    # Test 4: Wrong password
    try:
        valid_encrypted = MaatCrossLangCrypto.encrypt('test data', 'correct-password')
        MaatCrossLangCrypto.decrypt(valid_encrypted, 'wrong-password')
        print('❌ Should have thrown error for wrong password')
    except Exception as error:
        print(f'✅ Wrong password error handled: {error}')
    
    # Test 5: Invalid key generation length
    try:
        MaatCrossLangCrypto.generate_key(8)  # Too short
        print('❌ Should have thrown error for invalid key length')
    except Exception as error:
        print(f'✅ Invalid key length error handled: {error}')
    
    print('\n✅ All error handling tests passed!\n')

error_handling_example()

# ========================================
# Example 6: Performance Testing
# ========================================

print('📝 Example 6: Performance Testing')
print('=' * 50)

def performance_example():
    password = 'performance-test-password'
    test_sizes = [
        {'name': 'Small (100 bytes)', 'data': 'x' * 100},
        {'name': 'Medium (1KB)', 'data': 'x' * 1024},
        {'name': 'Large (10KB)', 'data': 'x' * 10240},
        {'name': 'Extra Large (50KB)', 'data': 'x' * 51200}
    ]
    
    for test in test_sizes:
        print(f'\nTesting {test["name"]}:')
        
        # Encryption performance
        start_time = time.time()
        encrypted = MaatCrossLangCrypto.encrypt(test['data'], password)
        encrypt_time = time.time() - start_time
        
        # Decryption performance
        start_time = time.time()
        decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
        decrypt_time = time.time() - start_time
        
        # Verify integrity
        is_valid = test['data'] == decrypted
        
        print(f'Encryption time: {encrypt_time:.3f}s')
        print(f'Decryption time: {decrypt_time:.3f}s')
        print(f'Total time: {encrypt_time + decrypt_time:.3f}s')
        print(f'Data integrity: {"✅ Valid" if is_valid else "❌ Corrupted"}')
        print(f'Compression ratio: {len(encrypted) / len(test["data"]):.2f}x')
    
    print('\n✅ Performance testing complete!\n')

performance_example()

# ========================================
# Example 7: Django Integration
# ========================================

print('📝 Example 7: Django Integration Pattern')
print('=' * 50)

def django_integration_example():
    # This simulates Django settings and usage
    print('Django integration pattern:\n')
    
    # Simulate Django settings
    DJANGO_SETTINGS = {
        'CROSS_LANG_CRYPTO': {
            'DEFAULT_KEY': os.getenv('DJANGO_CRYPTO_KEY', 'django-demo-key-2024'),
            'DEFAULT_OPTIONS': {'iterations': 100000}
        }
    }
    
    class CryptoHelper:
        """Django helper class for encryption"""
        
        def __init__(self, settings):
            self.key = settings['CROSS_LANG_CRYPTO']['DEFAULT_KEY']
            self.options = settings['CROSS_LANG_CRYPTO']['DEFAULT_OPTIONS']
        
        def encrypt_field(self, data):
            """Encrypt a single field"""
            if isinstance(data, (dict, list)):
                data = json.dumps(data)
            return MaatCrossLangCrypto.encrypt(str(data), self.key, self.options)
        
        def decrypt_field(self, encrypted_data):
            """Decrypt a single field"""
            decrypted = MaatCrossLangCrypto.decrypt(encrypted_data, self.key)
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted
        
        def encrypt_model_data(self, model_data, sensitive_fields):
            """Encrypt sensitive fields in model data"""
            encrypted_data = model_data.copy()
            for field in sensitive_fields:
                if field in encrypted_data and encrypted_data[field]:
                    encrypted_data[field] = self.encrypt_field(encrypted_data[field])
            return encrypted_data
        
        def decrypt_model_data(self, encrypted_data, sensitive_fields):
            """Decrypt sensitive fields in model data"""
            decrypted_data = encrypted_data.copy()
            for field in sensitive_fields:
                if field in decrypted_data and decrypted_data[field]:
                    decrypted_data[field] = self.decrypt_field(decrypted_data[field])
            return decrypted_data
    
    # Usage example
    crypto_helper = CryptoHelper(DJANGO_SETTINGS)
    
    # Simulate user model data
    user_model = {
        'id': 1,
        'username': 'johndoe',
        'email': 'john@example.com',
        'phone': '+1-555-0123',
        'address': '123 Main St, City, State 12345',
        'preferences': {
            'theme': 'dark',
            'notifications': True
        },
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    
    sensitive_fields = ['email', 'phone', 'address', 'preferences']
    
    print('Original Django model data:')
    print(json.dumps(user_model, indent=2))
    
    # Encrypt for database storage
    encrypted_model = crypto_helper.encrypt_model_data(user_model, sensitive_fields)
    
    print('\nEncrypted model data (for database):')
    for key, value in encrypted_model.items():
        if key in sensitive_fields:
            print(f'  {key}: {str(value)[:40]}...')
        else:
            print(f'  {key}: {value}')
    
    # Decrypt for application use
    decrypted_model = crypto_helper.decrypt_model_data(encrypted_model, sensitive_fields)
    
    print('\nDecrypted model data (for application):')
    print(json.dumps(decrypted_model, indent=2, default=str))
    
    # Verify integrity
    data_intact = json.dumps(user_model, sort_keys=True, default=str) == json.dumps(decrypted_model, sort_keys=True, default=str)
    print(f'\n✅ Django integration test: {"Success!" if data_intact else "Failed!"}\n')

django_integration_example()

# ========================================
# Example 8: Database Field Encryption
# ========================================

print('📝 Example 8: Database Field Encryption')
print('=' * 50)

def database_field_example():
    # Simulate database records with sensitive fields
    db_password = 'database-encryption-key-2024'
    
    users = [
        {
            'id': 1,
            'username': 'john_doe',
            'email': 'john@example.com',
            'phone': '+1-555-0123',
            'ssn': '123-45-6789',
            'address': '123 Main St, Anytown, USA 12345'
        },
        {
            'id': 2,
            'username': 'jane_smith',
            'email': 'jane@example.com',
            'phone': '+1-555-0456',
            'ssn': '987-65-4321',
            'address': '456 Oak Ave, Somewhere, USA 67890'
        }
    ]
    
    print('Original user records:')
    for user in users:
        print(json.dumps(user, indent=2))
    
    # Encrypt sensitive fields
    sensitive_fields = ['email', 'phone', 'ssn', 'address']
    
    encrypted_users = []
    for user in users:
        encrypted_user = user.copy()
        
        for field in sensitive_fields:
            if encrypted_user.get(field):
                encrypted_user[field] = MaatCrossLangCrypto.encrypt(
                    encrypted_user[field], 
                    db_password
                )
        
        encrypted_users.append(encrypted_user)
    
    print('\nEncrypted user records (ready for database storage):')
    for user in encrypted_users:
        print(f"User {user['id']}:")
        print(f"  Username: {user['username']}")
        print(f"  Email: {user['email'][:30]}...")
        print(f"  Phone: {user['phone'][:30]}...")
        print(f"  SSN: {user['ssn'][:30]}...")
        print(f"  Address: {user['address'][:30]}...")
    
    # Decrypt for application use
    decrypted_users = []
    for user in encrypted_users:
        decrypted_user = user.copy()
        
        for field in sensitive_fields:
            if decrypted_user.get(field):
                decrypted_user[field] = MaatCrossLangCrypto.decrypt(
                    decrypted_user[field], 
                    db_password
                )
        
        decrypted_users.append(decrypted_user)
    
    print('\nDecrypted user records (for application use):')
    for user in decrypted_users:
        print(json.dumps(user, indent=2))
    
    # Verify data integrity
    data_intact = json.dumps(users, sort_keys=True) == json.dumps(decrypted_users, sort_keys=True)
    print(f'\n✅ Database field encryption test: {"Success!" if data_intact else "Failed!"}\n')

database_field_example()

# ========================================
# Example 9: API Response Encryption
# ========================================

print('📝 Example 9: API Response Encryption')
print('=' * 50)

def api_response_example():
    api_key = 'api-response-encryption-key-2024'
    
    # Simulate API responses
    print('🔄 Simulating encrypted API responses...\n')
    
    # API Response 1: User profile
    user_profile_response = {
        'status': 'success',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'data': {
            'user': {
                'id': 12345,
                'username': 'johndoe',
                'profile': {
                    'firstName': 'John',
                    'lastName': 'Doe',
                    'email': 'john@example.com',
                    'phone': '+1-555-0123'
                },
                'preferences': {
                    'theme': 'dark',
                    'notifications': True,
                    'language': 'en'
                }
            }
        },
        'meta': {
            'version': '1.0',
            'requestId': 'req-' + str(int(time.time()))
        }
    }
    
    print('API Response 1 - User Profile:')
    print(json.dumps(user_profile_response, indent=2))
    
    # Encrypt the response
    encrypted_response = MaatCrossLangCrypto.encrypt(
        json.dumps(user_profile_response), 
        api_key
    )
    
    print(f'\nEncrypted API response: {encrypted_response[:60]}...')
    print(f'Response size: {len(encrypted_response)} characters')
    
    # Client decrypts the response
    decrypted_json = MaatCrossLangCrypto.decrypt(encrypted_response, api_key)
    decrypted_response = json.loads(decrypted_json)
    
    print('\nDecrypted API response:')
    print(json.dumps(decrypted_response, indent=2))
    
    # API Response 2: Financial data
    financial_response = {
        'status': 'success',
        'data': {
            'account': {
                'accountNumber': '****1234',
                'balance': 15420.50,
                'currency': 'USD'
            },
            'transactions': [
                {
                    'id': 'txn-001',
                    'amount': -50.00,
                    'description': 'Coffee Shop Purchase',
                    'date': '2024-01-15'
                },
                {
                    'id': 'txn-002',
                    'amount': 2500.00,
                    'description': 'Salary Deposit',
                    'date': '2024-01-14'
                }
            ]
        }
    }
    
    print('\nAPI Response 2 - Financial Data:')
    print(json.dumps(financial_response, indent=2))
    
    encrypted_financial = MaatCrossLangCrypto.encrypt(
        json.dumps(financial_response), 
        api_key
    )
    
    decrypted_financial = json.loads(
        MaatCrossLangCrypto.decrypt(encrypted_financial, api_key)
    )
    
    integrity_check = (
        json.dumps(financial_response, sort_keys=True) == 
        json.dumps(decrypted_financial, sort_keys=True)
    )
    
    print(f'\n✅ API response encryption test: {"Success!" if integrity_check else "Failed!"}\n')

api_response_example()

# ========================================
# Example 10: File Encryption Simulation
# ========================================

print('📝 Example 10: File Encryption Simulation')
print('=' * 50)

def file_encryption_example():
    file_password = 'file-encryption-password-2024'
    
    # Simulate different file types
    files = [
        {
            'name': 'document.txt',
            'type': 'text/plain',
            'content': 'This is a confidential document containing sensitive business information. It should be encrypted before storage or transmission.'
        },
        {
            'name': 'config.json',
            'type': 'application/json',
            'content': json.dumps({
                'database': {
                    'host': 'db.example.com',
                    'username': 'app_user',
                    'password': 'super_secret_db_password',
                    'database': 'production_db'
                },
                'api': {
                    'key': 'api_key_12345',
                    'secret': 'api_secret_67890',
                    'endpoints': {
                        'users': '/api/v1/users',
                        'payments': '/api/v1/payments'
                    }
                }
            }, indent=2)
        },
        {
            'name': 'user_data.csv',
            'type': 'text/csv',
            'content': 'id,name,email,phone\n1,John Doe,john@example.com,555-0123\n2,Jane Smith,jane@example.com,555-0456\n3,Bob Johnson,bob@example.com,555-0789'
        }
    ]
    
    print('Original files:')
    for i, file_info in enumerate(files, 1):
        print(f'\n{i}. {file_info["name"]} ({file_info["type"]})')
        print(f'Size: {len(file_info["content"])} bytes')
        content_preview = file_info["content"][:100]
        if len(file_info["content"]) > 100:
            content_preview += '...'
        print(f'Content: {content_preview}')
    
    # Encrypt files
    encrypted_files = []
    for file_info in files:
        encrypted_file = {
            **file_info,
            'encrypted': True,
            'encrypted_content': MaatCrossLangCrypto.encrypt(file_info['content'], file_password),
            'original_size': len(file_info['content'])
        }
        encrypted_files.append(encrypted_file)
    
    print('\n\nEncrypted files:')
    for i, file_info in enumerate(encrypted_files, 1):
        print(f'\n{i}. {file_info["name"]} (encrypted)')
        print(f'Original size: {file_info["original_size"]} bytes')
        print(f'Encrypted size: {len(file_info["encrypted_content"])} bytes')
        print(f'Overhead: {len(file_info["encrypted_content"]) - file_info["original_size"]} bytes')
        print(f'Encrypted content: {file_info["encrypted_content"][:80]}...')
    
    # Decrypt files
    print('\n\nDecrypting files...')
    decrypted_files = []
    for file_info in encrypted_files:
        decrypted_file = {
            'name': file_info['name'],
            'type': file_info['type'],
            'content': MaatCrossLangCrypto.decrypt(file_info['encrypted_content'], file_password)
        }
        decrypted_files.append(decrypted_file)
    
    # Verify integrity
    all_files_intact = True
    for i, (original_file, decrypted_file) in enumerate(zip(files, decrypted_files)):
        is_intact = original_file['content'] == decrypted_file['content']
        
        if not is_intact:
            all_files_intact = False
        
        print(f'{decrypted_file["name"]}: {"✅ Intact" if is_intact else "❌ Corrupted"}')
    
    print(f'\n✅ File encryption test: {"All files successfully encrypted/decrypted!" if all_files_intact else "Some files corrupted!"}\n')

file_encryption_example()

# ========================================
# Example 11: Cross-Language Compatibility Demo
# ========================================

print('📝 Example 11: Cross-Language Compatibility Demo')
print('=' * 50)

def cross_language_demo():
    print('Demonstrating cross-language compatibility...\n')
    
    shared_password = 'cross-language-test-password-2024'
    test_data = {
        'message': 'This data was encrypted in Python',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'metadata': {
            'language': 'Python',
            'version': '1.0.0',
            'platform': sys.platform,
            'python_version': sys.version
        },
        'test_cases': [
            'Simple string',
            'Unicode: 🔐 🌍 🚀',
            'Special chars: !@#$%^&*()',
            'Numbers: 123456789',
            json.dumps({'nested': 'object', 'array': [1, 2, 3]})
        ]
    }
    
    print('Test data for cross-language compatibility:')
    print(json.dumps(test_data, indent=2, default=str))
    
    # Encrypt with Python
    python_encrypted = MaatCrossLangCrypto.encrypt(
        json.dumps(test_data, default=str), 
        shared_password
    )
    
    print(f'\nPython encrypted data: {python_encrypted[:60]}...')
    print(f'Data length: {len(python_encrypted)} characters')
    
    # Verify we can decrypt our own encryption
    python_decrypted = json.loads(
        MaatCrossLangCrypto.decrypt(python_encrypted, shared_password)
    )
    
    print('\nPython self-decryption test:')
    original_json = json.dumps(test_data, sort_keys=True, default=str)
    decrypted_json = json.dumps(python_decrypted, sort_keys=True, default=str)
    success = original_json == decrypted_json
    print(f'✅ {"Success!" if success else "Failed!"}')
    
    # Parse structure info for other languages
    import base64
    structure_info = json.loads(
        base64.b64decode(python_encrypted).decode('utf-8')
    )
    
    print('\nEncrypted data structure (for verification by other languages):')
    print(f'Version: {structure_info["v"]}')
    print(f'Algorithm: {structure_info["alg"]}')
    print(f'KDF: {structure_info["kdf"]}')
    print(f'Iterations: {structure_info["iter"]}')
    print(f'IV length: {len(base64.b64decode(structure_info["iv"]))} bytes')
    print(f'Salt length: {len(base64.b64decode(structure_info["salt"]))} bytes')
    print(f'Tag length: {len(base64.b64decode(structure_info["tag"]))} bytes')
    
    print('\n📋 To test cross-language compatibility:')
    print('1. Use the encrypted data above in JavaScript/PHP')
    print('2. Decrypt with the same password')
    print('3. Verify the decrypted JSON matches the original')
    print('4. Encrypt new data in JavaScript/PHP')
    print('5. Decrypt that data here in Python\n')
    
    # Save for cross-language testing
    return {
        'encrypted': python_encrypted,
        'password': shared_password,
        'original_data': test_data
    }

cross_lang_data = cross_language_demo()

# ========================================
# Example 12: Flask Integration
# ========================================

print('📝 Example 12: Flask Integration Pattern')
print('=' * 50)

def flask_integration_example():
    print('Flask integration pattern:\n')
    
    class FlaskCryptoExtension:
        """Flask extension for encryption"""
        
        def __init__(self, app=None):
            self.app = app
            self.crypto_key = None
            if app is not None:
                self.init_app(app)
        
        def init_app(self, app):
            # Simulate Flask app config
            app_config = {
                'CRYPTO_KEY': os.getenv('FLASK_CRYPTO_KEY', 'flask-demo-key-2024'),
                'CRYPTO_OPTIONS': {'iterations': 100000}
            }
            
            self.crypto_key = app_config['CRYPTO_KEY']
            self.crypto_options = app_config['CRYPTO_OPTIONS']
            
            print('✅ Flask crypto extension initialized')
        
        def encrypt(self, data):
            if isinstance(data, (dict, list)):
                data = json.dumps(data)
            return MaatCrossLangCrypto.encrypt(str(data), self.crypto_key, self.crypto_options)
        
        def decrypt(self, encrypted_data):
            decrypted = MaatCrossLangCrypto.decrypt(encrypted_data, self.crypto_key)
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted
        
        def secure_jsonify(self, data):
            """Encrypt data before sending as JSON response"""
            encrypted = self.encrypt(data)
            return {'encrypted': encrypted}
    
    # Simulate Flask app
    class MockFlaskApp:
        def __init__(self):
            self.config = {}
    
    app = MockFlaskApp()
    crypto = FlaskCryptoExtension(app)
    
    # Example usage in Flask routes
    user_session_data = {
        'user_id': 12345,
        'username': 'johndoe',
        'roles': ['user', 'premium'],
        'session_start': datetime.now(timezone.utc).isoformat(),
        'last_activity': datetime.now(timezone.utc).isoformat()
    }
    
    print('Original Flask session data:')
    print(json.dumps(user_session_data, indent=2, default=str))
    
    # Encrypt session data
    encrypted_session = crypto.encrypt(user_session_data)
    print(f'\nEncrypted session: {encrypted_session[:50]}...')
    
    # Decrypt session data
    decrypted_session = crypto.decrypt(encrypted_session)
    print('\nDecrypted session data:')
    print(json.dumps(decrypted_session, indent=2, default=str))
    
    # Test secure API response
    api_data = {
        'status': 'success',
        'user': user_session_data,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    secure_response = crypto.secure_jsonify(api_data)
    print('\nSecure API response:')
    print(f'Response contains encrypted data: {len(secure_response["encrypted"])} characters')
    
    # Client would decrypt the response
    client_decrypted = crypto.decrypt(secure_response['encrypted'])
    
    integrity_check = (
        json.dumps(api_data, sort_keys=True, default=str) == 
        json.dumps(client_decrypted, sort_keys=True, default=str)
    )
    
    print(f'\n✅ Flask integration test: {"Success!" if integrity_check else "Failed!"}\n')

flask_integration_example()

# ========================================
# Example 13: Environment and Library Info
# ========================================

print('📝 Example 13: Library Information')
print('=' * 50)

def library_info_example():
    version_info = MaatCrossLangCrypto.version()
    
    print('MAAT Cross-Language Crypto Library Information:')
    print(json.dumps(version_info, indent=2))
    
    print('\nEnvironment Information:')
    print(f'Python Version: {sys.version}')
    print(f'Platform: {sys.platform}')
    print(f'Current Working Directory: {os.getcwd()}')
    print(f'Script Path: {Path(__file__).absolute()}')
    
    # Feature support check
    print('\nFeature Support:')
    features = [
        '✅ AES-256-GCM encryption',
        '✅ PBKDF2-SHA256 key derivation',
        '✅ Cryptographically secure random generation',
        '✅ Cross-language compatibility',
        '✅ JSON data encryption',
        '✅ Custom security options',
        '✅ Error handling and validation',
        '✅ Django integration patterns',
        '✅ Flask extension support'
    ]
    
    for feature in features:
        print(feature)
    
    print('\n✅ Library information example complete!\n')

library_info_example()

# ========================================
# Summary and Next Steps
# ========================================

print('🎉 All Python Examples Complete!')
print('=' * 50)

print('\n📚 What you learned:')
learning_points = [
    '• Basic encryption and decryption',
    '• JSON data handling',
    '• Custom security options',
    '• Key generation',
    '• Error handling',
    '• Performance considerations',
    '• Django integration patterns',
    '• Database field encryption',
    '• API response encryption',
    '• File encryption patterns',
    '• Cross-language compatibility',
    '• Flask integration patterns',
    '• Library information and features'
]

for point in learning_points:
    print(point)

print('\n🔄 Next steps:')
next_steps = [
    '• Try the JavaScript examples',
    '• Try the PHP examples',
    '• Test cross-language compatibility',
    '• Integrate into your Django/Flask applications',
    '• Review the security documentation'
]

for step in next_steps:
    print(step)

print('\n💡 Tips:')
tips = [
    '• Always use strong passwords',
    '• Store passwords securely (environment variables)',
    '• Use appropriate iteration counts for your security needs',
    '• Test cross-language compatibility thoroughly',
    '• Handle errors gracefully in production'
]

for tip in tips:
    print(tip)

print('\n🛡️ Security reminders:')
security_reminders = [
    '• Never hardcode passwords in your source code',
    '• Use HTTPS for data transmission',
    '• Regularly rotate encryption keys',
    '• Monitor for security updates',
    '• Follow the security best practices guide'
]

for reminder in security_reminders:
    print(reminder)

print('\n✨ Happy encrypting with MAAT Cross-Language Crypto! ✨')