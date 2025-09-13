#!/usr/bin/env python3

"""
Cross-Language Test Vector Validator - Python
Validates that implementations work with shared test vectors
"""

import json
import sys
import os
import base64
from pathlib import Path
from typing import Dict, Any, Optional


class TestVectorValidator:
    def __init__(self, crypto_implementation):
        self.crypto = crypto_implementation
        self.test_vectors = None
    
    def load_test_vectors(self, file_path: str = '../test-vectors/test-vectors.json'):
        try:
            full_path = Path(__file__).parent / file_path
            
            if not full_path.exists():
                raise Exception(f'Test vectors file not found: {full_path}')
            
            with open(full_path, 'r', encoding='utf-8') as f:
                self.test_vectors = json.load(f)
            
            print('✅ Test vectors loaded successfully')
            return self.test_vectors
            
        except Exception as e:
            raise Exception(f'Failed to load test vectors: {e}')
    
    def validate_all_vectors(self):
        print('🧪 Validating implementation against test vectors...\n')
        
        if not self.test_vectors:
            raise Exception('Test vectors not loaded. Call load_test_vectors() first.')
        
        results = {
            'passed': 0,
            'failed': 0,
            'total': len(self.test_vectors['vectors']),
            'details': []
        }
        
        for index, vector in enumerate(self.test_vectors['vectors']):
            print(f"Testing vector {index + 1}: {vector['description']}")
            
            try:
                result = self.validate_single_vector(vector)
                
                if result['success']:
                    print("  ✅ Passed")
                    results['passed'] += 1
                else:
                    print(f"  ❌ Failed: {result['error']}")
                    results['failed'] += 1
                
                results['details'].append({
                    'id': vector['id'],
                    'success': result['success'],
                    'error': result.get('error'),
                    'details': result.get('details')
                })
                
            except Exception as e:
                print(f"  ❌ Error: {e}")
                results['failed'] += 1
                results['details'].append({
                    'id': vector['id'],
                    'success': False,
                    'error': str(e)
                })
        
        print(f"\n📊 Validation Summary:")
        print(f"  Passed: {results['passed']}/{results['total']}")
        print(f"  Failed: {results['failed']}/{results['total']}")
        success_rate = (results['passed'] / results['total']) * 100
        print(f"  Success rate: {success_rate:.1f}%")
        
        return results
    
    def validate_single_vector(self, vector: Dict[str, Any]):
        input_data = vector['input']
        
        try:
            # Test 1: Encrypt the input data with our implementation
            print("    → Testing self-encryption and decryption...")
            encrypted = self.crypto.encrypt(input_data['data'], input_data['password'], input_data['options'])
            
            if not encrypted:
                return {
                    'success': False,
                    'error': 'Encryption returned empty result'
                }
            
            print(f"    → Encrypted data length: {len(encrypted)} characters")
            
            # Test 2: Decrypt our own encryption
            print("    → Testing decryption of our encrypted data...")
            decrypted = self.crypto.decrypt(encrypted, input_data['password'])
            
            if decrypted != input_data['data']:
                return {
                    'success': False,
                    'error': f"Decryption mismatch. Expected: \"{input_data['data']}\", Got: \"{decrypted}\""
                }
            
            print("    → Decrypted data matches original ✓")
            
            # Test 3: Validate structure format
            print("    → Validating encrypted data structure...")
            structure = self.parse_encrypted_data(encrypted)
            structure_validation = self.validate_structure(structure, input_data['options'])
            
            if not structure_validation['valid']:
                return {
                    'success': False,
                    'error': f"Structure validation failed: {structure_validation['error']}"
                }
            
            print("    → Structure format is valid ✓")
            
            # Test 4: Test with wrong password (should fail)
            print("    → Testing wrong password (should fail)...")
            try:
                self.crypto.decrypt(encrypted, 'wrong-password')
                return {
                    'success': False,
                    'error': 'Wrong password should have failed but succeeded'
                }
            except Exception:
                print("    → Wrong password correctly rejected ✓")
            
            return {
                'success': True,
                'details': {
                    'encrypted_length': len(encrypted),
                    'original_length': len(input_data['data']),
                    'structure_valid': True,
                    'wrong_password_rejected': True
                }
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def parse_encrypted_data(self, encrypted: str) -> Dict[str, Any]:
        try:
            json_str = base64.b64decode(encrypted).decode('utf-8')
            return json.loads(json_str)
        except Exception as e:
            raise Exception(f'Failed to parse encrypted data: {e}')
    
    def validate_structure(self, structure: Dict[str, Any], expected_options: Dict[str, Any]) -> Dict[str, Any]:
        # Check required fields
        required = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data']
        
        for field in required:
            if field not in structure or not structure[field]:
                return {'valid': False, 'error': f'Missing required field: {field}'}
        
        # Check values
        if structure['v'] != '1.0.0':
            return {'valid': False, 'error': f'Wrong version: {structure["v"]}'}
        if structure['alg'] != 'AES-256-GCM':
            return {'valid': False, 'error': f'Wrong algorithm: {structure["alg"]}'}
        if structure['kdf'] != 'PBKDF2-SHA256':
            return {'valid': False, 'error': f'Wrong KDF: {structure["kdf"]}'}
        if structure['iter'] != expected_options['iterations']:
            return {'valid': False, 'error': f'Wrong iterations: {structure["iter"]} vs {expected_options["iterations"]}'}
        
        # Check base64 field lengths
        try:
            iv = base64.b64decode(structure['iv'])
            salt = base64.b64decode(structure['salt'])
            tag = base64.b64decode(structure['tag'])
            
            if len(iv) != 12:
                return {'valid': False, 'error': f'Wrong IV length: {len(iv)} bytes (should be 12)'}
            if len(salt) != 16:
                return {'valid': False, 'error': f'Wrong salt length: {len(salt)} bytes (should be 16)'}
            if len(tag) != 16:
                return {'valid': False, 'error': f'Wrong tag length: {len(tag)} bytes (should be 16)'}
                
        except Exception as e:
            return {'valid': False, 'error': f'Base64 decode error: {e}'}
        
        return {'valid': True}
    
    def test_basic_functionality(self) -> bool:
        print('🔧 Testing basic functionality...\n')
        
        try:
            # Test 1: Simple encryption/decryption
            print('Test 1: Basic encrypt/decrypt')
            data = 'Hello World!'
            password = 'test-password'
            
            encrypted = self.crypto.encrypt(data, password)
            print(f'  Encrypted: {encrypted[:50]}...')
            
            decrypted = self.crypto.decrypt(encrypted, password)
            print(f'  Decrypted: {decrypted}')
            
            if data == decrypted:
                print('  ✅ Basic test passed!\n')
            else:
                print('  ❌ Basic test failed!\n')
                return False
            
            # Test 2: Key generation
            print('Test 2: Key generation')
            key1 = self.crypto.generate_key()
            key2 = self.crypto.generate_key()
            
            print(f'  Key 1: {key1[:20]}...')
            print(f'  Key 2: {key2[:20]}...')
            
            if key1 != key2:
                print('  ✅ Key generation test passed!\n')
            else:
                print('  ❌ Keys should be different!\n')
                return False
            
            # Test 3: Version info
            print('Test 3: Version info')
            version = self.crypto.version()
            print(f'  Version: {version["version"]}')
            print(f'  Algorithm: {version["algorithm"]}')
            print('  ✅ Version info test passed!\n')
            
            return True
            
        except Exception as e:
            print(f'  ❌ Basic functionality test failed: {e}\n')
            return False
    
    def generate_report(self, results: Dict[str, Any], output_path: str = '../test-vectors/validation-report-python.json'):
        from datetime import datetime
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'implementation': 'python',
            'test_vectors_version': self.test_vectors.get('metadata', {}).get('version', 'unknown') if self.test_vectors else 'unknown',
            'summary': {
                'total_tests': results['total'],
                'passed': results['passed'],
                'failed': results['failed'],
                'success_rate': f"{(results['passed'] / results['total']) * 100:.1f}%"
            },
            'details': results['details'],
            'environment': {
                'python_version': sys.version,
                'platform': sys.platform
            }
        }
        
        try:
            full_path = Path(__file__).parent / output_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f'\n📊 Validation report saved to: {full_path}')
            
        except Exception as e:
            print(f'⚠️  Could not save report: {e}')
        
        return report


def main():
    print('🚀 Starting Python Implementation Validation\n')
    print('=' * 60)
    
    try:
        # Try to load the crypto implementation
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        try:
            from packages.python.maat_cross_lang_crypto import MaatCrossLangCrypto
        except ImportError as e:
            print('❌ Failed to load Python crypto implementation:')
            print('   Make sure the module exists at: packages/python/cross_lang_crypto/')
            print(f'   Error: {e}')
            sys.exit(1)
        
        # Create validator with our crypto implementation
        validator = TestVectorValidator(MaatCrossLangCrypto)
        
        # First, test basic functionality
        print('\nPhase 1: Basic Functionality Tests')
        print('-' * 40)
        
        if not validator.test_basic_functionality():
            print('❌ Basic functionality tests failed. Stopping.')
            sys.exit(1)
        
        # Load test vectors
        print('Phase 2: Test Vector Validation')
        print('-' * 40)
        print('📁 Loading test vectors...')
        
        try:
            validator.load_test_vectors()
        except Exception as e:
            print(f'❌ Failed to load test vectors: {e}')
            print('\n💡 Make sure you have:')
            print('1. Created test-vectors/test-vectors.json file')
            print('2. Run this script from the project root directory')
            sys.exit(1)
        
        # Run validation against test vectors
        results = validator.validate_all_vectors()
        
        # Generate report
        report = validator.generate_report(results)
        
        print('\n' + '=' * 60)
        
        if results['failed'] == 0:
            print('🎉 All tests passed! Python implementation is working correctly.')
            print('✅ Your implementation can handle all test vector scenarios.')
            print('🔄 Ready for cross-language compatibility testing.')
            sys.exit(0)
        else:
            print('⚠️  Some tests had issues. Check details above.')
            print('💡 This is normal during development - fix issues one by one.')
            
            # Show summary of failures
            failed = [d for d in results['details'] if not d['success']]
            failed_ids = [f['id'] for f in failed]
            print(f'\n❌ Failed tests: {", ".join(failed_ids)}')
            
            sys.exit(1)
            
    except Exception as e:
        print(f'❌ Validation failed: {e}')
        
        # Provide helpful debugging info
        print('\n🔍 Debugging checklist:')
        print('1. Is your crypto implementation working? Try: python packages/python/cross_lang_crypto/crypto.py')
        print('2. Does test-vectors.json exist? Check: test-vectors/test-vectors.json')
        print('3. Are you running from project root? Current dir:', os.getcwd())
        
        sys.exit(1)


if __name__ == '__main__':
    main()