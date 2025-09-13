"""
Performance Tests for Python Implementation
"""

import unittest
import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from maat_cross_lang_crypto import MaatCrossLangCrypto


class TestPerformance(unittest.TestCase):
    
    def test_performance_benchmarks(self):
        """Run performance benchmarks"""
        print("⚡ Running Python performance tests...\n")
        
        password = 'performance-test-password'
        test_sizes = [
            {'name': 'Small (100 bytes)', 'data': 'x' * 100},
            {'name': 'Medium (1KB)', 'data': 'x' * 1024},
            {'name': 'Large (10KB)', 'data': 'x' * 10240}
        ]
        
        for test in test_sizes:
            iterations = 10 if len(test['data']) > 5000 else 100
            
            print(f"Testing {test['name']}:")
            
            # Encryption performance
            enc_start = time.time()
            encrypted = None
            for _ in range(iterations):
                encrypted = MaatCrossLangCrypto.encrypt(test['data'], password)
            enc_time = (time.time() - enc_start) * 1000 / iterations
            
            # Decryption performance  
            dec_start = time.time()
            for _ in range(iterations):
                MaatCrossLangCrypto.decrypt(encrypted, password)
            dec_time = (time.time() - dec_start) * 1000 / iterations
            
            print(f"  Encryption: {enc_time:.2f}ms avg")
            print(f"  Decryption: {dec_time:.2f}ms avg")
            print(f"  Total: {enc_time + dec_time:.2f}ms avg\n")
        
        # Just assert that we completed without errors
        self.assertTrue(True)


if __name__ == '__main__':
    print("⚡ Running Python Performance Tests...\n")
    unittest.main(verbosity=2)