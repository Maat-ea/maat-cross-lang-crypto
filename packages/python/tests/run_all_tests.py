"""
Run All Python Tests - Main Test Runner
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_all_tests():
    """Run all test suites"""
    print("🚀 Starting Complete Python Test Suite\n")
    print("=" * 50)
    
    # Discover and run all tests
    loader = unittest.TestLoader()
    suite = loader.discover('.', pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 50)
    
    if result.wasSuccessful():
        print("🎉 ALL PYTHON TESTS COMPLETED SUCCESSFULLY!")
        print("✅ Your Python implementation is ready for production")
        return True
    else:
        print("❌ SOME TESTS FAILED!")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        return False


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)