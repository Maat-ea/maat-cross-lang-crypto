/**
 * Basic JavaScript Crypto Tests
 */

const MaatCrossLangCrypto = require('../src/index.js');

class BasicCryptoTests {
  static runAllTests() {
    console.log('🧪 Running Basic Crypto Tests...\n');
    
    try {
      this.testBasicEncryptDecrypt();
      this.testDifferentDataTypes();
      this.testCustomOptions();
      this.testErrorHandling();
      this.testKeyGeneration();
      
      console.log('✅ All basic tests passed!');
    } catch (error) {
      console.error('❌ Test failed:', error.message);
      process.exit(1);
    }
  }

  static testBasicEncryptDecrypt() {
    console.log('📝 Testing basic encrypt/decrypt...');
    
    const password = 'test-password-123';
    const originalData = 'Hello, World!';
    
    const encrypted = MaatCrossLangCrypto.encrypt(originalData, password);
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
    
    if (decrypted !== originalData) {
      throw new Error(`Decryption failed. Expected: "${originalData}", Got: "${decrypted}"`);
    }
    
    console.log('  ✅ Basic encryption/decryption works\n');
  }

  static testDifferentDataTypes() {
    console.log('📝 Testing different data types...');
    
    const password = 'test-password-456';
    const testCases = [
      'Simple string',
      '{"json": "data", "number": 42}',
      'Special chars: äöü ñ 中文 🚀',
      'Multi\nline\ntext\nwith\nbreaks',
      '   whitespace   test   ',
      '1234567890'
    ];
    
    testCases.forEach((data, index) => {
      const encrypted = MaatCrossLangCrypto.encrypt(data, password);
      const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
      
      if (decrypted !== data) {
        throw new Error(`Test case ${index} failed`);
      }
    });
    
    console.log('  ✅ Different data types work\n');
  }

  static testCustomOptions() {
    console.log('📝 Testing custom options...');
    
    const password = 'test-password-789';
    const data = 'Custom options test';
    
    const customOptions = {
      iterations: 50000,
      keyLength: 32,
      ivLength: 12,
      saltLength: 16
    };
    
    const encrypted = MaatCrossLangCrypto.encrypt(data, password, customOptions);
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
    
    if (decrypted !== data) {
      throw new Error('Custom options test failed');
    }
    
    // Verify the options were used
    const parsedData = JSON.parse(Buffer.from(encrypted, 'base64').toString());
    if (parsedData.iter !== customOptions.iterations) {
      throw new Error('Custom iterations not used');
    }
    
    console.log('  ✅ Custom options work\n');
  }

  static testErrorHandling() {
    console.log('📝 Testing error handling...');
    
    // Test empty inputs
    this.expectError(() => MaatCrossLangCrypto.encrypt('', 'password'), 'empty data');
    this.expectError(() => MaatCrossLangCrypto.encrypt('data', ''), 'empty password');
    this.expectError(() => MaatCrossLangCrypto.decrypt('', 'password'), 'empty encrypted');
    this.expectError(() => MaatCrossLangCrypto.decrypt('invalid', 'password'), 'invalid data');
    
    // Test wrong password
    const encrypted = MaatCrossLangCrypto.encrypt('test', 'password1');
    this.expectError(() => MaatCrossLangCrypto.decrypt(encrypted, 'password2'), 'wrong password');
    
    console.log('  ✅ Error handling works\n');
  }

  static testKeyGeneration() {
    console.log('📝 Testing key generation...');
    
    const key1 = MaatCrossLangCrypto.generateKey();
    const key2 = MaatCrossLangCrypto.generateKey();
    
    if (key1 === key2) {
      throw new Error('Generated keys should be different');
    }
    
    // Test custom key lengths
    const shortKey = MaatCrossLangCrypto.generateKey(16);
    const longKey = MaatCrossLangCrypto.generateKey(64);
    
    if (Buffer.from(shortKey, 'base64').length !== 16) {
      throw new Error('Short key wrong length');
    }
    
    if (Buffer.from(longKey, 'base64').length !== 64) {
      throw new Error('Long key wrong length');
    }
    
    console.log('  ✅ Key generation works\n');
  }

  static expectError(fn, description) {
    try {
      fn();
      throw new Error(`Expected error for: ${description}`);
    } catch (error) {
      if (error.message.startsWith('Expected error')) {
        throw error;
      }
      // Error was thrown as expected
    }
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  BasicCryptoTests.runAllTests();
}

module.exports = BasicCryptoTests;