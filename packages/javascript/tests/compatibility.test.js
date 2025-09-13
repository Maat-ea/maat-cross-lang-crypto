/**
 * Cross-Language Compatibility Tests
 */

const MaatCrossLangCrypto = require('../src/index.js');

class CompatibilityTests {
  static runCompatibilityTests() {
    console.log('🌐 Running compatibility tests...\n');
    
    try {
      this.testDataStructureConsistency();
      this.testKnownTestVectors();
      this.testVersionCompatibility();
      
      console.log('✅ All compatibility tests passed!');
    } catch (error) {
      console.error('❌ Compatibility test failed:', error.message);
      throw error;
    }
  }

  static testDataStructureConsistency() {
    console.log('📝 Testing data structure consistency...');
    
    const password = 'structure-test';
    const data = 'Test data for structure validation';
    
    const encrypted = MaatCrossLangCrypto.encrypt(data, password);
    const structure = this.parseEncryptedData(encrypted);
    
    // Validate required fields
    const requiredFields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
    requiredFields.forEach(field => {
      if (!structure[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    });
    
    // Validate field values
    if (structure.v !== '1.0.0') throw new Error('Wrong version');
    if (structure.alg !== 'AES-256-GCM') throw new Error('Wrong algorithm');
    if (structure.kdf !== 'PBKDF2-SHA256') throw new Error('Wrong KDF');
    
    console.log('  ✅ Data structure is consistent\n');
  }

  static testKnownTestVectors() {
    console.log('📝 Testing with known test vectors...');
    
    const testVectors = [
      {
        password: 'test123',
        data: 'Hello World',
        options: { iterations: 10000 }
      },
      {
        password: 'secure-key-456',
        data: '{"test": "json", "value": 42}',
        options: { iterations: 25000 }
      }
    ];
    
    testVectors.forEach((vector, index) => {
      const encrypted = MaatCrossLangCrypto.encrypt(
        vector.data, 
        vector.password, 
        vector.options
      );
      const decrypted = MaatCrossLangCrypto.decrypt(encrypted, vector.password);
      
      if (decrypted !== vector.data) {
        throw new Error(`Test vector ${index} failed`);
      }
    });
    
    console.log('  ✅ Test vectors work correctly\n');
  }

  static testVersionCompatibility() {
    console.log('📝 Testing version compatibility...');
    
    const versionInfo = MaatCrossLangCrypto.version();
    
    if (!versionInfo.version) throw new Error('Missing version info');
    if (!versionInfo.algorithm) throw new Error('Missing algorithm info');
    if (!versionInfo.library) throw new Error('Missing library info');
    
    console.log('  ✅ Version compatibility checks passed\n');
  }

  static parseEncryptedData(encrypted) {
    const jsonStr = Buffer.from(encrypted, 'base64').toString();
    return JSON.parse(jsonStr);
  }
}

// Run if executed directly
if (require.main === module) {
  CompatibilityTests.runCompatibilityTests();
}

module.exports = CompatibilityTests;