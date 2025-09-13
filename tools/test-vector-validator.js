/**
 * Cross-Language Test Vector Validator - JavaScript
 * Validates that implementations work with shared test vectors
 */

const fs = require('fs');
const path = require('path');

class TestVectorValidator {
  constructor(cryptoImplementation) {
    this.crypto = cryptoImplementation;
    this.testVectors = null;
  }

  loadTestVectors(filePath = '../test-vectors/test-vectors.json') {
    try {
      const fullPath = path.resolve(__dirname, filePath);
      if (!fs.existsSync(fullPath)) {
        throw new Error(`Test vectors file not found: ${fullPath}`);
      }
      
      const data = fs.readFileSync(fullPath, 'utf8');
      this.testVectors = JSON.parse(data);
      console.log('✅ Test vectors loaded successfully');
      return this.testVectors;
    } catch (error) {
      throw new Error(`Failed to load test vectors: ${error.message}`);
    }
  }

  validateAllVectors() {
    console.log('🧪 Validating implementation against test vectors...\n');
    
    if (!this.testVectors) {
      throw new Error('Test vectors not loaded. Call loadTestVectors() first.');
    }

    const results = {
      passed: 0,
      failed: 0,
      total: this.testVectors.vectors.length,
      details: []
    };

    this.testVectors.vectors.forEach((vector, index) => {
      console.log(`Testing vector ${index + 1}: ${vector.description}`);
      
      try {
        const result = this.validateSingleVector(vector);
        
        if (result.success) {
          console.log(`  ✅ Passed`);
          results.passed++;
        } else {
          console.log(`  ❌ Failed: ${result.error}`);
          results.failed++;
        }
        
        results.details.push({
          id: vector.id,
          success: result.success,
          error: result.error || null,
          details: result.details || null
        });
        
      } catch (error) {
        console.log(`  ❌ Error: ${error.message}`);
        results.failed++;
        results.details.push({
          id: vector.id,
          success: false,
          error: error.message
        });
      }
    });

    console.log(`\n📊 Validation Summary:`);
    console.log(`  Passed: ${results.passed}/${results.total}`);
    console.log(`  Failed: ${results.failed}/${results.total}`);
    console.log(`  Success rate: ${((results.passed / results.total) * 100).toFixed(1)}%`);

    return results;
  }

  validateSingleVector(vector) {
    const { input } = vector;
    
    try {
      // Test 1: Encrypt the input data with our implementation
      console.log('    → Testing self-encryption and decryption...');
      const encrypted = this.crypto.encrypt(input.data, input.password, input.options);
      
      if (!encrypted) {
        return {
          success: false,
          error: 'Encryption returned empty result'
        };
      }

      console.log(`    → Encrypted data length: ${encrypted.length} characters`);

      // Test 2: Decrypt our own encryption
      console.log('    → Testing decryption of our encrypted data...');
      const decrypted = this.crypto.decrypt(encrypted, input.password);
      
      if (decrypted !== input.data) {
        return {
          success: false,
          error: `Decryption mismatch. Expected: "${input.data}", Got: "${decrypted}"`
        };
      }

      console.log('    → Decrypted data matches original ✓');

      // Test 3: Validate structure format
      console.log('    → Validating encrypted data structure...');
      const structure = this.parseEncryptedData(encrypted);
      const structureValidation = this.validateStructure(structure, input.options);
      
      if (!structureValidation.valid) {
        return {
          success: false,
          error: `Structure validation failed: ${structureValidation.error}`
        };
      }

      console.log('    → Structure format is valid ✓');

      // Test 4: Test with wrong password (should fail)
      console.log('    → Testing wrong password (should fail)...');
      try {
        this.crypto.decrypt(encrypted, 'wrong-password');
        return {
          success: false,
          error: 'Wrong password should have failed but succeeded'
        };
      } catch (error) {
        console.log('    → Wrong password correctly rejected ✓');
      }

      return {
        success: true,
        details: {
          encrypted_length: encrypted.length,
          original_length: input.data.length,
          structure_valid: true,
          wrong_password_rejected: true
        }
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  parseEncryptedData(encrypted) {
    try {
      const jsonStr = Buffer.from(encrypted, 'base64').toString('utf8');
      return JSON.parse(jsonStr);
    } catch (error) {
      throw new Error(`Failed to parse encrypted data: ${error.message}`);
    }
  }

  validateStructure(structure, expectedOptions) {
    // Check required fields
    const required = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
    for (const field of required) {
      if (!structure[field]) {
        return { valid: false, error: `Missing required field: ${field}` };
      }
    }

    // Check values
    if (structure.v !== '1.0.0') {
      return { valid: false, error: `Wrong version: ${structure.v}` };
    }
    if (structure.alg !== 'AES-256-GCM') {
      return { valid: false, error: `Wrong algorithm: ${structure.alg}` };
    }
    if (structure.kdf !== 'PBKDF2-SHA256') {
      return { valid: false, error: `Wrong KDF: ${structure.kdf}` };
    }
    if (structure.iter !== expectedOptions.iterations) {
      return { valid: false, error: `Wrong iterations: ${structure.iter} vs ${expectedOptions.iterations}` };
    }

    // Check base64 field lengths
    try {
      const iv = Buffer.from(structure.iv, 'base64');
      const salt = Buffer.from(structure.salt, 'base64');
      const tag = Buffer.from(structure.tag, 'base64');
      
      if (iv.length !== 12) {
        return { valid: false, error: `Wrong IV length: ${iv.length} bytes (should be 12)` };
      }
      if (salt.length !== 16) {
        return { valid: false, error: `Wrong salt length: ${salt.length} bytes (should be 16)` };
      }
      if (tag.length !== 16) {
        return { valid: false, error: `Wrong tag length: ${tag.length} bytes (should be 16)` };
      }
      
    } catch (error) {
      return { valid: false, error: `Base64 decode error: ${error.message}` };
    }

    return { valid: true };
  }

  runCompatibilityTests() {
    console.log('🔄 Running cross-language compatibility tests...\n');
    
    if (!this.testVectors || !this.testVectors.cross_language_tests) {
      console.log('⚠️  No cross-language tests defined in test vectors.');
      return;
    }
    
    // For now, we can only test our own implementation
    // But this sets up the structure for cross-language testing
    this.testVectors.cross_language_tests.forEach(test => {
      console.log(`📝 ${test.description}`);
      
      if (test.test_id === 'js_to_php' || test.test_id === 'python_to_js') {
        console.log(`  → Would test: ${test.description}`);
        console.log(`  → Status: Requires other language implementations to generate test data`);
      } else if (test.test_id === 'round_trip') {
        console.log(`  → Would test: ${test.description}`);
        console.log(`  → Status: Requires all language implementations`);
      }
      
      console.log(`  → Test vectors: ${test.vector_ids.join(', ')}`);
      console.log(`  → Expected: ${test.expected_result}\n`);
    });
    
    console.log('💡 Cross-language testing will be available once all implementations are working.');
  }

  testBasicFunctionality() {
    console.log('🔧 Testing basic functionality...\n');
    
    try {
      // Test 1: Simple encryption/decryption
      console.log('Test 1: Basic encrypt/decrypt');
      const data = 'Hello World!';
      const password = 'test-password';
      
      const encrypted = this.crypto.encrypt(data, password);
      console.log(`  Encrypted: ${encrypted.substring(0, 50)}...`);
      
      const decrypted = this.crypto.decrypt(encrypted, password);
      console.log(`  Decrypted: ${decrypted}`);
      
      if (data === decrypted) {
        console.log('  ✅ Basic test passed!\n');
      } else {
        console.log('  ❌ Basic test failed!\n');
        return false;
      }
      
      // Test 2: Key generation
      console.log('Test 2: Key generation');
      const key1 = this.crypto.generateKey();
      const key2 = this.crypto.generateKey();
      
      console.log(`  Key 1: ${key1.substring(0, 20)}...`);
      console.log(`  Key 2: ${key2.substring(0, 20)}...`);
      
      if (key1 !== key2) {
        console.log('  ✅ Key generation test passed!\n');
      } else {
        console.log('  ❌ Keys should be different!\n');
        return false;
      }
      
      // Test 3: Version info
      console.log('Test 3: Version info');
      const version = this.crypto.version();
      console.log(`  Version: ${version.version}`);
      console.log(`  Algorithm: ${version.algorithm}`);
      console.log('  ✅ Version info test passed!\n');
      
      return true;
      
    } catch (error) {
      console.log(`  ❌ Basic functionality test failed: ${error.message}\n`);
      return false;
    }
  }

  generateReport(results, outputPath = '../test-vectors/validation-report-js.json') {
    const report = {
      timestamp: new Date().toISOString(),
      implementation: 'javascript',
      test_vectors_version: this.testVectors?.metadata?.version || 'unknown',
      summary: {
        total_tests: results.total,
        passed: results.passed,
        failed: results.failed,
        success_rate: ((results.passed / results.total) * 100).toFixed(1) + '%'
      },
      details: results.details,
      environment: {
        node_version: process.version,
        platform: process.platform
      }
    };

    try {
      const fullPath = path.resolve(__dirname, outputPath);
      const dir = path.dirname(fullPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(fullPath, JSON.stringify(report, null, 2));
      console.log(`\n📊 Validation report saved to: ${fullPath}`);
    } catch (error) {
      console.log(`⚠️  Could not save report: ${error.message}`);
    }

    return report;
  }
}

module.exports = TestVectorValidator;

// Example usage if run directly
if (require.main === module) {
  console.log('Test Vector Validator for JavaScript');
  console.log('Usage: const validator = new TestVectorValidator(yourCryptoImplementation);');
  console.log('       validator.loadTestVectors();');
  console.log('       const results = validator.validateAllVectors();');
}