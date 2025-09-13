/**
 * Performance Test Suite
 */

const MaatCrossLangCrypto = require('../src/index.js');

class PerformanceTests {
  static runPerformanceTests() {
    console.log('⚡ Running performance tests...\n');
    
    const password = 'performance-test-password';
    const testSizes = [
      { name: 'Small (100 bytes)', data: 'x'.repeat(100) },
      { name: 'Medium (1KB)', data: 'x'.repeat(1024) },
      { name: 'Large (10KB)', data: 'x'.repeat(10240) }
    ];
    
    testSizes.forEach(test => {
      const iterations = test.data.length > 5000 ? 10 : 100;
      
      console.log(`Testing ${test.name}:`);
      
      // Encryption performance
      const encStart = Date.now();
      let encrypted;
      for (let i = 0; i < iterations; i++) {
        encrypted = MaatCrossLangCrypto.encrypt(test.data, password);
      }
      const encTime = (Date.now() - encStart) / iterations;
      
      // Decryption performance
      const decStart = Date.now();
      for (let i = 0; i < iterations; i++) {
        MaatCrossLangCrypto.decrypt(encrypted, password);
      }
      const decTime = (Date.now() - decStart) / iterations;
      
      console.log(`  Encryption: ${encTime.toFixed(2)}ms avg`);
      console.log(`  Decryption: ${decTime.toFixed(2)}ms avg`);
      console.log(`  Total: ${(encTime + decTime).toFixed(2)}ms avg\n`);
    });
  }
}

// Run if executed directly
if (require.main === module) {
  PerformanceTests.runPerformanceTests();
}

module.exports = PerformanceTests;