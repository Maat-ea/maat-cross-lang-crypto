#!/usr/bin/env node

const TestVectorValidator = require('./test-vector-validator');
const MaatCrossLangCrypto = require('../packages/javascript/src/index.js');

async function main() {
  console.log('🚀 JavaScript Implementation Validation\n');
  
  try {
    // Create validator with our crypto implementation
    const validator = new TestVectorValidator(MaatCrossLangCrypto);
    
    // Load test vectors
    console.log('📁 Loading test vectors...');
    validator.loadTestVectors();
    
    // Run validation
    const results = validator.validateAllVectors();
    
    // Generate report
    const report = validator.generateReport(results);
    
    // Run compatibility tests
    validator.runCompatibilityTests();
    
    if (results.failed === 0) {
      console.log('\n🎉 All tests passed! JavaScript implementation is valid.');
      process.exit(0);
    } else {
      console.log('\n❌ Some tests failed. Check the validation report.');
      process.exit(1);
    }
    
  } catch (error) {
    console.error('❌ Validation failed:', error.message);
    process.exit(1);
  }
}

main();