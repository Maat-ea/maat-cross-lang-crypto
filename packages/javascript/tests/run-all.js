/**
 * Run All Tests - Main Test Runner
 */

const BasicCryptoTests = require('./test.js');
const PerformanceTests = require('./performance.js');
const CompatibilityTests = require('./compatibility.js');

async function runAllTests() {
  console.log('🚀 Starting Complete JavaScript Test Suite\n');
  console.log('=' .repeat(50));
  
  try {
    // Run basic functionality tests
    console.log('PHASE 1: Basic Functionality Tests');
    console.log('-'.repeat(30));
    BasicCryptoTests.runAllTests();
    
    console.log('\nPHASE 2: Compatibility Tests');
    console.log('-'.repeat(30));
    CompatibilityTests.runCompatibilityTests();
    
    console.log('\nPHASE 3: Performance Tests');
    console.log('-'.repeat(30));
    PerformanceTests.runPerformanceTests();
    
    console.log('\n' + '='.repeat(50));
    console.log('🎉 ALL TESTS COMPLETED SUCCESSFULLY!');
    console.log('✅ Your JavaScript implementation is ready for production');
    
  } catch (error) {
    console.log('\n' + '='.repeat(50));
    console.error('❌ TEST SUITE FAILED:', error.message);
    process.exit(1);
  }
}

// Run all tests
runAllTests();