<?php

require_once __DIR__ . '/CrossLangCryptoTest.php';
require_once __DIR__ . '/PerformanceTest.php';
require_once __DIR__ . '/CompatibilityTest.php';

echo "🚀 Starting Complete PHP Test Suite\n";
echo str_repeat('=', 50) . "\n";

try {
    // Run basic functionality tests
    echo "PHASE 1: Basic Functionality Tests\n";
    echo str_repeat('-', 30) . "\n";
    CrossLangCryptoTest::runAllTests();
    
    echo "\nPHASE 2: Compatibility Tests\n";
    echo str_repeat('-', 30) . "\n";
    CompatibilityTest::runCompatibilityTests();
    
    echo "\nPHASE 3: Performance Tests\n";
    echo str_repeat('-', 30) . "\n";
    PerformanceTest::runPerformanceTests();
    
    echo "\n" . str_repeat('=', 50) . "\n";
    echo "🎉 ALL PHP TESTS COMPLETED SUCCESSFULLY!\n";
    echo "✅ Your PHP implementation is ready for production\n";
    
} catch (Exception $e) {
    echo "\n" . str_repeat('=', 50) . "\n";
    echo "❌ PHP TEST SUITE FAILED: " . $e->getMessage() . "\n";
    exit(1);
}