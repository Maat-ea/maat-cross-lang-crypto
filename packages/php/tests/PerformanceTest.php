<?php

require_once __DIR__ . '/../src/MaatCrossLangCrypto.php';

use MAAT\Crypto\MaatCrossLangCrypto;

class PerformanceTest
{
    public static function runPerformanceTests()
    {
        echo "⚡ Running PHP performance tests...\n\n";
        
        $password = 'performance-test-password';
        $testSizes = [
            ['name' => 'Small (100 bytes)', 'data' => str_repeat('x', 100)],
            ['name' => 'Medium (1KB)', 'data' => str_repeat('x', 1024)],
            ['name' => 'Large (10KB)', 'data' => str_repeat('x', 10240)]
        ];
        
        foreach ($testSizes as $test) {
            $iterations = strlen($test['data']) > 5000 ? 10 : 100;
            
            echo "Testing {$test['name']}:\n";
            
            // Encryption performance
            $encStart = microtime(true);
            $encrypted = '';
            for ($i = 0; $i < $iterations; $i++) {
                $encrypted = MaatCrossLangCrypto::encrypt($test['data'], $password);
            }
            $encTime = (microtime(true) - $encStart) * 1000 / $iterations;
            
            // Decryption performance
            $decStart = microtime(true);
            for ($i = 0; $i < $iterations; $i++) {
                MaatCrossLangCrypto::decrypt($encrypted, $password);
            }
            $decTime = (microtime(true) - $decStart) * 1000 / $iterations;
            
            printf("  Encryption: %.2fms avg\n", $encTime);
            printf("  Decryption: %.2fms avg\n", $decTime);
            printf("  Total: %.2fms avg\n\n", $encTime + $decTime);
        }
    }
}

// Run if executed directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    PerformanceTest::runPerformanceTests();
}