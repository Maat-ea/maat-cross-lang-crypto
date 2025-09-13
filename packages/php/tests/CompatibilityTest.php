<?php

require_once __DIR__ . '/../src/MaatCrossLangCrypto.php';

use MAAT\Crypto\MaatCrossLangCrypto;

class CompatibilityTest
{
    public static function runCompatibilityTests()
    {
        echo "🌐 Running PHP compatibility tests...\n\n";
        
        try {
            self::testDataStructureConsistency();
            self::testKnownTestVectors();
            self::testLaravelIntegration();
            
            echo "✅ All compatibility tests passed!\n";
        } catch (Exception $e) {
            echo "❌ Compatibility test failed: " . $e->getMessage() . "\n";
            throw $e;
        }
    }

    public static function testDataStructureConsistency()
    {
        echo "📝 Testing data structure consistency...\n";
        
        $password = 'structure-test';
        $data = 'Test data for structure validation';
        
        $encrypted = MaatCrossLangCrypto::encrypt($data, $password);
        $structure = self::parseEncryptedData($encrypted);
        
        // Validate required fields
        $requiredFields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
        foreach ($requiredFields as $field) {
            if (!isset($structure[$field]) || empty($structure[$field])) {
                throw new Exception("Missing required field: {$field}");
            }
        }
        
        // Validate field values
        if ($structure['v'] !== '1.0.0') {
            throw new Exception('Wrong version');
        }
        if ($structure['alg'] !== 'AES-256-GCM') {
            throw new Exception('Wrong algorithm');
        }
        if ($structure['kdf'] !== 'PBKDF2-SHA256') {
            throw new Exception('Wrong KDF');
        }
        
        echo "  ✅ Data structure is consistent\n\n";
    }

    public static function testKnownTestVectors()
    {
        echo "📝 Testing with known test vectors...\n";
        
        $testVectors = [
            [
                'password' => 'test123',
                'data' => 'Hello World',
                'options' => ['iterations' => 10000]
            ],
            [
                'password' => 'secure-key-456',
                'data' => '{"test": "json", "value": 42}',
                'options' => ['iterations' => 25000]
            ]
        ];
        
        foreach ($testVectors as $index => $vector) {
            $encrypted = MaatCrossLangCrypto::encrypt(
                $vector['data'],
                $vector['password'],
                $vector['options']
            );
            $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $vector['password']);
            
            if ($decrypted !== $vector['data']) {
                throw new Exception("Test vector {$index} failed");
            }
        }
        
        echo "  ✅ Test vectors work correctly\n\n";
    }

    public static function testLaravelIntegration()
    {
        echo "📝 Testing Laravel-style usage...\n";
        
        // Simulate Laravel config
        $config = [
            'crypto_key' => 'laravel-test-key-12345',
            'options' => ['iterations' => 75000]
        ];
        
        $userData = json_encode([
            'user_id' => 12345,
            'email' => 'user@example.com',
            'permissions' => ['read', 'write']
        ]);
        
        // Encrypt like Laravel would
        $encrypted = MaatCrossLangCrypto::encrypt($userData, $config['crypto_key'], $config['options']);
        
        // Decrypt like Laravel would
        $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $config['crypto_key']);
        $parsedUser = json_decode($decrypted, true);
        
        if ($parsedUser['user_id'] !== 12345) {
            throw new Exception('Laravel integration test failed');
        }
        
        echo "  ✅ Laravel-style integration works\n\n";
    }

    private static function parseEncryptedData(string $encrypted): array
    {
        $jsonStr = base64_decode($encrypted);
        return json_decode($jsonStr, true);
    }
}

// Run if executed directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    CompatibilityTest::runCompatibilityTests();
}