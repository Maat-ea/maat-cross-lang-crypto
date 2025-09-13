<?php

require_once __DIR__ . '/../src/MaatCrossLangCrypto.php';

use MAAT\Crypto\MaatCrossLangCrypto;

class MaatCrossLangCryptoTest
{
    public static function runAllTests()
    {
        echo "🧪 Running PHP Crypto Tests...\n\n";
        
        try {
            self::testBasicEncryptDecrypt();
            self::testDifferentDataTypes();
            self::testCustomOptions();
            self::testErrorHandling();
            self::testKeyGeneration();
            self::testVersionInfo();
            
            echo "✅ All PHP tests passed!\n";
        } catch (Exception $e) {
            echo "❌ Test failed: " . $e->getMessage() . "\n";
            exit(1);
        }
    }

    public static function testBasicEncryptDecrypt()
    {
        echo "📝 Testing basic encrypt/decrypt...\n";
        
        $password = 'test-password-123';
        $originalData = 'Hello, World!';
        
        $encrypted = MaatCrossLangCrypto::encrypt($originalData, $password);
        $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
        
        if ($decrypted !== $originalData) {
            throw new Exception("Decryption failed. Expected: '{$originalData}', Got: '{$decrypted}'");
        }
        
        echo "  ✅ Basic encryption/decryption works\n\n";
    }

    public static function testDifferentDataTypes()
    {
        echo "📝 Testing different data types...\n";
        
        $password = 'test-password-456';
        $testCases = [
            'Simple string',
            '{"json": "data", "number": 42}',
            'Special chars: äöü ñ 中文 🚀',
            "Multi\nline\ntext\nwith\nbreaks",
            '   whitespace   test   ',
            '1234567890'
        ];
        
        foreach ($testCases as $index => $data) {
            $encrypted = MaatCrossLangCrypto::encrypt($data, $password);
            $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
            
            if ($decrypted !== $data) {
                throw new Exception("Test case {$index} failed");
            }
        }
        
        echo "  ✅ Different data types work\n\n";
    }

    public static function testCustomOptions()
    {
        echo "📝 Testing custom options...\n";
        
        $password = 'test-password-789';
        $data = 'Custom options test';
        
        $customOptions = [
            'iterations' => 50000,
            'keyLength' => 32,
            'ivLength' => 12,
            'saltLength' => 16
        ];
        
        $encrypted = MaatCrossLangCrypto::encrypt($data, $password, $customOptions);
        $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
        
        if ($decrypted !== $data) {
            throw new Exception('Custom options test failed');
        }
        
        // Verify the options were used
        $jsonString = base64_decode($encrypted);
        $parsedData = json_decode($jsonString, true);
        if ($parsedData['iter'] !== $customOptions['iterations']) {
            throw new Exception('Custom iterations not used');
        }
        
        echo "  ✅ Custom options work\n\n";
    }

    public static function testErrorHandling()
    {
        echo "📝 Testing error handling...\n";
        
        // Test empty inputs
        self::expectError(function() {
            MaatCrossLangCrypto::encrypt('', 'password');
        }, 'empty data');
        
        self::expectError(function() {
            MaatCrossLangCrypto::encrypt('data', '');
        }, 'empty password');
        
        self::expectError(function() {
            MaatCrossLangCrypto::decrypt('', 'password');
        }, 'empty encrypted');
        
        self::expectError(function() {
            MaatCrossLangCrypto::decrypt('invalid', 'password');
        }, 'invalid data');
        
        // Test wrong password
        $encrypted = MaatCrossLangCrypto::encrypt('test', 'password1');
        self::expectError(function() use ($encrypted) {
            MaatCrossLangCrypto::decrypt($encrypted, 'password2');
        }, 'wrong password');
        
        echo "  ✅ Error handling works\n\n";
    }

    public static function testKeyGeneration()
    {
        echo "📝 Testing key generation...\n";
        
        $key1 = MaatCrossLangCrypto::generateKey();
        $key2 = MaatCrossLangCrypto::generateKey();
        
        if ($key1 === $key2) {
            throw new Exception('Generated keys should be different');
        }
        
        // Test custom key lengths
        $shortKey = MaatCrossLangCrypto::generateKey(16);
        $longKey = MaatCrossLangCrypto::generateKey(64);
        
        if (strlen(base64_decode($shortKey)) !== 16) {
            throw new Exception('Short key wrong length');
        }
        
        if (strlen(base64_decode($longKey)) !== 64) {
            throw new Exception('Long key wrong length');
        }
        
        echo "  ✅ Key generation works\n\n";
    }

    public static function testVersionInfo()
    {
        echo "📝 Testing version info...\n";
        
        $version = MaatCrossLangCrypto::version();
        
        if (!isset($version['version']) || !$version['version']) {
            throw new Exception('Missing version info');
        }
        
        if (!isset($version['algorithm']) || $version['algorithm'] !== 'AES-256-GCM') {
            throw new Exception('Wrong algorithm info');
        }
        
        echo "  ✅ Version info works\n\n";
    }

    private static function expectError(callable $fn, string $description)
    {
        try {
            $fn();
            throw new Exception("Expected error for: {$description}");
        } catch (Exception $e) {
            if (strpos($e->getMessage(), 'Expected error') === 0) {
                throw $e;
            }
            // Error was thrown as expected
        }
    }
}

// Run tests if this file is executed directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    MaatCrossLangCryptoTest::runAllTests();
}