<?php
#!/usr/bin/env php

require_once __DIR__ . '/../packages/php/src/MaatCrossLangCrypto.php';

use MAAT\Crypto\MaatCrossLangCrypto;

class PHPTestVectorValidator {
    private $testVectors;
    
    public function loadTestVectors($filePath = '../test-vectors/test-vectors.json') {
        $fullPath = realpath(__DIR__ . '/' . $filePath);
        
        if (!file_exists($fullPath)) {
            throw new Exception("Test vectors file not found: {$fullPath}");
        }
        
        $data = file_get_contents($fullPath);
        $this->testVectors = json_decode($data, true);
        
        if (!$this->testVectors) {
            throw new Exception('Failed to parse test vectors JSON');
        }
        
        return $this->testVectors;
    }
    
    public function validateAllVectors() {
        echo "🧪 PHP Implementation Validation\n\n";
        
        $results = [
            'passed' => 0,
            'failed' => 0,
            'total' => count($this->testVectors['vectors']),
            'details' => []
        ];
        
        foreach ($this->testVectors['vectors'] as $index => $vector) {
            echo "Testing vector " . ($index + 1) . ": {$vector['description']}\n";
            
            try {
                $result = $this->validateSingleVector($vector);
                
                if ($result['success']) {
                    echo "  ✅ Passed\n";
                    $results['passed']++;
                } else {
                    echo "  ❌ Failed: {$result['error']}\n";
                    $results['failed']++;
                }
                
                $results['details'][] = [
                    'id' => $vector['id'],
                    'success' => $result['success'],
                    'error' => $result['error'] ?? null
                ];
                
            } catch (Exception $e) {
                echo "  ❌ Error: {$e->getMessage()}\n";
                $results['failed']++;
                $results['details'][] = [
                    'id' => $vector['id'],
                    'success' => false,
                    'error' => $e->getMessage()
                ];
            }
        }
        
        echo "\n📊 Validation Summary:\n";
        echo "  Passed: {$results['passed']}/{$results['total']}\n";
        echo "  Failed: {$results['failed']}/{$results['total']}\n";
        $successRate = round(($results['passed'] / $results['total']) * 100, 1);
        echo "  Success rate: {$successRate}%\n";
        
        return $results;
    }
    
    private function validateSingleVector($vector) {
        $input = $vector['input'];
        
        try {
            // Since we don't have pre-generated encrypted data, we'll test our own implementation
            echo "    → Testing self-encryption and decryption...\n";
            
            // Test 1: Encrypt the input data
            $encrypted = MaatCrossLangCrypto::encrypt($input['data'], $input['password'], $input['options']);
            
            if (empty($encrypted)) {
                return [
                    'success' => false,
                    'error' => 'Encryption returned empty result'
                ];
            }
            
            echo "    → Encrypted data length: " . strlen($encrypted) . " characters\n";
            
            // Test 2: Decrypt our own encrypted data
            echo "    → Testing decryption of our encrypted data...\n";
            $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $input['password']);
            
            if ($decrypted !== $input['data']) {
                return [
                    'success' => false,
                    'error' => "Decryption mismatch. Expected: \"{$input['data']}\", Got: \"{$decrypted}\""
                ];
            }
            
            echo "    → Decrypted data matches original ✓\n";
            
            // Test 3: Validate structure format
            echo "    → Validating encrypted data structure...\n";
            $structure = $this->parseEncryptedData($encrypted);
            $structureValidation = $this->validateStructure($structure, $input['options']);
            
            if (!$structureValidation['valid']) {
                return [
                    'success' => false,
                    'error' => "Structure validation failed: {$structureValidation['error']}"
                ];
            }
            
            echo "    → Structure format is valid ✓\n";
            
            // Test 4: Test with wrong password (should fail)
            echo "    → Testing wrong password (should fail)...\n";
            try {
                MaatCrossLangCrypto::decrypt($encrypted, 'wrong-password');
                return [
                    'success' => false,
                    'error' => 'Wrong password should have failed but succeeded'
                ];
            } catch (Exception $e) {
                echo "    → Wrong password correctly rejected ✓\n";
            }
            
            return [
                'success' => true,
                'details' => [
                    'encrypted_length' => strlen($encrypted),
                    'original_length' => strlen($input['data']),
                    'structure_valid' => true,
                    'wrong_password_rejected' => true
                ]
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }
    
    private function parseEncryptedData($encrypted) {
        try {
            $jsonStr = base64_decode($encrypted);
            if ($jsonStr === false) {
                throw new Exception('Invalid base64 encoding');
            }
            
            $structure = json_decode($jsonStr, true);
            if ($structure === null) {
                throw new Exception('Invalid JSON structure');
            }
            
            return $structure;
        } catch (Exception $e) {
            throw new Exception("Failed to parse encrypted data: " . $e->getMessage());
        }
    }
    
    private function validateStructure($structure, $expectedOptions) {
        // Check required fields
        $required = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
        
        foreach ($required as $field) {
            if (!isset($structure[$field]) || empty($structure[$field])) {
                return ['valid' => false, 'error' => "Missing required field: {$field}"];
            }
        }
        
        // Check field values
        if ($structure['v'] !== '1.0.0') {
            return ['valid' => false, 'error' => "Wrong version: {$structure['v']}"];
        }
        if ($structure['alg'] !== 'AES-256-GCM') {
            return ['valid' => false, 'error' => "Wrong algorithm: {$structure['alg']}"];
        }
        if ($structure['kdf'] !== 'PBKDF2-SHA256') {
            return ['valid' => false, 'error' => "Wrong KDF: {$structure['kdf']}"];
        }
        if ($structure['iter'] !== $expectedOptions['iterations']) {
            return ['valid' => false, 'error' => "Wrong iterations: {$structure['iter']} vs {$expectedOptions['iterations']}"];
        }
        
        // Check base64 field lengths
        try {
            $iv = base64_decode($structure['iv']);
            $salt = base64_decode($structure['salt']);
            $tag = base64_decode($structure['tag']);
            
            if ($iv === false || strlen($iv) !== 12) {
                return ['valid' => false, 'error' => "Invalid IV length: " . strlen($iv ?: '') . " bytes (should be 12)"];
            }
            if ($salt === false || strlen($salt) !== 16) {
                return ['valid' => false, 'error' => "Invalid salt length: " . strlen($salt ?: '') . " bytes (should be 16)"];
            }
            if ($tag === false || strlen($tag) !== 16) {
                return ['valid' => false, 'error' => "Invalid tag length: " . strlen($tag ?: '') . " bytes (should be 16)"];
            }
            
        } catch (Exception $e) {
            return ['valid' => false, 'error' => "Base64 decode error: " . $e->getMessage()];
        }
        
        return ['valid' => true];
    }
    
    public function testBasicFunctionality() {
        echo "🔧 Testing basic functionality...\n\n";
        
        try {
            // Test 1: Simple encryption/decryption
            echo "Test 1: Basic encrypt/decrypt\n";
            $data = "Hello World!";
            $password = "test-password";
            
            $encrypted = MaatCrossLangCrypto::encrypt($data, $password);
            echo "  Encrypted: " . substr($encrypted, 0, 50) . "...\n";
            
            $decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
            echo "  Decrypted: {$decrypted}\n";
            
            if ($data === $decrypted) {
                echo "  ✅ Basic test passed!\n\n";
            } else {
                echo "  ❌ Basic test failed!\n\n";
                return false;
            }
            
            // Test 2: Key generation
            echo "Test 2: Key generation\n";
            $key1 = MaatCrossLangCrypto::generateKey();
            $key2 = MaatCrossLangCrypto::generateKey();
            
            echo "  Key 1: " . substr($key1, 0, 20) . "...\n";
            echo "  Key 2: " . substr($key2, 0, 20) . "...\n";
            
            if ($key1 !== $key2) {
                echo "  ✅ Key generation test passed!\n\n";
            } else {
                echo "  ❌ Keys should be different!\n\n";
                return false;
            }
            
            // Test 3: Version info
            echo "Test 3: Version info\n";
            $version = MaatCrossLangCrypto::version();
            echo "  Version: {$version['version']}\n";
            echo "  Algorithm: {$version['algorithm']}\n";
            echo "  ✅ Version info test passed!\n\n";
            
            return true;
            
        } catch (Exception $e) {
            echo "  ❌ Basic functionality test failed: " . $e->getMessage() . "\n\n";
            return false;
        }
    }
}

// Main execution
try {
    echo "🚀 Starting MAAT Cross-Language Crypto PHP Validation\n";
    echo str_repeat('=', 60) . "\n\n";
    
    $validator = new PHPTestVectorValidator();
    
    // First, test basic functionality
    if (!$validator->testBasicFunctionality()) {
        echo "❌ Basic functionality tests failed. Stopping.\n";
        exit(1);
    }
    
    // Then load and validate against test vectors
    echo "📁 Loading test vectors...\n";
    $validator->loadTestVectors();
    echo "✅ Test vectors loaded successfully\n\n";
    
    // Run validation against test vectors
    $results = $validator->validateAllVectors();
    
    echo "\n" . str_repeat('=', 60) . "\n";
    
    if ($results['failed'] === 0) {
        echo "🎉 All tests passed! PHP implementation is working correctly.\n";
        echo "✅ Your implementation can handle all test vector scenarios.\n";
        exit(0);
    } else {
        echo "⚠️  Some tests had issues. Details above.\n";
        echo "💡 This is normal during development - fix issues one by one.\n";
        exit(1);
    }
    
} catch (Exception $e) {
    echo "❌ Validation failed: {$e->getMessage()}\n";
    
    // Check if it's a file not found error
    if (strpos($e->getMessage(), 'not found') !== false) {
        echo "\n💡 Make sure you have:\n";
        echo "1. Created test-vectors/test-vectors.json file\n";
        echo "2. Run this script from the project root directory\n";
        echo "3. Your PHP implementation exists at packages/php/src/MaatCrossLangCrypto.php\n";
    }
    
    exit(1);
}

?>