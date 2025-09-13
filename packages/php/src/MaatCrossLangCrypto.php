<?php

namespace MAAT\Crypto;

/**
 * Cross-Language Encryption Package - PHP Implementation
 * Compatible with JavaScript, Python, and other language implementations
 */
class MaatCrossLangCrypto
{
    const VERSION = '1.0.0';
    const ALGORITHM = 'aes-256-gcm';
    const KDF = 'pbkdf2';
    const HASH = 'sha256';
    
    const DEFAULT_OPTIONS = [
        'iterations' => 100000,
        'keyLength' => 32,    // 256 bits
        'ivLength' => 12,     // 96 bits for GCM
        'saltLength' => 16,   // 128 bits
        'tagLength' => 16     // 128 bits
    ];

    /**
     * Encrypts data with password using AES-256-GCM
     * 
     * @param string $data Data to encrypt
     * @param string $password Password for encryption
     * @param array $options Optional encryption parameters
     * @return string Base64 encoded encrypted data with metadata
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public static function encrypt(string $data, string $password, array $options = []): string
    {
        try {
            // Merge options with defaults
            $opts = array_merge(self::DEFAULT_OPTIONS, $options);
            
            // Input validation
            if (empty($data)) {
                throw new \InvalidArgumentException('Data must be a non-empty string');
            }
            if (empty($password)) {
                throw new \InvalidArgumentException('Password must be a non-empty string');
            }

            // Generate random salt and IV
            $salt = random_bytes($opts['saltLength']);
            $iv = random_bytes($opts['ivLength']);

            // Derive key using PBKDF2
            $key = hash_pbkdf2(self::HASH, $password, $salt, $opts['iterations'], $opts['keyLength'], true);

            // Encrypt data
            $encrypted = openssl_encrypt(
                $data,
                self::ALGORITHM,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            if ($encrypted === false) {
                throw new \RuntimeException('Encryption failed: ' . openssl_error_string());
            }

            // Create metadata structure
            $encryptedData = [
                'v' => self::VERSION,
                'alg' => 'AES-256-GCM',
                'kdf' => 'PBKDF2-SHA256',
                'iter' => $opts['iterations'],
                'iv' => base64_encode($iv),
                'salt' => base64_encode($salt),
                'tag' => base64_encode($tag),
                'data' => base64_encode($encrypted)
            ];

            // Return base64 encoded JSON
            return base64_encode(json_encode($encryptedData, JSON_THROW_ON_ERROR));

        } catch (\Exception $e) {
            throw new \RuntimeException('Encryption failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypts data with password
     * 
     * @param string $encryptedData Base64 encoded encrypted data
     * @param string $password Password for decryption
     * @return string Decrypted data
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public static function decrypt(string $encryptedData, string $password): string
    {
        try {
            // Input validation
            if (empty($encryptedData)) {
                throw new \InvalidArgumentException('Encrypted data must be a non-empty string');
            }
            if (empty($password)) {
                throw new \InvalidArgumentException('Password must be a non-empty string');
            }

            // Parse base64 encoded JSON
            $jsonString = base64_decode($encryptedData, true);
            if ($jsonString === false) {
                throw new \InvalidArgumentException('Invalid base64 encoded data');
            }

            $parsedData = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);
            if (!$parsedData) {
                throw new \InvalidArgumentException('Invalid encrypted data format');
            }

            // Validate structure and version
            self::validateEncryptedData($parsedData);

            // Extract components
            $iv = base64_decode($parsedData['iv'], true);
            $salt = base64_decode($parsedData['salt'], true);
            $tag = base64_decode($parsedData['tag'], true);
            $encrypted = base64_decode($parsedData['data'], true);

            if ($iv === false || $salt === false || $tag === false || $encrypted === false) {
                throw new \InvalidArgumentException('Invalid base64 data in encrypted payload');
            }

            // Derive key using same parameters
            $key = hash_pbkdf2(
                self::HASH,
                $password,
                $salt,
                $parsedData['iter'],
                32, // keyLength - fixed for AES-256
                true
            );

            // Decrypt data
            $decrypted = openssl_decrypt(
                $encrypted,
                self::ALGORITHM,
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );

            if ($decrypted === false) {
                throw new \RuntimeException('Decryption failed: ' . openssl_error_string());
            }

            return $decrypted;

        } catch (\JsonException $e) {
            throw new \RuntimeException('Decryption failed: Invalid JSON format', 0, $e);
        } catch (\Exception $e) {
            throw new \RuntimeException('Decryption failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Generates a cryptographically secure random key
     * 
     * @param int $length Key length in bytes (default: 32)
     * @return string Base64 encoded random key
     * @throws \InvalidArgumentException
     */
    public static function generateKey(int $length = 32): string
    {
        if ($length < 16 || $length > 64) {
            throw new \InvalidArgumentException('Key length must be between 16 and 64 bytes');
        }
        
        return base64_encode(random_bytes($length));
    }

    /**
     * Get version information
     * 
     * @return array Version and algorithm info
     */
    public static function version(): array
    {
        return [
            'version' => self::VERSION,
            'algorithm' => 'AES-256-GCM',
            'kdf' => 'PBKDF2-SHA256',
            'library' => 'cross-lang-crypto-php'
        ];
    }

    /**
     * Validates encrypted data structure
     * 
     * @param array $data Parsed encrypted data
     * @throws \InvalidArgumentException
     */
    private static function validateEncryptedData(array $data): void
    {
        $requiredFields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
        
        foreach ($requiredFields as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new \InvalidArgumentException("Missing required field: {$field}");
            }
        }

        if ($data['alg'] !== 'AES-256-GCM') {
            throw new \InvalidArgumentException("Unsupported algorithm: {$data['alg']}");
        }

        if ($data['kdf'] !== 'PBKDF2-SHA256') {
            throw new \InvalidArgumentException("Unsupported KDF: {$data['kdf']}");
        }

        if (!is_int($data['iter']) || $data['iter'] < 10000) {
            throw new \InvalidArgumentException('Invalid iteration count');
        }
    }
}

// Laravel Service Provider (Optional)
if (class_exists('Illuminate\Support\ServiceProvider')) {
    class CrossLangCryptoServiceProvider extends \Illuminate\Support\ServiceProvider
    {
        public function register()
        {
            $this->app->singleton('cross-lang-crypto', function () {
                return new CrossLangCrypto();
            });
        }

        public function provides()
        {
            return ['cross-lang-crypto'];
        }
    }
}

// Laravel Facade (Optional)
if (class_exists('Illuminate\Support\Facades\Facade')) {
    class CrossLangCryptoFacade extends \Illuminate\Support\Facades\Facade
    {
        protected static function getFacadeAccessor()
        {
            return 'cross-lang-crypto';
        }
    }
}

/*
Example usage:

// Basic usage
$password = 'my-secret-password';
$data = 'Hello, cross-language world!';

// Encrypt
$encrypted = CrossLangCrypto::encrypt($data, $password);
echo "Encrypted: " . $encrypted . "\n";

// Decrypt
$decrypted = CrossLangCrypto::decrypt($encrypted, $password);
echo "Decrypted: " . $decrypted . "\n";

// Generate key
$key = CrossLangCrypto::generateKey();
echo "Random key: " . $key . "\n";

// Custom options
$options = ['iterations' => 50000];
$encrypted = CrossLangCrypto::encrypt($data, $password, $options);

// Laravel usage (if using facade)
use YourCompany\Crypto\CrossLangCryptoFacade as Crypto;

$encrypted = Crypto::encrypt($data, config('app.crypto_key'));
$decrypted = Crypto::decrypt($encrypted, config('app.crypto_key'));
*/