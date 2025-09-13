## Production Examples

### Environment Configuration

Secure configuration management across environments:

<details>
<summary>JavaScript (Production Setup)</summary>

```javascript
// config/crypto.js
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

class ProductionCrypto {
    constructor() {
        this.validateEnvironment();
        this.initializeKeys();
        this.setupOptions();
    }
    
    validateEnvironment() {
        const required = [
            'CRYPTO_MASTER_KEY',
            'CRYPTO_DB_KEY',
            'CRYPTO_API_KEY',
            'NODE_ENV'
        ];
        
        for (const env of required) {
            if (!process.env[env]) {
                throw new Error(`Missing required environment variable: ${env}`);
            }
        }
    }
    
    initializeKeys() {
        this.keys = {
            master: process.env.CRYPTO_MASTER_KEY,
            database: process.env.CRYPTO_DB_KEY,
            api: process.env.CRYPTO_API_KEY,
            session: process.env.CRYPTO_SESSION_KEY || this.generateSessionKey()
        };
    }
    
    setupOptions() {
        const isProduction = process.env.NODE_ENV === 'production';
        
        this.options = {
            production: {
                iterations: 200000,  // High security for production
                keyLength: 32,
                ivLength: 12,
                saltLength: 16,
                tagLength: 16
            },
            staging: {
                iterations: 100000,  // Balanced for testing
                keyLength: 32,
                ivLength: 12,
                saltLength: 16,
                tagLength: 16
            },
            development: {
                iterations: 50000,   // Faster for development
                keyLength: 32,
                ivLength: 12,
                saltLength: 16,
                tagLength: 16
            }
        };
        
        this.currentOptions = this.options[process.env.NODE_ENV] || this.options.development;
    }
    
    generateSessionKey() {
        // Generate a session key if not provided
        return MaatCrossLangCrypto.generateKey(32);
    }
    
    // Database encryption
    encryptForDatabase(data) {
        return MaatCrossLangCrypto.encrypt(
            JSON.stringify(data),
            this.keys.database,
            this.currentOptions
        );
    }
    
    decryptFromDatabase(encryptedData) {
        const decrypted = MaatCrossLangCrypto.decrypt(encryptedData, this.keys.database);
        return JSON.parse(decrypted);
    }
    
    // API encryption
    encryptForAPI(data) {
        return MaatCrossLangCrypto.encrypt(
            JSON.stringify(data),
            this.keys.api,
            this.currentOptions
        );
    }
    
    decryptFromAPI(encryptedData) {
        const decrypted = MaatCrossLangCrypto.decrypt(encryptedData, this.keys.api);
        return JSON.parse(decrypted);
    }
    
    // Session encryption
    encryptSession(sessionData) {
        return MaatCrossLangCrypto.encrypt(
            JSON.stringify(sessionData),
            this.keys.session,
            this.currentOptions
        );
    }
    
    decryptSession(encryptedSession) {
        const decrypted = MaatCrossLangCrypto.decrypt(encryptedSession, this.keys.session);
        return JSON.parse(decrypted);
    }
    
    // Health check for crypto operations
    healthCheck() {
        try {
            const testData = { test: 'crypto-health-check', timestamp: Date.now() };
            
            // Test all encryption types
            const dbEncrypted = this.encryptForDatabase(testData);
            const dbDecrypted = this.decryptFromDatabase(dbEncrypted);
            
            const apiEncrypted = this.encryptForAPI(testData);
            const apiDecrypted = this.decryptFromAPI(apiEncrypted);
            
            const sessionEncrypted = this.encryptSession(testData);
            const sessionDecrypted = this.decryptSession(sessionEncrypted);
            
            // Verify integrity
            const checks = [
                JSON.stringify(testData) === JSON.stringify(dbDecrypted),
                JSON.stringify(testData) === JSON.stringify(apiDecrypted),
                JSON.stringify(testData) === JSON.stringify(sessionDecrypted)
            ];
            
            return {
                status: checks.every(check => check) ? 'healthy' : 'error',
                checks: {
                    database: checks[0],
                    api: checks[1],
                    session: checks[2]
                },
                environment: process.env.NODE_ENV,
                options: this.currentOptions,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return {
                status: 'error',
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }
}

// Export singleton instance
module.exports = new ProductionCrypto();

// Example usage in Express app
const express = require('express');
const crypto = require('./config/crypto');

const app = express();

// Health check endpoint
app.get('/health/crypto', (req, res) => {
    const health = crypto.healthCheck();
    const statusCode = health.status === 'healthy' ? 200 : 500;
    res.status(statusCode).json(health);
});

// Protected route with encryption
app.post('/api/secure-data', express.json(), async (req, res) => {
    try {
        const { data } = req.body;
        
        // Encrypt for database storage
        const encryptedForDB = crypto.encryptForDatabase(data);
        
        // Simulate database save
        console.log('Saving encrypted data to database...');
        
        // Encrypt for API response
        const encryptedResponse = crypto.encryptForAPI({
            success: true,
            message: 'Data processed successfully',
            timestamp: new Date().toISOString()
        });
        
        res.json({ encrypted: encryptedResponse });
        
    } catch (error) {
        res.status(500).json({ error: 'Processing failed' });
    }
});

app.listen(3000, () => {
    console.log('Production crypto server running on port 3000');
    console.log('Environment:', process.env.NODE_ENV);
    
    // Perform startup health check
    const health = crypto.healthCheck();
    console.log('Crypto health check:', health.status);
});
```
</details>

### Error Handling and Monitoring

Comprehensive error handling for production:

<details>
<summary>Python (Production Error Handling)</summary>

```python
import logging
import traceback
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum
from maat_cross_lang_crypto import MaatCrossLangCrypto

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CryptoErrorType(Enum):
    ENCRYPTION_FAILED = "encryption_failed"
    DECRYPTION_FAILED = "decryption_failed"
    INVALID_PASSWORD = "invalid_password"
    INVALID_DATA = "invalid_data"
    CONFIG_ERROR = "config_error"
    KEY_ERROR = "key_error"

@dataclass
class CryptoError:
    error_type: CryptoErrorType
    message: str
    timestamp: datetime
    context: Dict[str, Any]
    traceback_info: Optional[str] = None

class ProductionCryptoManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.error_history = []
        self.metrics = {
            'encryptions': 0,
            'decryptions': 0,
            'errors': 0,
            'success_rate': 0.0
        }
        
        self._validate_config()
        self._setup_monitoring()
    
    def _validate_config(self):
        """Validate configuration and keys"""
        required_keys = ['database_key', 'api_key', 'session_key']
        missing_keys = [key for key in required_keys if not self.config.get(key)]
        
        if missing_keys:
            error = CryptoError(
                error_type=CryptoErrorType.CONFIG_ERROR,
                message=f"Missing required keys: {missing_keys}",
                timestamp=datetime.now(timezone.utc),
                context={'missing_keys': missing_keys}
            )
            self._log_error(error)
            raise ValueError(f"Configuration error: {error.message}")
    
    def _setup_monitoring(self):
        """Setup monitoring and health checks"""
        logger.info("Crypto manager initialized successfully")
        logger.info(f"Environment: {self.config.get('environment', 'unknown')}")
    
    def _log_error(self, error: CryptoError):
        """Log crypto errors with context"""
        self.error_history.append(error)
        self.metrics['errors'] += 1
        
        logger.error(
            f"Crypto Error [{error.error_type.value}]: {error.message}",
            extra={
                'error_type': error.error_type.value,
                'context': error.context,
                'timestamp': error.timestamp.isoformat()
            }
        )
        
        if error.traceback_info:
            logger.error(f"Traceback: {error.traceback_info}")
    
    def _update_metrics(self, operation: str, success: bool):
        """Update performance metrics"""
        if operation in ['encrypt', 'decrypt']:
            self.metrics[f'{operation}ions'] += 1
        
        total_ops = self.metrics['encryptions'] + self.metrics['decryptions']
        if total_ops > 0:
            success_ops = total_ops - self.metrics['errors']
            self.metrics['success_rate'] = (success_ops / total_ops) * 100
    
    def safe_encrypt(self, data: Any, key_type: str = 'database', 
                    options: Optional[Dict] = None) -> Optional[str]:
        """Safely encrypt data with comprehensive error handling"""
        try:
            # Input validation
            if not data:
                raise ValueError("Data cannot be empty")
            
            if key_type not in self.config:
                raise ValueError(f"Unknown key type: {key_type}")
            
            # Convert data to string if needed
            if isinstance(data, (dict, list)):
                data_str = json.dumps(data, default=str)
            else:
                data_str = str(data)
            
            # Get encryption key
            encryption_key = self.config[f'{key_type}_key']
            
            # Perform encryption
            encrypted = MaatCrossLangCrypto.encrypt(
                data_str, 
                encryption_key, 
                options or self.config.get('options', {})
            )
            
            self._update_metrics('encrypt', True)
            
            logger.debug(
                f"Encryption successful",
                extra={
                    'key_type': key_type,
                    'data_length': len(data_str),
                    'encrypted_length': len(encrypted)
                }
            )
            
            return encrypted
            
        except ValueError as e:
            error = CryptoError(
                error_type=CryptoErrorType.INVALID_DATA,
                message=str(e),
                timestamp=datetime.now(timezone.utc),
                context={
                    'key_type': key_type,
                    'data_type': type(data).__name__,
                    'data_length': len(str(data)) if data else 0
                }
            )
            self._log_error(error)
            self._update_metrics('encrypt', False)
            return None
            
        except Exception as e:
            error = CryptoError(
                error_type=CryptoErrorType.ENCRYPTION_FAILED,
                message=str(e),
                timestamp=datetime.now(timezone.utc),
                context={
                    'key_type': key_type,
                    'data_type': type(data).__name__
                },
                traceback_info=traceback.format_exc()
            )
            self._log_error(error)
            self._update_metrics('encrypt', False)
            return None
    
    def safe_decrypt(self, encrypted_data: str, key_type: str = 'database') -> Optional[Any]:
        """Safely decrypt data with comprehensive error handling"""
        try:
            # Input validation
            if not encrypted_data or not isinstance(encrypted_data, str):
                raise ValueError("Encrypted data must be a non-empty string")
            
            if key_type not in self.config:
                raise ValueError(f"Unknown key type: {key_type}")
            
            # Get decryption key
            decryption_key = self.config[f'{key_type}_key']
            
            # Perform decryption
            decrypted = MaatCrossLangCrypto.decrypt(encrypted_data, decryption_key)
            
            # Try to parse as JSON, fallback to string
            try:
                result = json.loads(decrypted)
            except json.JSONDecodeError:
                result = decrypted
            
            self._update_metrics('decrypt', True)
            
            logger.debug(
                f"Decryption successful",
                extra={
                    'key_type': key_type,
                    'encrypted_length': len(encrypted_data),
                    'decrypted_length': len(decrypted)
                }
            )
            
            return result
            
        except ValueError as e:
            error = CryptoError(
                error_type=CryptoErrorType.INVALID_DATA,
                message=str(e),
                timestamp=datetime.now(timezone.utc),
                context={
                    'key_type': key_type,
                    'encrypted_length': len(encrypted_data) if encrypted_data else 0
                }
            )
            self._log_error(error)
            self._update_metrics('decrypt', False)
            return None
            
        except RuntimeError as e:
            # This typically indicates wrong password or corrupted data
            error = CryptoError(
                error_type=CryptoErrorType.INVALID_PASSWORD,
                message="Decryption failed - invalid password or corrupted data",
                timestamp=datetime.now(timezone.utc),
                context={
                    'key_type': key_type,
                    'original_error': str(e)
                }
            )
            self._log_error(error)
            self._update_metrics('decrypt', False)
            return None
            
        except Exception as e:
            error = CryptoError(
                error_type=CryptoErrorType.DECRYPTION_FAILED,
                message=str(e),
                timestamp=datetime.now(timezone.utc),
                context={
                    'key_type': key_type
                },
                traceback_info=traceback.format_exc()
            )
            self._log_error(error)
            self._update_metrics('decrypt', False)
            return None
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        recent_errors = [
            error for error in self.error_history[-10:]
        ]
        
        # Test all key types
        test_data = {"health_check": True, "timestamp": datetime.now(timezone.utc).isoformat()}
        key_tests = {}
        
        for key_type in ['database', 'api', 'session']:
            if f'{key_type}_key' in self.config:
                encrypted = self.safe_encrypt(test_data, key_type)
                if encrypted:
                    decrypted = self.safe_decrypt(encrypted, key_type)
                    key_tests[key_type] = decrypted is not None
                else:
                    key_tests[key_type] = False
            else:
                key_tests[key_type] = 'not_configured'
        
        return {
            'status': 'healthy' if all(test == True for test in key_tests.values()) else 'degraded',
            'metrics': self.metrics.copy(),
            'key_tests': key_tests,
            'recent_errors': len(recent_errors),
            'error_types': list(set(error.error_type.value for error in recent_errors)),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': self.config.get('environment', 'unknown')
        }
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary for monitoring"""
        if not self.error_history:
            return {'total_errors': 0, 'error_types': {}}
        
        error_types = {}
        for error in self.error_history:
            error_type = error.error_type.value
            if error_type not in error_types:
                error_types[error_type] = {
                    'count': 0,
                    'latest': None
                }
            error_types[error_type]['count'] += 1
            error_types[error_type]['latest'] = error.timestamp.isoformat()
        
        return {
            'total_errors': len(self.error_history),
            'error_types': error_types,
            'latest_error': self.error_history[-1].timestamp.isoformat() if self.error_history else None
        }

# Production usage example
if __name__ == '__main__':
    import os
    import json
    
    # Production configuration
    config = {
        'environment': os.getenv('ENVIRONMENT', 'production'),
        'database_key': os.getenv('CRYPTO_DATABASE_KEY'),
        'api_key': os.getenv('CRYPTO_API_KEY'),
        'session_key': os.getenv('CRYPTO_SESSION_KEY'),
        'options': {
            'iterations': int(os.getenv('CRYPTO_ITERATIONS', '200000'))
        }
    }
    
    # Initialize crypto manager
    crypto_manager = ProductionCryptoManager(config)
    
    # Example usage with error handling
    sensitive_data = {
        'user_id': 12345,
        'email': 'user@example.com',
        'personal_info': {
            'ssn': '123-45-6789',
            'phone': '+1-555-0123'
        }
    }
    
    print("Production Crypto Manager Example")
    print("=" * 50)
    
    # Safe encryption
    encrypted = crypto_manager.safe_encrypt(sensitive_data, 'database')
    if encrypted:
        print(f"✅ Encryption successful: {encrypted[:50]}...")
        
        # Safe decryption
        decrypted = crypto_manager.safe_decrypt(encrypted, 'database')
        if decrypted:
            print("✅ Decryption successful")
            print(f"Data integrity: {json.dumps(sensitive_data) == json.dumps(decrypted)}")
        else:
            print("❌ Decryption failed")
    else:
        print("❌ Encryption failed")
    
    # Health status
    print("\nHealth Status:")
    health = crypto_manager.get_health_status()
    print(json.dumps(health, indent=2))
    
    # Error summary
    error_summary = crypto_manager.get_error_summary()
    if error_summary['total_errors'] > 0:
        print(f"\nErrors encountered: {error_summary['total_errors']}")
        print("Error summary:")
        print(json.dumps(error_summary, indent=2))
    else:
        print("\n✅ No errors encountered")
```
</details>

### Load Testing and Performance

Performance testing for production readiness:

<details>
<summary>PHP (Performance Testing)</summary>

```php
<?php

use MAAT\Crypto\MaatCrossLangCrypto;

class CryptoPerformanceTester
{
    private $results = [];
    private $config;
    
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'iterations' => [100000, 200000],
            'data_sizes' => [100, 1024, 10240, 102400], // bytes
            'test_duration' => 30, // seconds
            'concurrent_operations' => 10
        ], $config);
    }
    
    public function runPerformanceTests(): array
    {
        echo "🚀 Starting Crypto Performance Tests\n";
        echo str_repeat('=', 60) . "\n\n";
        
        $this->testEncryptionSpeed();
        $this->testDecryptionSpeed();
        $this->testMemoryUsage();
        $this->testConcurrentOperations();
        $this->testIterationImpact();
        
        return $this->generateReport();
    }
    
    private function testEncryptionSpeed(): void
    {
        echo "📊 Testing Encryption Speed\n";
        echo str_repeat('-', 30) . "\n";
        
        $password = 'performance-test-password-2024';
        
        foreach ($this->config['data_sizes'] as $size) {
            $data = str_repeat('x', $size);
            $iterations = 100;
            
            $startTime = microtime(true);
            $startMemory = memory_get_usage(true);
            
            for ($i = 0; $i < $iterations; $i++) {
                MaatCrossLangCrypto::encrypt($data, $password);
            }
            
            $endTime = microtime(true);
            $endMemory = memory_get_usage(true);
            
            $avgTime = (($endTime - $startTime) * 1000) / $iterations;
            $memoryUsed = $endMemory - $startMemory;
            
            $this->results['encryption'][$size] = [
                'avg_time_ms' => round($avgTime, 2),
                'memory_used_kb' => round($memoryUsed / 1024, 2),
                'throughput_ops_sec' => round(1000 / $avgTime, 2)
            ];
            
            printf("  %s bytes: %.2f ms/op, %.2f ops/sec, %.2f KB memory\n",
                $this->formatBytes($size),
                $avgTime,
                1000 / $avgTime,
                $memoryUsed / 1024
            );
        }
        echo "\n";
    }
    
    private function testDecryptionSpeed(): void
    {
        echo "📊 Testing Decryption Speed\n";
        echo str_repeat('-', 30) . "\n";
        
        $password = 'performance-test-password-2024';
        
        foreach ($this->config['data_sizes'] as $size) {
            $data = str_repeat('x', $size);
            $encrypted = MaatCrossLangCrypto::encrypt($data, $password);
            $iterations = 100;
            
            $startTime = microtime(true);
            $startMemory = memory_get_usage(true);
            
            for ($i = 0; $i < $iterations; $i++) {
                MaatCrossLangCrypto::decrypt($encrypted, $password);
            }
            
            $endTime = microtime(true);
            $endMemory = memory_get_usage(true);
            
            $avgTime = (($endTime - $startTime) * 1000) / $iterations;
            $memoryUsed = $endMemory - $startMemory;
            
            $this->results['decryption'][$size] = [
                'avg_time_ms' => round($avgTime, 2),
                'memory_used_kb' => round($memoryUsed / 1024, 2),
                'throughput_ops_sec' => round(1000 / $avgTime, 2)
            ];
            
            printf("  %s bytes: %.2f ms/op, %.2f ops/sec, %.2f KB memory\n",
                $this->formatBytes($size),
                $avgTime,
                1000 / $avgTime,
                $memoryUsed / 1024
            );
        }
        echo "\n";
    }
    
    private function testMemoryUsage(): void
    {
        echo "💾 Testing Memory Usage\n";
        echo str_repeat('-', 30) . "\n";
        
        $password = 'memory-test-password-2024';
        $data = str_repeat('x', 10240); // 10KB
        
        // Test memory growth
        $baseMemory = memory_get_usage(true);
        $encrypted_items = [];
        
        for ($i = 0; $i < 1000; $i++) {
            $encrypted_items[] = MaatCrossLangCrypto::encrypt($data, $password);
            
            if (($i + 1) % 100 === 0) {
                $currentMemory = memory_get_usage(true);
                $memoryGrowth = ($currentMemory - $baseMemory) / 1024;
                
                printf("  After %d operations: %.2f KB memory growth\n", 
                    $i + 1, $memoryGrowth);
            }
        }
        
        $finalMemory = memory_get_usage(true);
        $totalGrowth = ($finalMemory - $baseMemory) / 1024;
        
        $this->results['memory'] = [
            'base_memory_kb' => round($baseMemory / 1024, 2),
            'final_memory_kb' => round($finalMemory / 1024, 2),
            'total_growth_kb' => round($totalGrowth, 2),
            'avg_per_operation_bytes' => round($totalGrowth * 1024 / 1000, 2)
        ];
        
        printf("  Total memory growth: %.2f KB (%.2f bytes/operation)\n\n", 
            $totalGrowth, $totalGrowth * 1024 / 1000);
    }
    
    private function testConcurrentOperations(): void
    {
        echo "⚡ Testing Concurrent Operations Simulation\n";
        echo str_repeat('-', 30) . "\n";
        
        $password = 'concurrent-test-password-2024';
        $data = 'Concurrent operation test data';
        $operations = 1000;
        
        // Simulate concurrent operations with mixed encrypt/decrypt
        $encrypted_pool = [];
        for ($i = 0; $i < 100; $i++) {
            $encrypted_pool[] = MaatCrossLangCrypto::encrypt($data . $i, $password);
        }
        
        $startTime = microtime(true);
        
        for ($i = 0; $i < $operations; $i++) {
            if ($i % 2 === 0) {
                // Encrypt operation
                MaatCrossLangCrypto::encrypt($data . $i, $password);
            } else {
                // Decrypt operation
                $randomEncrypted = $encrypted_pool[array_rand($encrypted_pool)];
                MaatCrossLangCrypto::decrypt($randomEncrypted, $password);
            }
        }
        
        $endTime = microtime(true);
        $totalTime = ($endTime - $startTime) * 1000;
        $avgTime = $totalTime / $operations;
        $throughput = $operations / ($totalTime / 1000);
        
        $this->results['concurrent'] = [
            'total_operations' => $operations,
            'total_time_ms' => round($totalTime, 2),
            'avg_time_ms' => round($avgTime, 2),
            'throughput_ops_sec' => round($throughput, 2)
        ];
        
        printf("  %d mixed operations: %.2f ms total, %.2f ms/op, %.2f ops/sec\n\n",
            $operations, $totalTime, $avgTime, $throughput);
    }
    
    private function testIterationImpact(): void
    {
        echo "🔄 Testing Iteration Count Impact\n";
        echo str_repeat('-', 30) . "\n";
        
        $password = 'iteration-test-password-2024';
        $data = 'Iteration impact test data';
        
        foreach ($this->config['iterations'] as $iterations) {
            $options = ['iterations' => $iterations];
            $testRuns = 10;
            
            $startTime = microtime(true);
            
            for ($i = 0; $i < $testRuns; $i++) {
                $encrypted = MaatCrossLangCrypto::encrypt($data, $password, $options);
                MaatCrossLangCrypto::decrypt($encrypted, $password);
            }
            
            $endTime = microtime(true);
            $avgTime = (($endTime - $startTime) * 1000) / $testRuns;
            
            $this->results['iterations'][$iterations] = [
                'avg_time_ms' => round($avgTime, 2),
                'relative_speed' => $iterations === 100000 ? 1.0 : round($avgTime / 
                    ($this->results['iterations'][100000]['avg_time_ms'] ?? $avgTime), 2)
            ];
            
            printf("  %s iterations: %.2f ms/op\n",
                number_format($iterations), $avgTime);
        }
        echo "\n";
    }
    
    private function formatBytes(int $bytes): string
    {
        if ($bytes < 1024) {
            return $bytes;
        } elseif ($bytes < 1024 * 1024) {
            return round($bytes / 1024, 1) . 'K';
        } else {
            return round($bytes / (1024 * 1024), 1) . 'M';
        }
    }
    
    private function generateReport(): array
    {
        echo "📈 Performance Test Summary\n";
        echo str_repeat('=', 60) . "\n";
        
        // Overall performance summary
        $encSpeeds = array_column($this->results['encryption'], 'avg_time_ms');
        $decSpeeds = array_column($this->results['decryption'], 'avg_time_ms');
        
        $report = [
            'summary' => [
                'test_date' => date('Y-m-d H:i:s'),
                'php_version' => PHP_VERSION,
                'avg_encryption_ms' => round(array_sum($encSpeeds) / count($encSpeeds), 2),
                'avg_decryption_ms' => round(array_sum($decSpeeds) / count($decSpeeds), 2),
                'memory_efficiency' => $this->results['memory']['avg_per_operation_bytes'] . ' bytes/op',
                'concurrent_throughput' => $this->results['concurrent']['throughput_ops_sec'] . ' ops/sec'
            ],
            'detailed_results' => $this->results,
            'recommendations' => $this->generateRecommendations()
        ];
        
        echo "Average Encryption Speed: {$report['summary']['avg_encryption_ms']} ms\n";
        echo "Average Decryption Speed: {$report['summary']['avg_decryption_ms']} ms\n";
        echo "Memory per Operation: {$report['summary']['memory_efficiency']}\n";
        echo "Concurrent Throughput: {$report['summary']['concurrent_throughput']}\n    def get_phone(self):
        """Get decrypted phone number"""
        crypto_service = DjangoCryptoService()
        return crypto_service.decrypt_field(self.encrypted_phone)
    
    def set_phone(self, phone):
        """Set phone number (will be encrypted on save)"""
        self._phone_plaintext = phone
    
    def get_address(self):
        """Get decrypted address"""
        crypto_service = DjangoCryptoService()
        return crypto_service.decrypt_field(self.encrypted_address)
    
    def set_address(self, address):
        """Set address (will be encrypted on save)"""
        self._address_plaintext = address
```

### Laravel (PHP)

Create a Laravel service provider and facade:

```php
<?php
// app/Services/CryptoService.php
namespace App\Services;

use MAAT\Crypto\MaatCrossLangCrypto;
use Illuminate\Support\Facades\Config;

class CryptoService
{
    private $key;
    private $options;
    
    public function __construct()
    {
        $this->key = config('crypto.key');
        $this->options = config('crypto.options', ['iterations' => 100000]);
    }
    
    public function encryptField($data)
    {
        if (is_array($data) || is_object($data)) {
            $data = json_encode($data);
        }
        return MaatCrossLangCrypto::encrypt((string)$data, $this->key, $this->options);
    }
    
    public function decryptField($encryptedData)
    {
        $decrypted = MaatCrossLangCrypto::decrypt($encryptedData, $this->key);
        $decoded = json_decode($decrypted, true);
        return $decoded !== null ? $decoded : $decrypted;
    }
    
    public function encryptModelAttributes($model, array $attributes)
    {
        foreach ($attributes as $attribute) {
            if (isset($model->$attribute)) {
                $model->$attribute = $this->encryptField($model->$attribute);
            }
        }
        return $model;
    }
}

// app/Providers/CryptoServiceProvider.php
namespace App\Providers;

use App\Services\CryptoService;
use Illuminate\Support\ServiceProvider;

class CryptoServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('crypto', function () {
            return new CryptoService();
        });
    }
    
    public function provides()
    {
        return ['crypto'];
    }
}

// app/Facades/Crypto.php
namespace App\Facades;

use Illuminate\Support\Facades\Facade;

class Crypto extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'crypto';
    }
}

// config/crypto.php
return [
    'key' => env('CRYPTO_KEY'),
    'options' => [
        'iterations' => env('CRYPTO_ITERATIONS', 100000)
    ]
];

// app/Http/Controllers/UserController.php
namespace App\Http\Controllers;

use App\Facades\Crypto;
use Illuminate\Http\Request;

class UserController extends Controller
{
    public function getEncryptedProfile(Request $request)
    {
        $userData = [
            'id' => $request->user()->id,
            'name' => $request->user()->name,
            'email' => $request->user()->email,
            'profile' => [
                'phone' => $request->user()->phone,
                'address' => $request->user()->address
            ]
        ];
        
        $encrypted = Crypto::encryptField($userData);
        
        return response()->json([
            'encrypted' => $encrypted,
            'timestamp' => now()->toISOString()
        ]);
    }
}

// app/Models/User.php (Eloquent Model with encrypted fields)
namespace App\Models;

use App\Facades\Crypto;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'encrypted_phone', 'encrypted_address'];
    
    // Automatically encrypt phone when setting
    public function setPhoneAttribute($value)
    {
        $this->attributes['encrypted_phone'] = Crypto::encryptField($value);
    }
    
    // Automatically decrypt phone when getting
    public function getPhoneAttribute()
    {
        if (isset($this->attributes['encrypted_phone'])) {
            return Crypto::decryptField($this->attributes['encrypted_phone']);
        }
        return null;
    }
    
    // Automatically encrypt address when setting
    public function setAddressAttribute($value)
    {
        $this->attributes['encrypted_address'] = Crypto::encryptField($value);
    }
    
    // Automatically decrypt address when getting
    public function getAddressAttribute()
    {
        if (isset($this->attributes['encrypted_address'])) {
            return Crypto::decryptField($this->attributes['encrypted_address']);
        }
        return null;
    }
}
```

## Real-World Use Cases

### Database Field Encryption

Encrypt sensitive database columns:

<details>
<summary>JavaScript (with MongoDB)</summary>

```javascript
const mongoose = require('mongoose');
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const CRYPTO_KEY = process.env.DB_CRYPTO_KEY;

// Custom encryption functions
function encryptField(value) {
    return MaatCrossLangCrypto.encrypt(JSON.stringify(value), CRYPTO_KEY);
}

function decryptField(encryptedValue) {
    const decrypted = MaatCrossLangCrypto.decrypt(encryptedValue, CRYPTO_KEY);
    return JSON.parse(decrypted);
}

// User schema with encrypted fields
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    encryptedEmail: { type: String, required: true },
    encryptedPhone: { type: String },
    encryptedAddress: { type: String },
    createdAt: { type: Date, default: Date.now }
});

// Virtual fields for easy access
userSchema.virtual('email')
    .get(function() {
        return this.encryptedEmail ? decryptField(this.encryptedEmail) : null;
    })
    .set(function(value) {
        this.encryptedEmail = encryptField(value);
    });

userSchema.virtual('phone')
    .get(function() {
        return this.encryptedPhone ? decryptField(this.encryptedPhone) : null;
    })
    .set(function(value) {
        this.encryptedPhone = encryptField(value);
    });

userSchema.virtual('address')
    .get(function() {
        return this.encryptedAddress ? decryptField(this.encryptedAddress) : null;
    })
    .set(function(value) {
        this.encryptedAddress = encryptField(value);
    });

const User = mongoose.model('User', userSchema);

// Usage example
async function createUser() {
    const user = new User({
        username: 'johndoe',
        email: 'john@example.com',  // Automatically encrypted
        phone: '+1-555-0123',       // Automatically encrypted
        address: '123 Main St'      // Automatically encrypted
    });
    
    await user.save();
    
    console.log('Stored (encrypted):', {
        username: user.username,
        encryptedEmail: user.encryptedEmail.substring(0, 30) + '...',
        encryptedPhone: user.encryptedPhone.substring(0, 30) + '...'
    });
    
    console.log('Retrieved (decrypted):', {
        username: user.username,
        email: user.email,    // Automatically decrypted
        phone: user.phone,    // Automatically decrypted
        address: user.address // Automatically decrypted
    });
}
```
</details>

<details>
<summary>Python (with SQLAlchemy)</summary>

```python
from sqlalchemy import Column, Integer, String, Text, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.hybrid import hybrid_property
from maat_cross_lang_crypto import MaatCrossLangCrypto
import json
import os
from datetime import datetime

Base = declarative_base()
CRYPTO_KEY = os.environ.get('DB_CRYPTO_KEY')

class EncryptedUser(Base):
    __tablename__ = 'encrypted_users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    encrypted_email = Column(Text)
    encrypted_phone = Column(Text)
    encrypted_address = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def _encrypt_field(self, value):
        return MaatCrossLangCrypto.encrypt(json.dumps(value), CRYPTO_KEY)
    
    def _decrypt_field(self, encrypted_value):
        if not encrypted_value:
            return None
        decrypted = MaatCrossLangCrypto.decrypt(encrypted_value, CRYPTO_KEY)
        return json.loads(decrypted)
    
    @hybrid_property
    def email(self):
        return self._decrypt_field(self.encrypted_email)
    
    @email.setter
    def email(self, value):
        self.encrypted_email = self._encrypt_field(value)
    
    @hybrid_property
    def phone(self):
        return self._decrypt_field(self.encrypted_phone)
    
    @phone.setter
    def phone(self, value):
        self.encrypted_phone = self._encrypt_field(value)
    
    @hybrid_property
    def address(self):
        return self._decrypt_field(self.encrypted_address)
    
    @address.setter
    def address(self, value):
        self.encrypted_address = self._encrypt_field(value)

# Usage example
engine = create_engine('sqlite:///encrypted_example.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

def create_user_example():
    session = Session()
    
    # Create user with automatic encryption
    user = EncryptedUser(
        username='johndoe',
        email='john@example.com',      # Automatically encrypted
        phone='+1-555-0123',           # Automatically encrypted
        address='123 Main St, City'    # Automatically encrypted
    )
    
    session.add(user)
    session.commit()
    
    print('Stored (encrypted):')
    print(f'  Username: {user.username}')
    print(f'  Encrypted Email: {user.encrypted_email[:30]}...')
    print(f'  Encrypted Phone: {user.encrypted_phone[:30]}...')
    
    print('\nRetrieved (decrypted):')
    print(f'  Username: {user.username}')
    print(f'  Email: {user.email}')        # Automatically decrypted
    print(f'  Phone: {user.phone}')        # Automatically decrypted
    print(f'  Address: {user.address}')    # Automatically decrypted
    
    session.close()

if __name__ == '__main__':
    create_user_example()
```
</details>

### API Response Encryption

Encrypt sensitive API responses:

<details>
<summary>JavaScript (REST API)</summary>

```javascript
const express = require('express');
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const app = express();
const API_KEY = process.env.API_CRYPTO_KEY;

// Middleware for encrypted responses
function encryptedResponse(req, res, next) {
    const originalJson = res.json;
    
    res.encryptedJson = function(data, encrypt = true) {
        if (encrypt) {
            const jsonString = JSON.stringify(data);
            const encrypted = MaatCrossLangCrypto.encrypt(jsonString, API_KEY);
            return originalJson.call(this, {
                encrypted: encrypted,
                timestamp: new Date().toISOString(),
                version: '1.0'
            });
        } else {
            return originalJson.call(this, data);
        }
    };
    
    next();
}

app.use(encryptedResponse);

// Financial data endpoint with encryption
app.get('/api/account/:id', async (req, res) => {
    try {
        // Simulate fetching sensitive financial data
        const accountData = {
            accountId: req.params.id,
            balance: 15420.50,
            currency: 'USD',
            accountNumber: '****1234',
            transactions: [
                {
                    id: 'txn001',
                    amount: -50.00,
                    description: 'Coffee Shop',
                    date: '2024-01-15',
                    category: 'dining'
                },
                {
                    id: 'txn002',
                    amount: 2500.00,
                    description: 'Salary',
                    date: '2024-01-14',
                    category: 'income'
                }
            ],
            personalInfo: {
                name: 'John Doe',
                email: 'john@example.com',
                phone: '+1-555-0123'
            }
        };
        
        // Send encrypted response
        res.encryptedJson(accountData);
        
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Client-side decryption example
app.post('/api/decrypt', express.json(), (req, res) => {
    try {
        const { encrypted } = req.body;
        const decrypted = MaatCrossLangCrypto.decrypt(encrypted, API_KEY);
        const data = JSON.parse(decrypted);
        
        res.json({
            success: true,
            data: data
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: 'Decryption failed'
        });
    }
});

app.listen(3000, () => {
    console.log('Encrypted API server running on port 3000');
});
```
</details>

### Microservice Communication

Secure communication between services:

<details>
<summary>Python (Service-to-Service)</summary>

```python
import requests
import json
from datetime import datetime, timezone
from maat_cross_lang_crypto import MaatCrossLangCrypto

# Shared key for microservice communication
SERVICE_CRYPTO_KEY = 'microservice-communication-key-2024'

class SecureServiceClient:
    def __init__(self, service_url, crypto_key):
        self.service_url = service_url
        self.crypto_key = crypto_key
    
    def encrypt_request(self, data):
        """Encrypt request data"""
        json_data = json.dumps(data, default=str)
        return MaatCrossLangCrypto.encrypt(json_data, self.crypto_key)
    
    def decrypt_response(self, encrypted_data):
        """Decrypt response data"""
        decrypted = MaatCrossLangCrypto.decrypt(encrypted_data, self.crypto_key)
        return json.loads(decrypted)
    
    def post_encrypted(self, endpoint, data):
        """Send encrypted POST request"""
        encrypted_data = self.encrypt_request(data)
        
        payload = {
            'encrypted': encrypted_data,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'service': 'user-service'
        }
        
        response = requests.post(f'{self.service_url}{endpoint}', json=payload)
        
        if response.status_code == 200:
            response_data = response.json()
            if 'encrypted' in response_data:
                return self.decrypt_response(response_data['encrypted'])
            return response_data
        else:
            raise Exception(f'Request failed: {response.status_code}')

class SecureServiceServer:
    def __init__(self, crypto_key):
        self.crypto_key = crypto_key
    
    def decrypt_request(self, request_data):
        """Decrypt incoming request"""
        if 'encrypted' in request_data:
            encrypted = request_data['encrypted']
            decrypted = MaatCrossLangCrypto.decrypt(encrypted, self.crypto_key)
            return json.loads(decrypted)
        return request_data
    
    def encrypt_response(self, data):
        """Encrypt outgoing response"""
        json_data = json.dumps(data, default=str)
        encrypted = MaatCrossLangCrypto.encrypt(json_data, self.crypto_key)
        
        return {
            'encrypted': encrypted,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'service': 'payment-service'
        }

# Example: User Service calling Payment Service
def process_payment_example():
    # User Service (Client)
    user_service = SecureServiceClient('http://payment-service:8080', SERVICE_CRYPTO_KEY)
    
    payment_request = {
        'user_id': 12345,
        'amount': 99.99,
        'currency': 'USD',
        'payment_method': {
            'type': 'credit_card',
            'token': 'tok_secure_payment_token_123'
        },
        'metadata': {
            'order_id': 'order-789',
            'description': 'Premium subscription'
        }
    }
    
    print('User Service - Sending encrypted payment request:')
    print(json.dumps(payment_request, indent=2))
    
    # Simulate encrypted communication
    server = SecureServiceServer(SERVICE_CRYPTO_KEY)
    
    # Payment Service receives and decrypts
    encrypted_request = user_service.encrypt_request(payment_request)
    decrypted_request = server.decrypt_request({'encrypted': encrypted_request})
    
    print('\nPayment Service - Received decrypted request:')
    print(json.dumps(decrypted_request, indent=2))
    
    # Payment Service processes and responds
    payment_response = {
        'transaction_id': f'txn_{int(datetime.now().timestamp())}',
        'status': 'completed',
        'amount': decrypted_request['amount'],
        'currency': decrypted_request['currency'],
        'processed_at': datetime.now(timezone.utc).isoformat(),
        'fees': {
            'processing_fee': 2.99,
            'total_charged': 102.98
        }
    }
    
    encrypted_response = server.encrypt_response(payment_response)
    print('\nPayment Service - Sending encrypted response')
    
    # User Service receives and decrypts response
    final_response = user_service.decrypt_response(encrypted_response['encrypted'])
    
    print('\nUser Service - Received decrypted response:')
    print(json.dumps(final_response, indent=2))

if __name__ == '__main__':
    process_payment_example()
```
</details>

## Cross-Language Examples

### JavaScript → Python → PHP Round Trip

Demonstrating full cross-language compatibility:

**Step 1: JavaScript encrypts data**
```javascript
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const sharedPassword = 'cross-language-demo-2024';
const originalData = {
    message: 'Cross-language encryption test',
    timestamp: new Date().toISOString(),
    languages: ['JavaScript', 'Python', 'PHP'],
    testData: {
        unicode: '🔐 🌍 Hello World! 🚀',
        numbers: [1, 2, 3, 42, 100],
        boolean: true,
        nested: {
            level1: {
                level2: 'Deep nested value'
            }
        }
    }
};

const jsEncrypted = MaatCrossLangCrypto.encrypt(
    JSON.stringify(originalData), 
    sharedPassword
);

console.log('JavaScript encrypted:', jsEncrypted.substring(0, 60) + '...');
```

**Step 2: Python decrypts and re-encrypts**
```python
from maat_cross_lang_crypto import MaatCrossLangCrypto
import json

shared_password = 'cross-language-demo-2024'

# Decrypt JavaScript data
js_encrypted = "eyJ2IjoiMS4wLjAiLCJhbGciOiJBRVMtMjU2LUdDTSIsImtkZiI6IlBCS0RGMi1TSEEyNTYiLCJpdGVyIjoxMDAwMDAsIml2IjoiYWJjZGVmZ2hpams..." # From JavaScript

try:
    decrypted_from_js = MaatCrossLangCrypto.decrypt(js_encrypted, shared_password)
    data = json.loads(decrypted_from_js)
    
    print('Python decrypted JavaScript data:')
    print(json.dumps(data, indent=2))
    
    # Modify data to prove Python processed it
    data['processed_by'] = 'Python'
    data['python_timestamp'] = datetime.now(timezone.utc).isoformat()
    
    # Re-encrypt for PHP
    python_encrypted = MaatCrossLangCrypto.encrypt(
        json.dumps(data, default=str), 
        shared_password
    )
    
    print(f'\nPython re-encrypted: {python_encrypted[:60]}...')
    
except Exception as e:
    print(f'Error in Python: {e}')
```

**Step 3: PHP decrypts and verifies**
```php
<?php
use MAAT\Crypto\MaatCrossLangCrypto;

$sharedPassword = 'cross-language-demo-2024';

// Decrypt Python data
$pythonEncrypted = "eyJ2IjoiMS4wLjAiLCJhbGciOiJBRVMtMjU2LUdDTSIsImtkZiI6IlBCS0RGMi1TSEEyNTYiLCJpdGVyIjoxMDAwMDAsIml2IjoieHl6YWJjZGVmZ2..."  // From Python

try {
    $decryptedFromPython = MaatCrossLangCrypto::decrypt($pythonEncrypted, $sharedPassword);
    $data = json_decode($decryptedFromPython, true);
    
    echo "PHP decrypted Python data:\n";
    echo json_encode($data, JSON_PRETTY_PRINT) . "\n";
    
    // Verify the chain of processing
    echo "\nCross-language processing chain:\n";
    echo "1. Original data created in: JavaScript\n";
    echo "2. Processed and modified by: " . ($data['processed_by'] ?? 'Unknown') . "\n";
    echo "3. Final verification in: PHP\n";
    
    // Verify original message is intact
    $originalMessage = $data['message'] ?? '';
    if ($originalMessage === 'Cross-language encryption test') {
        echo "\n✅ Cross-language compatibility test: SUCCESS!\n";
        echo "✅ Data integrity maintained across all languages\n";
    } else {
        echo "\n❌ Cross-language compatibility test: FAILED\n";
    }
    
} catch (Exception $e) {
    echo "Error in PHP: " . $e->getMessage() . "\n";
}
?>
```

## Advanced Patterns

### Batch Encryption

Efficiently encrypt multiple items:

<details>
<summary>JavaScript</summary>

```javascript
class BatchCrypto {
    constructor(password, options = {}) {
        this.password = password;
        this.options = options;
    }
    
    encryptBatch(items) {
        const results = [];
        const batchId = Date.now().toString();
        
        for (let i = 0; i < items.length; i++) {
            const item = items[i];
            const itemData = {
                batchId: batchId,
                index: i,
                timestamp: new Date().toISOString(),
                data: item
            };
            
            const encrypted = MaatCrossLangCrypto.encrypt(
                JSON.stringify(itemData),
                this.password,
                this.options
            );
            
            results.push({
                id: item.id || i,
                encrypted: encrypted,
                size: encrypted.length
            });
        }
        
        return {
            batchId: batchId,
            count: results.length,
            items: results,
            totalSize: results.reduce((sum, item) => sum + item.size, 0)
        };
    }
    
    decryptBatch(encryptedBatch) {
        const results = [];
        
        for (const encryptedItem of encryptedBatch.items) {
            try {
                const decrypted = MaatCrossLangCrypto.decrypt(
                    encryptedItem.encrypted,
                    this.password
                );
                const itemData = JSON.parse(decrypted);
                
                results.push({
                    id: encryptedItem.id,
                    data: itemData.data,
                    index: itemData.index,
                    timestamp: itemData.timestamp
                });
            } catch (error) {
                results.push({
                    id: encryptedItem.id,
                    error: error.message
                });
            }
        }
        
        return {
            batchId: encryptedBatch.batchId,
            count: results.length,
            items: results
        };
    }
}

// Usage example
const batchCrypto = new BatchCrypto('batch-encryption-key-2024');

const userDataBatch = [
    { id: 1, name: 'John Doe', email: 'john@example.com', role: 'admin' },
    { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'user' },
    { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'moderator' }
];

console.log('Original batch:');
console.log(JSON.stringify(userDataBatch, null, 2));

// Encrypt batch
const encryptedBatch = batchCrypto.encryptBatch(userDataBatch);
console.log('\nEncrypted batch summary:');
console.log(`Batch ID: ${encryptedBatch.batchId}`);
console.log(`Items: ${encryptedBatch.count}`);
console.log(`Total size: ${encryptedBatch.totalSize} characters`);

// Decrypt batch
const decryptedBatch = batchCrypto.decryptBatch(encryptedBatch);
console.log('\nDecrypted batch:');
console.log(JSON.stringify(decryptedBatch.items.map(item => item.data), null, 2));
```
</details>

### Stream Encryption

Handle large data streams:

<details>
<summary>Python</summary>

```python
import json
from typing import Iterator, Dict, Any
from maat_cross_lang_crypto import MaatCrossLangCrypto

class StreamCrypto:
    def __init__(self, password: str, options: Dict[str, Any] = None):
        self.password = password
        self.options = options or {'iterations': 100000}
        self.chunk_size = 1000  # Items per chunk
    
    def encrypt_stream(self, data_stream: Iterator[Dict]) -> Iterator[str]:
        """Encrypt a stream of data in chunks"""
        chunk = []
        chunk_id = 0
        
        for item in data_stream:
            chunk.append(item)
            
            if len(chunk) >= self.chunk_size:
                yield self._encrypt_chunk(chunk, chunk_id)
                chunk = []
                chunk_id += 1
        
        # Handle remaining items
        if chunk:
            yield self._encrypt_chunk(chunk, chunk_id)
    
    def decrypt_stream(self, encrypted_stream: Iterator[str]) -> Iterator[Dict]:
        """Decrypt a stream of encrypted chunks"""
        for encrypted_chunk in encrypted_stream:
            chunk_data = self._decrypt_chunk(encrypted_chunk)
            for item in chunk_data['items']:
                yield item
    
    def _encrypt_chunk(self, chunk: list, chunk_id: int) -> str:
        """Encrypt a single chunk"""
        chunk_data = {
            'chunk_id': chunk_id,
            'count': len(chunk),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'items': chunk
        }
        
        return MaatCrossLangCrypto.encrypt(
            json.dumps(chunk_data, default=str),
            self.password,
            self.options
        )
    
    def _decrypt_chunk(self, encrypted_chunk: str) -> Dict:
        """Decrypt a single chunk"""
        decrypted = MaatCrossLangCrypto.decrypt(encrypted_chunk, self.password)
        return json.loads(decrypted)

# Usage example with large dataset simulation
def generate_user_data(count: int) -> Iterator[Dict]:
    """Generate user data stream"""
    for i in range(count):
        yield {
            'id': i + 1,
            'username': f'user_{i + 1:06d}',
            'email': f'user{i + 1}@example.com',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'profile': {
                'first_name': f'FirstName{i + 1}',
                'last_name': f'LastName{i + 1}',
                'preferences': {
                    'theme': 'dark' if i % 2 == 0 else 'light',
                    'notifications': i % 3 == 0
                }
            },
            'metadata': {
                'signup_source': 'web' if i % 4 == 0 else 'mobile',
                'verification_status': i % 5 == 0
            }
        }

# Example: Process large dataset with encryption
stream_crypto = StreamCrypto('stream-encryption-key-2024')

print('Processing large user dataset with stream encryption...\n')

# Generate and encrypt 10,000 user records
user_stream = generate_user_data(10000)
encrypted_chunks = list(stream_crypto.encrypt_stream(user_stream))

print(f'Generated {len(encrypted_chunks)} encrypted chunks')
print(f'Sample encrypted chunk: {encrypted_chunks[0][:60]}...')

# Decrypt and verify
print('\nDecrypting stream...')
decrypted_users = list(stream_crypto.decrypt_stream(iter(encrypted_chunks)))

print(f'Decrypted {len(decrypted_users)} user records')
print('\nFirst 3 decrypted users:')
for i, user in enumerate(decrypted_users[:3]):
    print(f'{i + 1}. {user["username"]} ({user["email"]})')

print(f'\nLast user: {decrypted_users[-1]["username"]} (ID: {decrypted_users[-1]["id"]})')
print('✅ Stream encryption/decryption completed successfully!')
```
</details>

## Production Examples

#### Examples Guide

Comprehensive examples showing how to use MAAT Cross-Language Crypto in various scenarios.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Usage](#basic-usage)
- [Framework Integration](#framework-integration)
- [Real-World Use Cases](#real-world-use-cases)
- [Cross-Language Examples](#cross-language-examples)
- [Advanced Patterns](#advanced-patterns)
- [Production Examples](#production-examples)

## Getting Started

### Quick Installation

**JavaScript/Node.js:**
```bash
npm install @maat/maat-cross-lang-crypto
```

**Python:**
```bash
pip install maat-cross-lang-crypto
```

**PHP:**
```bash
composer require maat/maat-cross-lang-crypto
```

### First Example

All languages follow the same pattern:

<details>
<summary>JavaScript</summary>

```javascript
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const password = 'your-secure-password';
const data = 'Hello, World!';

// Encrypt
const encrypted = MaatCrossLangCrypto.encrypt(data, password);
console.log('Encrypted:', encrypted);

// Decrypt
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
console.log('Decrypted:', decrypted);
```
</details>

<details>
<summary>Python</summary>

```python
from maat_cross_lang_crypto import MaatCrossLangCrypto

password = 'your-secure-password'
data = 'Hello, World!'

# Encrypt
encrypted = MaatCrossLangCrypto.encrypt(data, password)
print(f'Encrypted: {encrypted}')

# Decrypt
decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
print(f'Decrypted: {decrypted}')
```
</details>

<details>
<summary>PHP</summary>

```php
<?php
use MAAT\Crypto\MaatCrossLangCrypto;

$password = 'your-secure-password';
$data = 'Hello, World!';

// Encrypt
$encrypted = MaatCrossLangCrypto::encrypt($data, $password);
echo "Encrypted: {$encrypted}\n";

// Decrypt
$decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
echo "Decrypted: {$decrypted}\n";
?>
```
</details>

## Basic Usage

### JSON Data Encryption

Perfect for encrypting structured data:

<details>
<summary>JavaScript</summary>

```javascript
const userData = {
    id: 12345,
    email: 'user@example.com',
    profile: {
        firstName: 'John',
        lastName: 'Doe',
        preferences: {
            theme: 'dark',
            notifications: true
        }
    }
};

// Convert to JSON string and encrypt
const jsonString = JSON.stringify(userData);
const encrypted = MaatCrossLangCrypto.encrypt(jsonString, password);

// Decrypt and parse back to object
const decryptedJson = MaatCrossLangCrypto.decrypt(encrypted, password);
const decryptedUser = JSON.parse(decryptedJson);

console.log('Original:', userData);
console.log('Decrypted:', decryptedUser);
```
</details>

<details>
<summary>Python</summary>

```python
import json

user_data = {
    'id': 12345,
    'email': 'user@example.com',
    'profile': {
        'firstName': 'John',
        'lastName': 'Doe',
        'preferences': {
            'theme': 'dark',
            'notifications': True
        }
    }
}

# Convert to JSON string and encrypt
json_string = json.dumps(user_data)
encrypted = MaatCrossLangCrypto.encrypt(json_string, password)

# Decrypt and parse back to dict
decrypted_json = MaatCrossLangCrypto.decrypt(encrypted, password)
decrypted_user = json.loads(decrypted_json)

print('Original:', user_data)
print('Decrypted:', decrypted_user)
```
</details>

<details>
<summary>PHP</summary>

```php
$userData = [
    'id' => 12345,
    'email' => 'user@example.com',
    'profile' => [
        'firstName' => 'John',
        'lastName' => 'Doe',
        'preferences' => [
            'theme' => 'dark',
            'notifications' => true
        ]
    ]
];

// Convert to JSON string and encrypt
$jsonString = json_encode($userData);
$encrypted = MaatCrossLangCrypto::encrypt($jsonString, $password);

// Decrypt and parse back to array
$decryptedJson = MaatCrossLangCrypto::decrypt($encrypted, $password);
$decryptedUser = json_decode($decryptedJson, true);

echo "Original: " . json_encode($userData) . "\n";
echo "Decrypted: " . json_encode($decryptedUser) . "\n";
```
</details>

### Custom Security Options

For high-security applications:

<details>
<summary>JavaScript</summary>

```javascript
const highSecurityOptions = {
    iterations: 200000,  // Double the default
    keyLength: 32,       // AES-256
    ivLength: 12,        // Standard for GCM
    saltLength: 16,      // 128-bit salt
    tagLength: 16        // 128-bit auth tag
};

const sensitiveData = 'Top secret financial information';
const encrypted = MaatCrossLangCrypto.encrypt(
    sensitiveData, 
    strongPassword, 
    highSecurityOptions
);

console.log('High-security encrypted:', encrypted);
```
</details>

<details>
<summary>Python</summary>

```python
high_security_options = {
    'iterations': 200000,  # Double the default
    'key_length': 32,      # AES-256
    'iv_length': 12,       # Standard for GCM
    'salt_length': 16,     # 128-bit salt
    'tag_length': 16       # 128-bit auth tag
}

sensitive_data = 'Top secret financial information'
encrypted = MaatCrossLangCrypto.encrypt(
    sensitive_data, 
    strong_password, 
    high_security_options
)

print(f'High-security encrypted: {encrypted}')
```
</details>

<details>
<summary>PHP</summary>

```php
$highSecurityOptions = [
    'iterations' => 200000,  // Double the default
    'keyLength' => 32,       // AES-256
    'ivLength' => 12,        // Standard for GCM
    'saltLength' => 16,      // 128-bit salt
    'tagLength' => 16        // 128-bit auth tag
];

$sensitiveData = 'Top secret financial information';
$encrypted = MaatCrossLangCrypto::encrypt(
    $sensitiveData, 
    $strongPassword, 
    $highSecurityOptions
);

echo "High-security encrypted: {$encrypted}\n";
```
</details>

### Key Generation

Generate secure random keys:

<details>
<summary>JavaScript</summary>

```javascript
// Generate keys of different lengths
const key128 = MaatCrossLangCrypto.generateKey(16);  // 128-bit
const key256 = MaatCrossLangCrypto.generateKey(32);  // 256-bit (default)
const key512 = MaatCrossLangCrypto.generateKey(64);  // 512-bit

console.log('128-bit key:', key128);
console.log('256-bit key:', key256);
console.log('512-bit key:', key512);

// Use generated key for encryption
const testData = 'Data encrypted with generated key';
const encrypted = MaatCrossLangCrypto.encrypt(testData, key256);
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, key256);

console.log('Test successful:', testData === decrypted);
```
</details>

<details>
<summary>Python</summary>

```python
# Generate keys of different lengths
key_128 = MaatCrossLangCrypto.generate_key(16)  # 128-bit
key_256 = MaatCrossLangCrypto.generate_key(32)  # 256-bit (default)
key_512 = MaatCrossLangCrypto.generate_key(64)  # 512-bit

print(f'128-bit key: {key_128}')
print(f'256-bit key: {key_256}')
print(f'512-bit key: {key_512}')

# Use generated key for encryption
test_data = 'Data encrypted with generated key'
encrypted = MaatCrossLangCrypto.encrypt(test_data, key_256)
decrypted = MaatCrossLangCrypto.decrypt(encrypted, key_256)

print(f'Test successful: {test_data == decrypted}')
```
</details>

<details>
<summary>PHP</summary>

```php
// Generate keys of different lengths
$key128 = MaatCrossLangCrypto::generateKey(16);  // 128-bit
$key256 = MaatCrossLangCrypto::generateKey(32);  // 256-bit (default)
$key512 = MaatCrossLangCrypto::generateKey(64);  // 512-bit

echo "128-bit key: {$key128}\n";
echo "256-bit key: {$key256}\n";
echo "512-bit key: {$key512}\n";

// Use generated key for encryption
$testData = 'Data encrypted with generated key';
$encrypted = MaatCrossLangCrypto::encrypt($testData, $key256);
$decrypted = MaatCrossLangCrypto::decrypt($encrypted, $key256);

echo "Test successful: " . ($testData === $decrypted ? 'Yes' : 'No') . "\n";
```
</details>

## Framework Integration

### Express.js (Node.js)

Create middleware for request/response encryption:

```javascript
const express = require('express');
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const app = express();
const CRYPTO_KEY = process.env.CRYPTO_KEY || 'your-app-key';

// Middleware to add encryption helpers
app.use((req, res, next) => {
    req.encrypt = (data) => {
        const jsonData = typeof data === 'object' ? JSON.stringify(data) : data;
        return MaatCrossLangCrypto.encrypt(jsonData, CRYPTO_KEY);
    };
    
    req.decrypt = (encryptedData) => {
        const decrypted = MaatCrossLangCrypto.decrypt(encryptedData, CRYPTO_KEY);
        try {
            return JSON.parse(decrypted);
        } catch {
            return decrypted;
        }
    };
    
    // Add encrypted response helper
    res.encryptedJson = (data) => {
        const encrypted = req.encrypt(data);
        res.json({ encrypted });
    };
    
    next();
});

// Example protected route
app.post('/api/user-data', (req, res) => {
    const userData = {
        id: 123,
        name: 'John Doe',
        email: 'john@example.com',
        sensitive: 'Confidential information'
    };
    
    // Send encrypted response
    res.encryptedJson(userData);
});

app.listen(3000, () => {
    console.log('Server running with encryption middleware');
});
```