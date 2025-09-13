# API Reference

Complete API documentation for MAAT Cross-Language Crypto library.

## Table of Contents

- [JavaScript/Node.js API](#javascriptnodejs-api)
- [Python API](#python-api)
- [PHP API](#php-api)
- [Common Parameters](#common-parameters)
- [Error Handling](#error-handling)
- [Data Structures](#data-structures)

## JavaScript/Node.js API

### Installation

```bash
npm install @maat/maat-cross-lang-crypto
```

### Import

```javascript
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');
// or ES6 modules
import MaatCrossLangCrypto from '@maat/maat-cross-lang-crypto';
```

### Methods

#### `encrypt(data, password, options?)`

Encrypts data using AES-256-GCM encryption.

**Parameters:**
- `data` (string): The data to encrypt
- `password` (string): The password for encryption
- `options` (object, optional): Encryption options

**Returns:** `string` - Base64 encoded encrypted data

**Example:**
```javascript
const encrypted = MaatCrossLangCrypto.encrypt('Hello World', 'my-password');
```

#### `decrypt(encryptedData, password)`

Decrypts previously encrypted data.

**Parameters:**
- `encryptedData` (string): Base64 encoded encrypted data
- `password` (string): The password used for encryption

**Returns:** `string` - Decrypted data

**Example:**
```javascript
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, 'my-password');
```

#### `generateKey(length?)`

Generates a cryptographically secure random key.

**Parameters:**
- `length` (number, optional): Key length in bytes (default: 32)

**Returns:** `string` - Base64 encoded random key

**Example:**
```javascript
const key = MaatCrossLangCrypto.generateKey(32); // 256-bit key
```

#### `version()`

Returns library version and algorithm information.

**Returns:** `object` - Version information

**Example:**
```javascript
const info = MaatCrossLangCrypto.version();
// {
//   version: '1.0.0',
//   algorithm: 'AES-256-GCM',
//   kdf: 'PBKDF2-SHA256',
//   library: 'cross-lang-crypto-js'
// }
```

## Python API

### Installation

```bash
pip install maat-cross-lang-crypto
```

### Import

```python
from maat_cross_lang_crypto import MaatCrossLangCrypto
```

### Methods

#### `encrypt(data: str, password: str, options: Optional[Dict[str, Any]] = None) -> str`

Encrypts data using AES-256-GCM encryption.

**Parameters:**
- `data` (str): The data to encrypt
- `password` (str): The password for encryption
- `options` (dict, optional): Encryption options

**Returns:** `str` - Base64 encoded encrypted data

**Raises:**
- `ValueError`: Invalid input parameters
- `RuntimeError`: Encryption failed

**Example:**
```python
encrypted = MaatCrossLangCrypto.encrypt('Hello World', 'my-password')
```

#### `decrypt(encrypted_data: str, password: str) -> str`

Decrypts previously encrypted data.

**Parameters:**
- `encrypted_data` (str): Base64 encoded encrypted data
- `password` (str): The password used for encryption

**Returns:** `str` - Decrypted data

**Raises:**
- `ValueError`: Invalid input parameters or data format
- `RuntimeError`: Decryption failed

**Example:**
```python
decrypted = MaatCrossLangCrypto.decrypt(encrypted, 'my-password')
```

#### `generate_key(length: int = 32) -> str`

Generates a cryptographically secure random key.

**Parameters:**
- `length` (int, optional): Key length in bytes (default: 32)

**Returns:** `str` - Base64 encoded random key

**Raises:**
- `ValueError`: Invalid key length

**Example:**
```python
key = MaatCrossLangCrypto.generate_key(32)  # 256-bit key
```

#### `version() -> Dict[str, str]`

Returns library version and algorithm information.

**Returns:** `dict` - Version information

**Example:**
```python
info = MaatCrossLangCrypto.version()
# {
#     'version': '1.0.0',
#     'algorithm': 'AES-256-GCM',
#     'kdf': 'PBKDF2-SHA256',
#     'library': 'cross-lang-crypto-python'
# }
```

## PHP API

### Installation

```bash
composer require maat/maat-cross-lang-crypto
```

### Import

```php
<?php
require_once 'vendor/autoload.php';
use MAAT\Crypto\MaatCrossLangCrypto;
```

### Methods

#### `encrypt(string $data, string $password, array $options = []): string`

Encrypts data using AES-256-GCM encryption.

**Parameters:**
- `$data` (string): The data to encrypt
- `$password` (string): The password for encryption
- `$options` (array, optional): Encryption options

**Returns:** `string` - Base64 encoded encrypted data

**Throws:**
- `InvalidArgumentException`: Invalid input parameters
- `RuntimeException`: Encryption failed

**Example:**
```php
$encrypted = MaatCrossLangCrypto::encrypt('Hello World', 'my-password');
```

#### `decrypt(string $encryptedData, string $password): string`

Decrypts previously encrypted data.

**Parameters:**
- `$encryptedData` (string): Base64 encoded encrypted data
- `$password` (string): The password used for encryption

**Returns:** `string` - Decrypted data

**Throws:**
- `InvalidArgumentException`: Invalid input parameters or data format
- `RuntimeException`: Decryption failed

**Example:**
```php
$decrypted = MaatCrossLangCrypto::decrypt($encrypted, 'my-password');
```

#### `generateKey(int $length = 32): string`

Generates a cryptographically secure random key.

**Parameters:**
- `$length` (int, optional): Key length in bytes (default: 32)

**Returns:** `string` - Base64 encoded random key

**Throws:**
- `InvalidArgumentException`: Invalid key length

**Example:**
```php
$key = MaatCrossLangCrypto::generateKey(32); // 256-bit key
```

#### `version(): array`

Returns library version and algorithm information.

**Returns:** `array` - Version information

**Example:**
```php
$info = MaatCrossLangCrypto::version();
// [
//     'version' => '1.0.0',
//     'algorithm' => 'AES-256-GCM',
//     'kdf' => 'PBKDF2-SHA256',
//     'library' => 'cross-lang-crypto-php'
// ]
```

## Common Parameters

### Options Object/Array

All languages support the same options structure:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `iterations` | integer | 100000 | PBKDF2 iteration count |
| `keyLength` | integer | 32 | Encryption key length in bytes |
| `ivLength` | integer | 12 | Initialization vector length in bytes |
| `saltLength` | integer | 16 | Salt length in bytes |
| `tagLength` | integer | 16 | Authentication tag length in bytes |

**Example:**
```javascript
const options = {
    iterations: 150000,    // Higher security
    keyLength: 32,         // AES-256
    ivLength: 12,          // GCM standard
    saltLength: 16,        // 128-bit salt
    tagLength: 16          // 128-bit auth tag
};
```

### Key Length Guidelines

| Length (bytes) | Key Strength | Use Case |
|----------------|--------------|----------|
| 16 | 128-bit | Basic security |
| 32 | 256-bit | **Recommended** |
| 64 | 512-bit | High security |

### Iteration Count Guidelines

| Iterations | Security Level | Use Case |
|------------|---------------|----------|
| 10,000 | Minimum | Testing only |
| 100,000 | **Recommended** | Production |
| 200,000+ | High Security | Sensitive data |

## Error Handling

### JavaScript

```javascript
try {
    const encrypted = MaatCrossLangCrypto.encrypt(data, password);
} catch (error) {
    console.error('Encryption failed:', error.message);
    // Handle error appropriately
}
```

### Python

```python
try:
    encrypted = MaatCrossLangCrypto.encrypt(data, password)
except ValueError as e:
    print(f'Invalid input: {e}')
except RuntimeError as e:
    print(f'Encryption failed: {e}')
```

### PHP

```php
try {
    $encrypted = MaatCrossLangCrypto::encrypt($data, $password);
} catch (InvalidArgumentException $e) {
    echo "Invalid input: " . $e->getMessage();
} catch (RuntimeException $e) {
    echo "Encryption failed: " . $e->getMessage();
}
```

### Common Error Types

| Error Type | Description | Resolution |
|------------|-------------|------------|
| Empty data | Data parameter is empty or null | Provide non-empty string |
| Empty password | Password parameter is empty or null | Provide non-empty password |
| Invalid format | Encrypted data is not valid base64/JSON | Check data integrity |
| Wrong password | Password doesn't match encryption | Use correct password |
| Invalid options | Options contain invalid values | Check option ranges |

## Data Structures

### Encrypted Data Format

All implementations produce the same encrypted data structure:

```json
{
  "v": "1.0.0",
  "alg": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "iter": 100000,
  "iv": "base64-encoded-iv",
  "salt": "base64-encoded-salt",
  "tag": "base64-encoded-auth-tag",
  "data": "base64-encoded-ciphertext"
}
```

This JSON is then base64-encoded for the final output.

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `v` | string | Library version |
| `alg` | string | Encryption algorithm |
| `kdf` | string | Key derivation function |
| `iter` | integer | PBKDF2 iteration count |
| `iv` | string | Base64-encoded initialization vector |
| `salt` | string | Base64-encoded salt |
| `tag` | string | Base64-encoded authentication tag |
| `data` | string | Base64-encoded encrypted data |

### Version Information Structure

```json
{
  "version": "1.0.0",
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-SHA256",
  "library": "cross-lang-crypto-[js|python|php]"
}
```

## Cross-Language Compatibility

All implementations are designed to be completely interoperable:

```javascript
// JavaScript encrypts
const jsEncrypted = MaatCrossLangCrypto.encrypt(data, password);
```

```python
# Python decrypts JavaScript data
decrypted = MaatCrossLangCrypto.decrypt(js_encrypted, password)
```

```php
// PHP decrypts JavaScript data
$decrypted = MaatCrossLangCrypto::decrypt($jsEncrypted, $password);
```

### Compatibility Requirements

1. **Same password** must be used across all languages
2. **Same options** should be used for consistent results
3. **UTF-8 encoding** is used for all string data
4. **Base64 encoding** is used for binary data
5. **JSON structure** is identical across implementations

## Performance Considerations

### Iteration Count Impact

Higher iteration counts increase security but reduce performance:

| Iterations | Relative Speed | Security Level |
|------------|---------------|----------------|
| 10,000 | 1x (baseline) | Minimum |
| 100,000 | ~10x slower | Recommended |
| 200,000 | ~20x slower | High security |

### Data Size Impact

Encryption overhead is constant regardless of data size:

| Data Size | Overhead | Total Size |
|-----------|----------|------------|
| 100 bytes | ~180 bytes | ~280 bytes |
| 1 KB | ~180 bytes | ~1.2 KB |
| 10 KB | ~180 bytes | ~10.2 KB |

The overhead includes:
- JSON structure metadata
- Base64 encoding expansion
- Salt, IV, and authentication tag

## Security Notes

### Algorithm Details

- **Encryption**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with SHA-256
- **Random Generation**: Cryptographically secure system RNG
- **Authentication**: Built-in with GCM mode

### Security Properties

- **Confidentiality**: 256-bit AES encryption
- **Integrity**: Authentication tags prevent tampering
- **Authenticity**: GCM provides authenticated encryption
- **Semantic Security**: Random IV ensures unique ciphertexts

### Best Practices

1. Use strong passwords (12+ characters, mixed case, numbers, symbols)
2. Store passwords securely (environment variables, key management)
3. Use high iteration counts (100,000+ for production)
4. Never log passwords or encrypted data
5. Regularly rotate encryption passwords
6. Use HTTPS for data transmission
7. Handle errors securely (don't leak information)

## Migration and Upgrades

### Version Compatibility

The library uses semantic versioning:
- **Major version** changes may break compatibility
- **Minor version** changes add features while maintaining compatibility
- **Patch version** changes fix bugs without breaking compatibility

### Upgrading

When upgrading versions:
1. Check changelog for breaking changes
2. Test with your existing encrypted data
3. Update dependencies in all environments
4. Consider re-encrypting with new security parameters if recommended

---

For more examples and use cases, see the [Examples Documentation](examples.md).

For security best practices, see the [Security Guide](security.md).