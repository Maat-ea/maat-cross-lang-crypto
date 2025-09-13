# @maat/maat-cross-lang-crypto

🔐 **Cross-Language Encryption Library** - AES-256-GCM encryption compatible across JavaScript, Python, and PHP

[![npm version](https://badge.fury.io/js/%40maat%2Fcross-lang-crypto.svg)](https://badge.fury.io/js/%40maat%2Fcross-lang-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/maat-systems/cross-lang-crypto/workflows/Node.js%20CI/badge.svg)](https://github.com/maat-systems/cross-lang-crypto/actions)

## Features

✨ **Cross-Language Compatible** - Encrypt in JavaScript, decrypt in Python/PHP (and vice versa)  
🛡️ **Military-Grade Security** - AES-256-GCM with PBKDF2-SHA256 key derivation  
🌐 **Universal Support** - Works in Node.js and browsers  
📦 **Zero Dependencies** - Lightweight with no external dependencies  
🔄 **Consistent Format** - Same encrypted output format across all implementations  
⚡ **High Performance** - Optimized for speed and security  
🧪 **Thoroughly Tested** - Comprehensive test suite with cross-language validation  

## Installation

```bash
npm install @maatsystems/maat-cross-lang-crypto
```

## Quick Start

```javascript
const MaatCrossLangCrypto = require('@maatsystems/maat-cross-lang-crypto');

const password = 'your-secure-password';
const data = 'Hello, cross-language world! 🌍';

// Encrypt
const encrypted = MaatCrossLangCrypto.encrypt(data, password);
console.log('Encrypted:', encrypted);

// Decrypt
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
console.log('Decrypted:', decrypted);
// Output: "Hello, cross-language world! 🌍"
```

## API Reference

### `encrypt(data, password, options?)`

Encrypts data with password using AES-256-GCM.

**Parameters:**
- `data` (string) - The data to encrypt
- `password` (string) - The password for encryption
- `options` (object, optional) - Custom encryption options

**Options:**
```javascript
{
  iterations: 100000,  // PBKDF2 iterations (default: 100000)
  keyLength: 32,       // Key length in bytes (default: 32)
  ivLength: 12,        // IV length in bytes (default: 12) 
  saltLength: 16,      // Salt length in bytes (default: 16)
  tagLength: 16        // Auth tag length in bytes (default: 16)
}
```

**Returns:** Base64 encoded encrypted data with metadata

**Example:**
```javascript
const encrypted = MaatCrossLangCrypto.encrypt('sensitive data', 'strong-password');

// With custom options
const customEncrypted = MaatCrossLangCrypto.encrypt('data', 'password', {
  iterations: 50000,
  saltLength: 32
});
```

### `decrypt(encryptedData, password)`

Decrypts previously encrypted data.

**Parameters:**
- `encryptedData` (string) - Base64 encoded encrypted data
- `password` (string) - The password used for encryption

**Returns:** Decrypted data as string

**Example:**
```javascript
const decrypted = MaatCrossLangCrypto.decrypt(encryptedData, 'strong-password');
```

### `generateKey(length?)`

Generates a cryptographically secure random key.

**Parameters:**
- `length` (number, optional) - Key length in bytes (default: 32, range: 16-64)

**Returns:** Base64 encoded random key

**Example:**
```javascript
const key32 = MaatCrossLangCrypto.generateKey();     // 32 bytes (256-bit)
const key16 = MaatCrossLangCrypto.generateKey(16);   // 16 bytes (128-bit)

// Use generated key as password
const encrypted = MaatCrossLangCrypto.encrypt('data', key32);
```

### `version()`

Returns library version and algorithm information.

**Returns:** Object with version details

**Example:**
```javascript
const info = MaatCrossLangCrypto.version();
console.log(info);
// {
//   version: '1.0.0',
//   algorithm: 'AES-256-GCM',
//   kdf: 'PBKDF2-SHA256',
//   library: 'cross-lang-crypto-js'
// }
```

## Cross-Language Compatibility

This library is designed to be compatible with implementations in other languages. The encrypted data format is standardized and can be decrypted by equivalent libraries in Python and PHP.

### Data Format

The encrypted output is a Base64-encoded JSON object with this structure:

```javascript
{
  "v": "1.0.0",                    // Version
  "alg": "AES-256-GCM",           // Algorithm
  "kdf": "PBKDF2-SHA256",         // Key derivation function
  "iter": 100000,                 // Iterations
  "iv": "base64-encoded-iv",      // Initialization vector
  "salt": "base64-encoded-salt",  // Salt
  "tag": "base64-encoded-tag",    // Authentication tag
  "data": "base64-encoded-data"   // Encrypted data
}
```

### Cross-Language Example

**Encrypt in JavaScript:**
```javascript
const MaatCrossLangCrypto = require('@maat/cross-lang-crypto');
const encrypted = MaatCrossLangCrypto.encrypt('Hello World', 'password123');
// Share this encrypted string with Python/PHP
```

**Decrypt in Python:**
```python
# Using equivalent Python library
from maat_cross_lang_crypto import MaatCrossLangCrypto
decrypted = MaatCrossLangCrypto.decrypt(encrypted_from_js, 'password123')
# Returns: "Hello World"
```

## Browser Usage

The library works in browsers using the Web Crypto API:

```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/@maat/cross-lang-crypto@latest/src/index.js"></script>
</head>
<body>
  <script>
    const data = 'Browser encryption test';
    const password = 'browser-password';
    
    const encrypted = MaatCrossLangCrypto.encrypt(data, password);
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
    
    console.log('Original:', data);
    console.log('Decrypted:', decrypted);
  </script>
</body>
</html>
```

## TypeScript Support

The library includes TypeScript definitions:

```typescript
import MaatCrossLangCrypto, { EncryptionOptions } from '@maat/cross-lang-crypto';

const options: EncryptionOptions = {
  iterations: 150000,
  keyLength: 32
};

const encrypted: string = MaatCrossLangCrypto.encrypt('data', 'password', options);
```

## Security Features

🔒 **AES-256-GCM Encryption** - Authenticated encryption with associated data  
🔑 **PBKDF2-SHA256 Key Derivation** - 100,000+ iterations by default  
🎲 **Cryptographically Secure Random** - Uses crypto.randomBytes()  
🛡️ **Authentication Tag** - Ensures data integrity and authenticity  
🧂 **Random Salt** - Prevents rainbow table attacks  
🔄 **Random IV** - Ensures different ciphertexts for same plaintext  

## Performance

Typical performance on modern hardware:

- **Encryption:** ~1000 operations/second (1KB data)
- **Decryption:** ~1200 operations/second (1KB data)
- **Key Generation:** ~10000 operations/second

*Note: Performance varies with iterations count and data size*

## Examples

### Basic Usage
```javascript
const crypto = require('@maat/cross-lang-crypto');

// Simple encryption
const result = crypto.encrypt('my secret', 'password123');
console.log(crypto.decrypt(result, 'password123'));
```

### Advanced Usage
```javascript
// Custom security parameters
const highSecurity = {
  iterations: 500000,  // Higher iterations for extra security
  saltLength: 32,      // Longer salt
  tagLength: 16        // Standard tag length
};

const encrypted = crypto.encrypt('top secret data', 'strong-password', highSecurity);
```

### File Encryption (Node.js)
```javascript
const fs = require('fs');
const crypto = require('@maat/cross-lang-crypto');

// Encrypt file contents
const fileContent = fs.readFileSync('document.txt', 'utf8');
const encrypted = crypto.encrypt(fileContent, 'file-password');
fs.writeFileSync('document.encrypted', encrypted);

// Decrypt file contents
const encryptedContent = fs.readFileSync('document.encrypted', 'utf8');
const decrypted = crypto.decrypt(encryptedContent, 'file-password');
fs.writeFileSync('document.decrypted.txt', decrypted);
```

## Requirements

- **Node.js:** 14.0.0 or higher
- **Browser:** Modern browsers with Web Crypto API support

## Testing

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:basic
npm run test:performance  
npm run test:compatibility

# Run example
npm run example
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 **Documentation:** [GitHub Wiki](https://github.com/maat-systems/cross-lang-crypto/wiki)
- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/maat-systems/cross-lang-crypto/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/maat-systems/cross-lang-crypto/discussions)
- 📧 **Email:** developers@maatsystems.com

## Related Libraries

- 🐍 **Python:** [@maat/cross-lang-crypto-py](https://pypi.org/project/maat-cross-lang-crypto/)
- 🐘 **PHP:** [maat/cross-lang-crypto-php](https://packagist.org/packages/maat/cross-lang-crypto-php)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.

---

**Made with ❤️ by [MAAT Systems East Africa Ltd](https://maatsystems.com)**

*Secure cross-language encryption for the modern web*