# MAAT Cross-Language Crypto

A secure, cross-language encryption library that provides consistent AES-256-GCM encryption across JavaScript, PHP, and Python implementations.

## 🔐 Features

- **Cross-Language Compatibility**: Encrypt in one language, decrypt in another
- **Secure by Default**: AES-256-GCM with PBKDF2-SHA256 key derivation
- **Production Ready**: Comprehensive test suites and security audits
- **Easy Integration**: Simple APIs for all supported languages
- **Framework Support**: Built-in support for Django, Laravel, Node.js, and more

## 🚀 Quick Start

### JavaScript/Node.js
```javascript
const MaatCrossLangCrypto = require('@maat/maat-cross-lang-crypto');

const password = 'your-secure-password';
const data = 'Hello, cross-language world!';

// Encrypt
const encrypted = MaatCrossLangCrypto.encrypt(data, password);
console.log('Encrypted:', encrypted);

// Decrypt
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
console.log('Decrypted:', decrypted);
```

### Python
```python
from maat_cross_lang_crypto import MaatCrossLangCrypto

password = 'your-secure-password'
data = 'Hello, cross-language world!'

# Encrypt
encrypted = MaatCrossLangCrypto.encrypt(data, password)
print(f'Encrypted: {encrypted}')

# Decrypt
decrypted = MaatCrossLangCrypto.decrypt(encrypted, password)
print(f'Decrypted: {decrypted}')
```

### PHP
```php
<?php
use MAAT\Crypto\MaatCrossLangCrypto;

$password = 'your-secure-password';
$data = 'Hello, cross-language world!';

// Encrypt
$encrypted = MaatCrossLangCrypto::encrypt($data, $password);
echo "Encrypted: {$encrypted}\n";

// Decrypt
$decrypted = MaatCrossLangCrypto::decrypt($encrypted, $password);
echo "Decrypted: {$decrypted}\n";
?>
```

## 📦 Installation

### JavaScript/Node.js
```bash
npm install @maat/maat-cross-lang-crypto
```

### Python
```bash
pip install maat-cross-lang-crypto
```

### PHP
```bash
composer require maat/maat-cross-lang-crypto
```

## 🔒 Security Features

- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **PBKDF2-SHA256**: Industry-standard key derivation (100,000+ iterations)
- **Cryptographically Secure**: Uses system random number generators
- **Tamper Detection**: Built-in integrity verification
- **No Key Storage**: Password-based encryption, no key management needed

## 🌍 Cross-Language Compatibility

All implementations produce identical encrypted output and can decrypt each other's data:

```javascript
// Encrypt in JavaScript
const jsEncrypted = MaatCrossLangCrypto.encrypt(data, password);
```

```python
# Decrypt in Python
decrypted = MaatCrossLangCrypto.decrypt(js_encrypted, password)
```

```php
// Decrypt in PHP
$decrypted = MaatCrossLangCrypto::decrypt($jsEncrypted, $password);
```

## 📚 Documentation

- **[API Reference](docs/api.md)** - Complete API documentation
- **[Examples](docs/examples.md)** - Usage examples and patterns
- **[Security Guide](docs/security.md)** - Security best practices

## 🛠 Framework Integration

### Django (Python)
```python
# settings.py
CROSS_LANG_CRYPTO = {
    'DEFAULT_KEY': 'your-app-encryption-key',
    'DEFAULT_OPTIONS': {'iterations': 100000}
}

# views.py
from django.conf import settings
encrypted = MaatCrossLangCrypto.encrypt(
    sensitive_data, 
    settings.CROSS_LANG_CRYPTO['DEFAULT_KEY']
)
```

### Laravel (PHP)
```php
// config/crypto.php
return [
    'key' => env('CRYPTO_KEY'),
    'options' => ['iterations' => 100000]
];

// Usage in controllers
$encrypted = MaatCrossLangCrypto::encrypt($data, config('crypto.key'));
```

### Express.js (Node.js)
```javascript
// app.js
const crypto = require('@maat/maat-cross-lang-crypto');

app.use((req, res, next) => {
    req.encrypt = (data) => crypto.encrypt(data, process.env.CRYPTO_KEY);
    req.decrypt = (data) => crypto.decrypt(data, process.env.CRYPTO_KEY);
    next();
});
```

## 🧪 Testing

All implementations include comprehensive test suites:

```bash
# JavaScript
npm test

# Python
python -m pytest tests/

# PHP  
php tests/run-all.php
```

Cross-language compatibility tests:
```bash
# Validate test vectors across all languages
npm run test:vectors
python tests/validate_with_vectors.py
php tests/validate-with-vectors.php
```

## 📊 Performance

| Data Size | Encryption | Decryption | Total |
|-----------|------------|------------|-------|
| 100 bytes | ~10ms      | ~10ms      | ~20ms |
| 1KB       | ~15ms      | ~15ms      | ~30ms |
| 10KB      | ~50ms      | ~50ms      | ~100ms |

*Benchmarks run on standard hardware with 100,000 PBKDF2 iterations*

## 🔧 Advanced Options

```javascript
const options = {
    iterations: 150000,    // Higher security (slower)
    keyLength: 32,         // AES-256 (32 bytes)
    ivLength: 12,          // GCM IV length
    saltLength: 16,        // Salt length
    tagLength: 16          // Auth tag length
};

const encrypted = MaatCrossLangCrypto.encrypt(data, password, options);
```

## 🤝 Use Cases

- **Microservices**: Secure data exchange between services
- **API Security**: Encrypt sensitive API responses
- **Database Fields**: Encrypt PII and sensitive database columns
- **File Storage**: Secure file encryption across platforms
- **Session Data**: Encrypted session storage
- **Cross-Platform Apps**: Consistent encryption across web, mobile, server

## 🛡 Security Considerations

- Always use strong passwords (12+ characters, mixed case, numbers, symbols)
- Store passwords securely (environment variables, key management systems)
- Use high iteration counts (100,000+ for production)
- Never log encrypted data or passwords
- Regularly rotate encryption passwords
- See [Security Guide](docs/security.md) for detailed best practices

## 📄 License

MIT License - see LICENSE file for details.

## 🤖 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass across all languages
5. Submit a pull request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/maat/cross-lang-crypto/issues)
- **Email**: support@maat-ea.com
- **Documentation**: [docs/](docs/)

## 🏢 About MAAT Systems

This library is developed and maintained by MAAT Systems East Africa Ltd, specializing in secure cross-platform solutions.

---

**⚠️ Security Notice**: This library has undergone security review but like all cryptographic software, should be used with proper security practices. See [SECURITY.md](SECURITY.md) for reporting security issues.