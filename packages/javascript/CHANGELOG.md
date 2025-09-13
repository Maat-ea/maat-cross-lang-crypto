# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Browser-specific optimizations
- Additional key derivation functions (Argon2, scrypt)
- Streaming encryption for large files
- Hardware security module (HSM) support

## [1.0.0] - 2025-12-09

### Added
- Initial release of MAAT Cross-Language Crypto JavaScript implementation
- AES-256-GCM encryption with PBKDF2-SHA256 key derivation
- Cross-language compatibility with Python and PHP implementations
- TypeScript definitions for better developer experience
- Comprehensive test suite covering functionality, performance, and compatibility
- Browser and Node.js support
- Zero external dependencies
- Cryptographically secure random key generation
- Configurable encryption parameters (iterations, key length, IV length, salt length, tag length)
- Input validation and error handling
- Base64-encoded JSON output format for easy sharing across platforms
- MIT license for open source usage

### Security
- Uses Node.js built-in `crypto` module for cryptographic operations
- Implements industry-standard AES-256-GCM authenticated encryption
- PBKDF2-SHA256 with 100,000 iterations by default
- Random salt generation for each encryption operation
- Random IV generation to prevent identical ciphertexts
- Authentication tag validation on decryption
- Secure key derivation with configurable iterations

### Features
- **encrypt(data, password, options?)** - Encrypts data with password
- **decrypt(encryptedData, password)** - Decrypts previously encrypted data  
- **generateKey(length?)** - Generates cryptographically secure random keys
- **version()** - Returns library version and algorithm information
- Support for Unicode and binary data
- Configurable security parameters
- Cross-platform compatibility (Node.js 14+ and modern browsers)
- Lightweight implementation with no dependencies

### Documentation
- Comprehensive README with usage examples
- API documentation with parameter details
- Cross-language usage examples
- Browser integration guide
- Security feature overview
- Performance benchmarks
- Contributing guidelines

### Testing
- Unit tests for all core functionality
- Performance benchmarks
- Cross-language compatibility tests
- Error handling validation
- Edge case coverage
- Automated test runner

---

## Version History

**1.0.0** - Initial stable release with full cross-language compatibility

## Migration Guide

### From Development to 1.0.0
- No breaking changes - this is the initial stable release
- All APIs are stable and follow semantic versioning from this point forward

## Support

For questions about specific versions or upgrade paths:
- Check the [GitHub Issues](https://github.com/Maat-ea/maat-cross-lang-crypto/issues)
- Review [GitHub Discussions](https://github.com/Maat-ea/maat-cross-lang-crypto/discussions)
- Contact us at hello@maat-ea.com