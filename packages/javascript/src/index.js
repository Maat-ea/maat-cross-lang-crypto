/**
 * Cross-Language Encryption Package - JavaScript Implementation
 * Compatible with Node.js and browsers
 */

const crypto = require('crypto');

class MaatCrossLangCrypto {
  static VERSION = '1.0.0';
  static ALGORITHM = 'aes-256-gcm';
  static KDF = 'pbkdf2';
  static HASH = 'sha256';
  
  static DEFAULT_OPTIONS = {
    iterations: 100000,
    keyLength: 32,    // 256 bits
    ivLength: 12,     // 96 bits for GCM
    saltLength: 16,   // 128 bits
    tagLength: 16     // 128 bits
  };

  /**
   * Encrypts data with password using AES-256-GCM
   * @param {string} data - Data to encrypt
   * @param {string} password - Password for encryption
   * @param {Object} options - Optional encryption parameters
   * @returns {string} Base64 encoded encrypted data with metadata
   */
  static encrypt(data, password, options = {}) {
    try {
      const opts = { ...MaatCrossLangCrypto.DEFAULT_OPTIONS, ...options };
      
      // Input validation
      if (!data || typeof data !== 'string') {
        throw new Error('Data must be a non-empty string');
      }
      if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
      }

      // Generate random salt and IV
      const salt = crypto.randomBytes(opts.saltLength);
      const iv = crypto.randomBytes(opts.ivLength);

      // Derive key using PBKDF2
      const key = crypto.pbkdf2Sync(password, salt, opts.iterations, opts.keyLength, MaatCrossLangCrypto.HASH);

      // Create cipher and encrypt
      const cipher = crypto.createCipheriv(MaatCrossLangCrypto.ALGORITHM, key, iv, {
        authTagLength: opts.tagLength
      });
      
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      // Get authentication tag
      const tag = cipher.getAuthTag();

      // Create metadata object
      const encryptedData = {
        v: MaatCrossLangCrypto.VERSION,
        alg: 'AES-256-GCM',
        kdf: 'PBKDF2-SHA256',
        iter: opts.iterations,
        iv: iv.toString('base64'),
        salt: salt.toString('base64'),
        tag: tag.toString('base64'),
        data: encrypted
      };

      // Return base64 encoded JSON
      return Buffer.from(JSON.stringify(encryptedData)).toString('base64');

    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypts data with password
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @param {string} password - Password for decryption
   * @returns {string} Decrypted data
   */
  static decrypt(encryptedData, password) {
    try {
      // Input validation
      if (!encryptedData || typeof encryptedData !== 'string') {
        throw new Error('Encrypted data must be a non-empty string');
      }
      if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
      }

      // Parse base64 encoded JSON
      let parsedData;
      try {
        const jsonString = Buffer.from(encryptedData, 'base64').toString('utf8');
        parsedData = JSON.parse(jsonString);
      } catch (error) {
        throw new Error('Invalid encrypted data format');
      }

      // Validate structure and version
      MaatCrossLangCrypto._validateEncryptedData(parsedData);

      // Extract components
      const iv = Buffer.from(parsedData.iv, 'base64');
      const salt = Buffer.from(parsedData.salt, 'base64');
      const tag = Buffer.from(parsedData.tag, 'base64');
      const encrypted = parsedData.data;

      // Derive key using same parameters
      const key = crypto.pbkdf2Sync(
        password, 
        salt, 
        parsedData.iter, 
        32, // keyLength - fixed for AES-256
        MaatCrossLangCrypto.HASH
      );

      // Create decipher and decrypt
      const decipher = crypto.createDecipheriv(MaatCrossLangCrypto.ALGORITHM, key, iv, {
        authTagLength: MaatCrossLangCrypto.DEFAULT_OPTIONS.tagLength
      });
      decipher.setAuthTag(tag);
      
      let decrypted = decipher.update(encrypted, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;

    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Generates a cryptographically secure random key
   * @param {number} length - Key length in bytes (default: 32)
   * @returns {string} Base64 encoded random key
   */
  static generateKey(length = 32) {
    if (!Number.isInteger(length) || length < 16 || length > 64) {
      throw new Error('Key length must be an integer between 16 and 64 bytes');
    }
    
    return crypto.randomBytes(length).toString('base64');
  }

  /**
   * Get version information
   * @returns {Object} Version and algorithm info
   */
  static version() {
    return {
      version: MaatCrossLangCrypto.VERSION,
      algorithm: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA256',
      library: 'cross-lang-crypto-js'
    };
  }

  /**
   * Validates encrypted data structure
   * @private
   */
  static _validateEncryptedData(data) {
    const requiredFields = ['v', 'alg', 'kdf', 'iter', 'iv', 'salt', 'tag', 'data'];
    
    for (const field of requiredFields) {
      if (!data[field]) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    if (data.alg !== 'AES-256-GCM') {
      throw new Error(`Unsupported algorithm: ${data.alg}`);
    }

    if (data.kdf !== 'PBKDF2-SHA256') {
      throw new Error(`Unsupported KDF: ${data.kdf}`);
    }

    if (!Number.isInteger(data.iter) || data.iter < 10000) {
      throw new Error('Invalid iteration count');
    }
  }
}

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
  module.exports = MaatCrossLangCrypto;
}

if (typeof window !== 'undefined') {
  window.MaatCrossLangCrypto = MaatCrossLangCrypto;
}

// Example usage:
/*
const password = 'my-secret-password';
const data = 'Hello, cross-language world!';

// Encrypt
const encrypted = MaatCrossLangCrypto.encrypt(data, password);
console.log('Encrypted:', encrypted);

// Decrypt
const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
console.log('Decrypted:', decrypted);

// Generate key
const key = MaatCrossLangCrypto.generateKey();
console.log('Random key:', key);
*/