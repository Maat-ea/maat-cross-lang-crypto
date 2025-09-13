/**
 * Cross-Language Encryption Package - TypeScript Definitions
 * Compatible with Node.js and browsers
 */

declare module '@maat/maat-cross-lang-crypto' {
  export interface EncryptionOptions {
    /**
     * Number of PBKDF2 iterations (default: 100000)
     */
    iterations?: number;
    
    /**
     * Key length in bytes (default: 32)
     */
    keyLength?: number;
    
    /**
     * IV length in bytes (default: 12)
     */
    ivLength?: number;
    
    /**
     * Salt length in bytes (default: 16)
     */
    saltLength?: number;
    
    /**
     * Authentication tag length in bytes (default: 16)
     */
    tagLength?: number;
  }

  export interface VersionInfo {
    /**
     * Library version
     */
    version: string;
    
    /**
     * Encryption algorithm used
     */
    algorithm: string;
    
    /**
     * Key derivation function used
     */
    kdf: string;
    
    /**
     * Library identifier
     */
    library: string;
  }

  export interface EncryptedData {
    /**
     * Version of the encryption format
     */
    v: string;
    
    /**
     * Algorithm identifier
     */
    alg: string;
    
    /**
     * Key derivation function identifier
     */
    kdf: string;
    
    /**
     * Number of iterations used
     */
    iter: number;
    
    /**
     * Base64 encoded initialization vector
     */
    iv: string;
    
    /**
     * Base64 encoded salt
     */
    salt: string;
    
    /**
     * Base64 encoded authentication tag
     */
    tag: string;
    
    /**
     * Base64 encoded encrypted data
     */
    data: string;
  }

  export class MaatCrossLangCrypto {
    /**
     * Library version
     */
    static readonly VERSION: string;
    
    /**
     * Encryption algorithm
     */
    static readonly ALGORITHM: string;
    
    /**
     * Key derivation function
     */
    static readonly KDF: string;
    
    /**
     * Hash function for KDF
     */
    static readonly HASH: string;
    
    /**
     * Default encryption options
     */
    static readonly DEFAULT_OPTIONS: Required<EncryptionOptions>;

    /**
     * Encrypts data with password using AES-256-GCM
     * @param data - The data to encrypt
     * @param password - The password for encryption
     * @param options - Optional encryption parameters
     * @returns Base64 encoded encrypted data with metadata
     * @throws {Error} When encryption fails or invalid parameters provided
     */
    static encrypt(data: string, password: string, options?: EncryptionOptions): string;

    /**
     * Decrypts previously encrypted data
     * @param encryptedData - Base64 encoded encrypted data
     * @param password - The password used for encryption
     * @returns Decrypted data
     * @throws {Error} When decryption fails, wrong password, or corrupted data
     */
    static decrypt(encryptedData: string, password: string): string;

    /**
     * Generates a cryptographically secure random key
     * @param length - Key length in bytes (default: 32, range: 16-64)
     * @returns Base64 encoded random key
     * @throws {Error} When invalid length provided
     */
    static generateKey(length?: number): string;

    /**
     * Returns library version and algorithm information
     * @returns Version information object
     */
    static version(): VersionInfo;

    /**
     * Validates encrypted data structure (private method)
     * @private
     */
    static _validateEncryptedData(data: any): void;
  }

  export default MaatCrossLangCrypto;
}

// Global declarations for browser usage
declare global {
  interface Window {
    MaatCrossLangCrypto: typeof import('@maat/cross-lang-crypto').MaatCrossLangCrypto;
  }
}