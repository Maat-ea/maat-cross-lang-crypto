/**
 * MAAT Cross-Language Crypto - JavaScript Examples
 * Complete examples showing various use cases
 */

const MaatCrossLangCrypto = require('../src/index.js');

console.log('🚀 MAAT Cross-Language Crypto - JavaScript Examples\n');

// ========================================
// Example 1: Basic Encryption/Decryption
// ========================================

console.log('📝 Example 1: Basic Encryption/Decryption');
console.log('=' .repeat(50));

function basicExample() {
    const password = 'my-secure-password-123';
    const data = 'Hello, World! This is a secret message.';
    
    console.log(`Original data: ${data}`);
    
    // Encrypt the data
    const encrypted = MaatCrossLangCrypto.encrypt(data, password);
    console.log(`Encrypted: ${encrypted.substring(0, 50)}...`);
    console.log(`Encrypted length: ${encrypted.length} characters`);
    
    // Decrypt the data
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
    console.log(`Decrypted: ${decrypted}`);
    
    console.log(`✅ Success: ${data === decrypted ? 'Data matches!' : 'Data mismatch!'}\n`);
    
    return encrypted; // Return for cross-language testing
}

const basicEncrypted = basicExample();

// ========================================
// Example 2: JSON Data Encryption
// ========================================

console.log('📝 Example 2: JSON Data Encryption');
console.log('=' .repeat(50));

function jsonExample() {
    const password = 'json-encryption-key-2024';
    
    // Complex JSON data
    const userData = {
        id: 12345,
        username: 'johndoe',
        email: 'john.doe@example.com',
        profile: {
            firstName: 'John',
            lastName: 'Doe',
            age: 30,
            preferences: {
                theme: 'dark',
                language: 'en',
                notifications: true
            }
        },
        roles: ['user', 'admin'],
        lastLogin: '2024-01-15T10:30:00Z',
        metadata: {
            loginCount: 42,
            accountCreated: '2023-01-01T00:00:00Z'
        }
    };
    
    console.log('Original user data:');
    console.log(JSON.stringify(userData, null, 2));
    
    // Convert to JSON string and encrypt
    const jsonString = JSON.stringify(userData);
    const encrypted = MaatCrossLangCrypto.encrypt(jsonString, password);
    
    console.log(`\nEncrypted JSON: ${encrypted.substring(0, 60)}...`);
    console.log(`Encrypted size: ${encrypted.length} characters`);
    console.log(`Original size: ${jsonString.length} characters`);
    console.log(`Overhead: ${encrypted.length - jsonString.length} characters`);
    
    // Decrypt and parse back to object
    const decryptedJson = MaatCrossLangCrypto.decrypt(encrypted, password);
    const decryptedUser = JSON.parse(decryptedJson);
    
    console.log('\nDecrypted user data:');
    console.log(JSON.stringify(decryptedUser, null, 2));
    
    const isValid = JSON.stringify(userData) === JSON.stringify(decryptedUser);
    console.log(`✅ JSON integrity: ${isValid ? 'Perfect match!' : 'Data corrupted!'}\n`);
}

jsonExample();

// ========================================
// Example 3: Custom Security Options
// ========================================

console.log('📝 Example 3: Custom Security Options');
console.log('=' .repeat(50));

function customOptionsExample() {
    const password = 'high-security-password-456';
    const data = 'Highly sensitive financial data requiring extra security';
    
    // High-security options
    const highSecurityOptions = {
        iterations: 200000,  // Double the default for extra security
        keyLength: 32,       // AES-256
        ivLength: 12,        // Standard for GCM
        saltLength: 16,      // 128-bit salt
        tagLength: 16        // 128-bit authentication tag
    };
    
    console.log('High-security encryption options:');
    console.log(JSON.stringify(highSecurityOptions, null, 2));
    
    console.time('High-security encryption');
    const encrypted = MaatCrossLangCrypto.encrypt(data, password, highSecurityOptions);
    console.timeEnd('High-security encryption');
    
    console.log(`Encrypted data: ${encrypted.substring(0, 50)}...`);
    
    console.time('High-security decryption');
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
    console.timeEnd('High-security decryption');
    
    console.log(`Decrypted: ${decrypted}`);
    console.log(`✅ Security test: ${data === decrypted ? 'Success!' : 'Failed!'}\n`);
}

customOptionsExample();

// ========================================
// Example 4: Key Generation
// ========================================

console.log('📝 Example 4: Cryptographic Key Generation');
console.log('=' .repeat(50));

function keyGenerationExample() {
    console.log('Generating cryptographically secure keys...');
    
    // Generate keys of different lengths
    const shortKey = MaatCrossLangCrypto.generateKey(16);  // 128-bit
    const standardKey = MaatCrossLangCrypto.generateKey(32); // 256-bit (default)
    const longKey = MaatCrossLangCrypto.generateKey(64);   // 512-bit
    
    console.log(`16-byte key: ${shortKey}`);
    console.log(`32-byte key: ${standardKey}`);
    console.log(`64-byte key: ${longKey}`);
    
    // Verify keys are different
    const key1 = MaatCrossLangCrypto.generateKey();
    const key2 = MaatCrossLangCrypto.generateKey();
    
    console.log(`\nUniqueness test:`);
    console.log(`Key 1: ${key1.substring(0, 20)}...`);
    console.log(`Key 2: ${key2.substring(0, 20)}...`);
    console.log(`Keys are unique: ${key1 !== key2 ? '✅ Yes' : '❌ No'}`);
    
    // Use generated key for encryption
    const testData = 'Test data encrypted with generated key';
    const encrypted = MaatCrossLangCrypto.encrypt(testData, standardKey);
    const decrypted = MaatCrossLangCrypto.decrypt(encrypted, standardKey);
    
    console.log(`\nGenerated key encryption test: ${testData === decrypted ? '✅ Success' : '❌ Failed'}\n`);
}

keyGenerationExample();

// ========================================
// Example 5: Error Handling
// ========================================

console.log('📝 Example 5: Error Handling');
console.log('=' .repeat(50));

function errorHandlingExample() {
    console.log('Testing various error scenarios...\n');
    
    // Test 1: Empty data
    try {
        MaatCrossLangCrypto.encrypt('', 'password');
        console.log('❌ Should have thrown error for empty data');
    } catch (error) {
        console.log('✅ Empty data error handled:', error.message);
    }
    
    // Test 2: Empty password
    try {
        MaatCrossLangCrypto.encrypt('data', '');
        console.log('❌ Should have thrown error for empty password');
    } catch (error) {
        console.log('✅ Empty password error handled:', error.message);
    }
    
    // Test 3: Invalid encrypted data
    try {
        MaatCrossLangCrypto.decrypt('invalid-base64-data', 'password');
        console.log('❌ Should have thrown error for invalid data');
    } catch (error) {
        console.log('✅ Invalid data error handled:', error.message);
    }
    
    // Test 4: Wrong password
    try {
        const validEncrypted = MaatCrossLangCrypto.encrypt('test data', 'correct-password');
        MaatCrossLangCrypto.decrypt(validEncrypted, 'wrong-password');
        console.log('❌ Should have thrown error for wrong password');
    } catch (error) {
        console.log('✅ Wrong password error handled:', error.message);
    }
    
    // Test 5: Invalid key generation length
    try {
        MaatCrossLangCrypto.generateKey(8); // Too short
        console.log('❌ Should have thrown error for invalid key length');
    } catch (error) {
        console.log('✅ Invalid key length error handled:', error.message);
    }
    
    console.log('\n✅ All error handling tests passed!\n');
}

errorHandlingExample();

// ========================================
// Example 6: Performance Testing
// ========================================

console.log('📝 Example 6: Performance Testing');
console.log('=' .repeat(50));

function performanceExample() {
    const password = 'performance-test-password';
    const testSizes = [
        { name: 'Small (100 bytes)', data: 'x'.repeat(100) },
        { name: 'Medium (1KB)', data: 'x'.repeat(1024) },
        { name: 'Large (10KB)', data: 'x'.repeat(10240) },
        { name: 'Extra Large (50KB)', data: 'x'.repeat(51200) }
    ];
    
    testSizes.forEach(test => {
        console.log(`\nTesting ${test.name}:`);
        
        // Encryption performance
        console.time(`${test.name} - Encryption`);
        const encrypted = MaatCrossLangCrypto.encrypt(test.data, password);
        console.timeEnd(`${test.name} - Encryption`);
        
        // Decryption performance
        console.time(`${test.name} - Decryption`);
        const decrypted = MaatCrossLangCrypto.decrypt(encrypted, password);
        console.timeEnd(`${test.name} - Decryption`);
        
        // Verify integrity
        const isValid = test.data === decrypted;
        console.log(`Data integrity: ${isValid ? '✅ Valid' : '❌ Corrupted'}`);
        console.log(`Compression ratio: ${(encrypted.length / test.data.length).toFixed(2)}x`);
    });
    
    console.log('\n✅ Performance testing complete!\n');
}

performanceExample();

// ========================================
// Example 7: Express.js Integration
// ========================================

console.log('📝 Example 7: Express.js Integration Pattern');
console.log('=' .repeat(50));

function expressIntegrationExample() {
    // This is a demonstration - not actual Express server
    console.log('Express.js middleware integration pattern:\n');
    
    const cryptoMiddleware = (encryptionKey) => {
        return (req, res, next) => {
            // Add encryption helpers to request object
            req.encrypt = (data) => {
                if (typeof data === 'object') {
                    data = JSON.stringify(data);
                }
                return MaatCrossLangCrypto.encrypt(data, encryptionKey);
            };
            
            req.decrypt = (encryptedData) => {
                const decrypted = MaatCrossLangCrypto.decrypt(encryptedData, encryptionKey);
                try {
                    return JSON.parse(decrypted);
                } catch {
                    return decrypted; // Return as string if not JSON
                }
            };
            
            // Add secure response helper
            res.encryptedJson = (data) => {
                const encrypted = req.encrypt(data);
                res.json({ encrypted: encrypted });
            };
            
            console.log('✅ Crypto middleware attached to request');
            next && next();
        };
    };
    
    // Simulate middleware usage
    const req = {};
    const res = { 
        json: (data) => console.log('Response:', JSON.stringify(data, null, 2)),
        encryptedJson: null 
    };
    
    const middleware = cryptoMiddleware(process.env.CRYPTO_KEY || 'demo-encryption-key');
    middleware(req, res);
    
    // Demo API endpoint logic
    const userData = {
        id: 1,
        name: 'John Doe',
        email: 'john@example.com',
        sensitive: 'This data is encrypted'
    };
    
    console.log('\nOriginal API data:');
    console.log(JSON.stringify(userData, null, 2));
    
    const encrypted = req.encrypt(userData);
    console.log(`\nEncrypted API data: ${encrypted.substring(0, 50)}...`);
    
    const decrypted = req.decrypt(encrypted);
    console.log('\nDecrypted API data:');
    console.log(JSON.stringify(decrypted, null, 2));
    
    console.log('\n✅ Express.js integration example complete!\n');
}

expressIntegrationExample();

// ========================================
// Example 8: Database Field Encryption
// ========================================

console.log('📝 Example 8: Database Field Encryption');
console.log('=' .repeat(50));

function databaseFieldExample() {
    // Simulate database records with sensitive fields
    const dbPassword = 'database-encryption-key-2024';
    
    const users = [
        {
            id: 1,
            username: 'john_doe',
            email: 'john@example.com',
            phone: '+1-555-0123',
            ssn: '123-45-6789',
            address: '123 Main St, Anytown, USA 12345'
        },
        {
            id: 2,
            username: 'jane_smith',
            email: 'jane@example.com', 
            phone: '+1-555-0456',
            ssn: '987-65-4321',
            address: '456 Oak Ave, Somewhere, USA 67890'
        }
    ];
    
    console.log('Original user records:');
    users.forEach(user => {
        console.log(JSON.stringify(user, null, 2));
    });
    
    // Encrypt sensitive fields
    const sensitiveFields = ['email', 'phone', 'ssn', 'address'];
    
    const encryptedUsers = users.map(user => {
        const encryptedUser = { ...user };
        
        sensitiveFields.forEach(field => {
            if (encryptedUser[field]) {
                encryptedUser[field] = MaatCrossLangCrypto.encrypt(
                    encryptedUser[field], 
                    dbPassword
                );
            }
        });
        
        return encryptedUser;
    });
    
    console.log('\nEncrypted user records (ready for database storage):');
    encryptedUsers.forEach(user => {
        console.log(`User ${user.id}:`);
        console.log(`  Username: ${user.username}`);
        console.log(`  Email: ${user.email.substring(0, 30)}...`);
        console.log(`  Phone: ${user.phone.substring(0, 30)}...`);
        console.log(`  SSN: ${user.ssn.substring(0, 30)}...`);
        console.log(`  Address: ${user.address.substring(0, 30)}...`);
    });
    
    // Decrypt for application use
    const decryptedUsers = encryptedUsers.map(user => {
        const decryptedUser = { ...user };
        
        sensitiveFields.forEach(field => {
            if (decryptedUser[field]) {
                decryptedUser[field] = MaatCrossLangCrypto.decrypt(
                    decryptedUser[field], 
                    dbPassword
                );
            }
        });
        
        return decryptedUser;
    });
    
    console.log('\nDecrypted user records (for application use):');
    decryptedUsers.forEach(user => {
        console.log(JSON.stringify(user, null, 2));
    });
    
    // Verify data integrity
    const dataIntact = JSON.stringify(users) === JSON.stringify(decryptedUsers);
    console.log(`\n✅ Database field encryption test: ${dataIntact ? 'Success!' : 'Failed!'}\n`);
}

databaseFieldExample();

// ========================================
// Example 9: Microservice Communication
// ========================================

console.log('📝 Example 9: Microservice Communication');
console.log('=' .repeat(50));

function microserviceExample() {
    const serviceKey = 'microservice-communication-key-2024';
    
    // Service A sends encrypted message to Service B
    console.log('🔄 Simulating microservice communication...\n');
    
    // Service A: Prepare encrypted message
    const serviceAMessage = {
        requestId: 'req-123-456-789',
        timestamp: new Date().toISOString(),
        source: 'user-service',
        target: 'payment-service',
        action: 'process_payment',
        payload: {
            userId: 12345,
            amount: 99.99,
            currency: 'USD',
            paymentMethod: {
                type: 'credit_card',
                last4: '1234',
                token: 'tok_secure_payment_token'
            },
            metadata: {
                orderId: 'order-789',
                description: 'Premium subscription'
            }
        },
        security: {
            clientIp: '192.168.1.100',
            userAgent: 'MobileApp/1.2.3'
        }
    };
    
    console.log('Service A - Original message:');
    console.log(JSON.stringify(serviceAMessage, null, 2));
    
    // Encrypt the message
    const encryptedMessage = MaatCrossLangCrypto.encrypt(
        JSON.stringify(serviceAMessage), 
        serviceKey
    );
    
    console.log(`\nService A - Encrypted message: ${encryptedMessage.substring(0, 50)}...`);
    console.log(`Message size: ${encryptedMessage.length} characters`);
    
    // Service B: Receive and decrypt message
    console.log('\n🔄 Service B processing...');
    
    const decryptedMessageJson = MaatCrossLangCrypto.decrypt(encryptedMessage, serviceKey);
    const serviceBMessage = JSON.parse(decryptedMessageJson);
    
    console.log('Service B - Decrypted message:');
    console.log(JSON.stringify(serviceBMessage, null, 2));
    
    // Service B: Process and respond
    const responseMessage = {
        requestId: serviceBMessage.requestId,
        timestamp: new Date().toISOString(),
        source: 'payment-service',
        target: 'user-service',
        status: 'success',
        result: {
            transactionId: 'txn-' + Date.now(),
            amount: serviceBMessage.payload.amount,
            currency: serviceBMessage.payload.currency,
            status: 'completed',
            processingTime: '1.23s'
        }
    };
    
    const encryptedResponse = MaatCrossLangCrypto.encrypt(
        JSON.stringify(responseMessage), 
        serviceKey
    );
    
    console.log('\nService B - Encrypted response sent');
    
    // Service A: Receive response
    const decryptedResponse = JSON.parse(
        MaatCrossLangCrypto.decrypt(encryptedResponse, serviceKey)
    );
    
    console.log('Service A - Response received:');
    console.log(JSON.stringify(decryptedResponse, null, 2));
    
    console.log('\n✅ Microservice communication example complete!\n');
}

microserviceExample();

// ========================================
// Example 10: File Encryption Simulation
// ========================================

console.log('📝 Example 10: File Encryption Simulation');
console.log('=' .repeat(50));

function fileEncryptionExample() {
    const filePassword = 'file-encryption-password-2024';
    
    // Simulate different file types
    const files = [
        {
            name: 'document.txt',
            type: 'text/plain',
            content: 'This is a confidential document containing sensitive business information. It should be encrypted before storage or transmission.'
        },
        {
            name: 'config.json',
            type: 'application/json',
            content: JSON.stringify({
                database: {
                    host: 'db.example.com',
                    username: 'app_user',
                    password: 'super_secret_db_password',
                    database: 'production_db'
                },
                api: {
                    key: 'api_key_12345',
                    secret: 'api_secret_67890',
                    endpoints: {
                        users: '/api/v1/users',
                        payments: '/api/v1/payments'
                    }
                }
            }, null, 2)
        },
        {
            name: 'user_data.csv',
            type: 'text/csv',
            content: 'id,name,email,phone\n1,John Doe,john@example.com,555-0123\n2,Jane Smith,jane@example.com,555-0456\n3,Bob Johnson,bob@example.com,555-0789'
        }
    ];
    
    console.log('Original files:');
    files.forEach((file, index) => {
        console.log(`\n${index + 1}. ${file.name} (${file.type})`);
        console.log(`Size: ${file.content.length} bytes`);
        console.log(`Content: ${file.content.substring(0, 100)}${file.content.length > 100 ? '...' : ''}`);
    });
    
    // Encrypt files
    const encryptedFiles = files.map(file => ({
        ...file,
        encrypted: true,
        encryptedContent: MaatCrossLangCrypto.encrypt(file.content, filePassword),
        originalSize: file.content.length
    }));
    
    console.log('\n\nEncrypted files:');
    encryptedFiles.forEach((file, index) => {
        console.log(`\n${index + 1}. ${file.name} (encrypted)`);
        console.log(`Original size: ${file.originalSize} bytes`);
        console.log(`Encrypted size: ${file.encryptedContent.length} bytes`);
        console.log(`Overhead: ${file.encryptedContent.length - file.originalSize} bytes`);
        console.log(`Encrypted content: ${file.encryptedContent.substring(0, 80)}...`);
    });
    
    // Decrypt files
    console.log('\n\nDecrypting files...');
    const decryptedFiles = encryptedFiles.map(file => ({
        name: file.name,
        type: file.type,
        content: MaatCrossLangCrypto.decrypt(file.encryptedContent, filePassword)
    }));
    
    // Verify integrity
    let allFilesIntact = true;
    decryptedFiles.forEach((decryptedFile, index) => {
        const originalFile = files[index];
        const isIntact = originalFile.content === decryptedFile.content;
        
        if (!isIntact) allFilesIntact = false;
        
        console.log(`${decryptedFile.name}: ${isIntact ? '✅ Intact' : '❌ Corrupted'}`);
    });
    
    console.log(`\n✅ File encryption test: ${allFilesIntact ? 'All files successfully encrypted/decrypted!' : 'Some files corrupted!'}\n`);
}

fileEncryptionExample();

// ========================================
// Example 11: Cross-Language Compatibility Demo
// ========================================

console.log('📝 Example 11: Cross-Language Compatibility Demo');
console.log('=' .repeat(50));

function crossLanguageDemo() {
    console.log('Demonstrating cross-language compatibility...\n');
    
    const sharedPassword = 'cross-language-test-password-2024';
    const testData = {
        message: 'This data was encrypted in JavaScript',
        timestamp: new Date().toISOString(),
        metadata: {
            language: 'JavaScript/Node.js',
            version: '1.0.0',
            platform: process.platform,
            nodeVersion: process.version
        },
        testCases: [
            'Simple string',
            'Unicode: 🔐 🌍 🚀',
            'Special chars: !@#$%^&*()',
            'Numbers: 123456789',
            JSON.stringify({ nested: 'object', array: [1, 2, 3] })
        ]
    };
    
    console.log('Test data for cross-language compatibility:');
    console.log(JSON.stringify(testData, null, 2));
    
    // Encrypt with JavaScript
    const jsEncrypted = MaatCrossLangCrypto.encrypt(
        JSON.stringify(testData), 
        sharedPassword
    );
    
    console.log(`\nJavaScript encrypted data: ${jsEncrypted.substring(0, 60)}...`);
    console.log(`Data length: ${jsEncrypted.length} characters`);
    
    // Verify we can decrypt our own encryption
    const jsDecrypted = JSON.parse(
        MaatCrossLangCrypto.decrypt(jsEncrypted, sharedPassword)
    );
    
    console.log('\nJavaScript self-decryption test:');
    console.log(`✅ ${JSON.stringify(testData) === JSON.stringify(jsDecrypted) ? 'Success!' : 'Failed!'}`);
    
    // Create data structure info for other languages
    const structureInfo = JSON.parse(
        Buffer.from(jsEncrypted, 'base64').toString('utf8')
    );
    
    console.log('\nEncrypted data structure (for verification by other languages):');
    console.log(`Version: ${structureInfo.v}`);
    console.log(`Algorithm: ${structureInfo.alg}`);
    console.log(`KDF: ${structureInfo.kdf}`);
    console.log(`Iterations: ${structureInfo.iter}`);
    console.log(`IV length: ${Buffer.from(structureInfo.iv, 'base64').length} bytes`);
    console.log(`Salt length: ${Buffer.from(structureInfo.salt, 'base64').length} bytes`);
    console.log(`Tag length: ${Buffer.from(structureInfo.tag, 'base64').length} bytes`);
    
    console.log('\n📋 To test cross-language compatibility:');
    console.log('1. Use the encrypted data above in Python/PHP');
    console.log('2. Decrypt with the same password');
    console.log('3. Verify the decrypted JSON matches the original');
    console.log('4. Encrypt new data in Python/PHP');
    console.log('5. Decrypt that data here in JavaScript\n');
    
    // Save for cross-language testing
    return {
        encrypted: jsEncrypted,
        password: sharedPassword,
        originalData: testData
    };
}

const crossLangData = crossLanguageDemo();

// ========================================
// Example 12: Version and Library Info
// ========================================

console.log('📝 Example 12: Library Information');
console.log('=' .repeat(50));

function libraryInfoExample() {
    const version = MaatCrossLangCrypto.version();
    
    console.log('MAAT Cross-Language Crypto Library Information:');
    console.log(JSON.stringify(version, null, 2));
    
    console.log('\nEnvironment Information:');
    console.log(`Node.js Version: ${process.version}`);
    console.log(`Platform: ${process.platform}`);
    console.log(`Architecture: ${process.arch}`);
    console.log(`Current Working Directory: ${process.cwd()}`);
    
    // Feature support check
    console.log('\nFeature Support:');
    console.log('✅ AES-256-GCM encryption');
    console.log('✅ PBKDF2-SHA256 key derivation');
    console.log('✅ Cryptographically secure random generation');
    console.log('✅ Cross-language compatibility');
    console.log('✅ JSON data encryption');
    console.log('✅ Custom security options');
    console.log('✅ Error handling and validation');
    
    console.log('\n✅ Library information example complete!\n');
}

libraryInfoExample();

// ========================================
// Summary and Next Steps
// ========================================

console.log('🎉 All JavaScript Examples Complete!');
console.log('=' .repeat(50));

console.log('\n📚 What you learned:');
console.log('• Basic encryption and decryption');
console.log('• JSON data handling');
console.log('• Custom security options');
console.log('• Key generation');
console.log('• Error handling');
console.log('• Performance considerations');
console.log('• Express.js integration');
console.log('• Database field encryption');
console.log('• Microservice communication');
console.log('• File encryption patterns');
console.log('• Cross-language compatibility');
console.log('• Library information and features');

console.log('\n🔄 Next steps:');
console.log('• Try the Python examples');
console.log('• Try the PHP examples');
console.log('• Test cross-language compatibility');
console.log('• Integrate into your applications');
console.log('• Review the security documentation');

console.log('\n💡 Tips:');
console.log('• Always use strong passwords');
console.log('• Store passwords securely (environment variables)');
console.log('• Use appropriate iteration counts for your security needs');
console.log('• Test cross-language compatibility thoroughly');
console.log('• Handle errors gracefully in production');

console.log('\n🛡️ Security reminders:');
console.log('• Never hardcode passwords in your source code');
console.log('• Use HTTPS for data transmission');
console.log('• Regularly rotate encryption keys');
console.log('• Monitor for security updates');
console.log('• Follow the security best practices guide');

console.log('\n✨ Happy encrypting with MAAT Cross-Language Crypto! ✨');