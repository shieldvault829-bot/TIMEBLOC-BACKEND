// 📁 backend/services/encryptionService.js - ULTIMATE SECURITY - COMPLETE FIXED
const crypto = require('crypto');

class MilitaryEncryptionService {
  constructor() {
    // Multi-layer key protection
    this.encryptionKey = this.generateSecureKey();
    this.backupKey = this.generateSecureKey();
    this.keyRotationInterval = 30 * 24 * 60 * 60 * 1000; // 30 days
    this.lastKeyRotation = Date.now();
    
    // Initialize key rotation
    this.startKeyRotation();
  }
  
  // Generate secure random key
  generateSecureKey() {
    return crypto.randomBytes(32); // 256-bit key
  }
  
  // Start automatic key rotation
  startKeyRotation() {
    // Only start if not in test environment
    if (process.env.NODE_ENV !== 'test') {
      setInterval(() => {
        this.rotateKeys();
      }, this.keyRotationInterval);
    }
  }
  
  // Rotate encryption keys
  rotateKeys() {
    try {
      const newKey = this.generateSecureKey();
      this.backupKey = this.encryptionKey;
      this.encryptionKey = newKey;
      this.lastKeyRotation = Date.now();
      console.log('🔐 Encryption keys rotated successfully');
    } catch (error) {
      console.error('❌ Key rotation failed:', error.message);
    }
  }
  
  // Main encryption method (AES-256-GCM)
  encryptData(text, customKey = null) {
    try {
      if (!text || typeof text !== 'string') {
        return { 
          success: false, 
          error: 'Invalid input: text must be a non-empty string' 
        };
      }
      
      const key = customKey || this.encryptionKey;
      const iv = crypto.randomBytes(16); // 128-bit IV
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      
      // Add timestamp to prevent replay attacks
      const timestamp = Date.now().toString();
      const dataToEncrypt = `${timestamp}:${text}`;
      
      let encrypted = cipher.update(dataToEncrypt, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();
      
      // Create hash for integrity check
      const dataHash = crypto.createHash('sha256').update(text).digest('hex');
      
      return {
        success: true,
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        dataHash,
        algorithm: 'AES-256-GCM',
        timestamp,
        keyVersion: this.lastKeyRotation
      };
    } catch (error) {
      console.error('🔒 Encryption error:', error.message);
      return { 
        success: false, 
        error: 'Encryption failed: ' + error.message 
      };
    }
  }
  
  // Main decryption method
  decryptData(encryptedData, customKey = null) {
    try {
      // Validate input
      if (!encryptedData || 
          !encryptedData.encrypted || 
          !encryptedData.iv || 
          !encryptedData.authTag) {
        return { 
          success: false, 
          error: 'Invalid encrypted data format' 
        };
      }
      
      const key = customKey || this.encryptionKey;
      
      // First try with current key
      try {
        return this._decryptWithKey(encryptedData, key);
      } catch (error) {
        // Try with backup key if current fails
        console.log('🔐 Trying backup key...');
        return this._decryptWithKey(encryptedData, this.backupKey);
      }
    } catch (error) {
      console.error('🔒 Decryption error:', error.message);
      return { 
        success: false, 
        error: 'Decryption failed: ' + error.message 
      };
    }
  }
  
  // Private decryption method
  _decryptWithKey(encryptedData, key) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(encryptedData.iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Verify timestamp (prevent replay attacks)
    const [timestamp, actualData] = decrypted.split(':');
    const age = Date.now() - parseInt(timestamp);
    
    if (age > 5 * 60 * 1000) { // 5 minutes max age
      throw new Error('Data too old - possible replay attack');
    }
    
    // Verify integrity hash if available
    if (encryptedData.dataHash) {
      const calculatedHash = crypto.createHash('sha256').update(actualData).digest('hex');
      if (calculatedHash !== encryptedData.dataHash) {
        throw new Error('Data integrity check failed');
      }
    }
    
    return {
      success: true,
      decrypted: actualData,
      timestamp: parseInt(timestamp)
    };
  }
  
  // Password hashing with multiple rounds
  hashPassword(password) {
    try {
      if (!password || typeof password !== 'string' || password.length < 6) {
        throw new Error('Password must be at least 6 characters');
      }
      
      const salt = crypto.randomBytes(32).toString('hex');
      const iterations = 210000; // High iteration count
      
      const hash = crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        64, // 512-bit hash
        'sha512'
      ).toString('hex');
      
      return {
        success: true,
        hash,
        salt,
        iterations,
        algorithm: 'PBKDF2-SHA512'
      };
    } catch (error) {
      console.error('Password hashing error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Password verification
  verifyPassword(password, storedHash, salt, iterations = 210000) {
    try {
      const verifyHash = crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        64,
        'sha512'
      ).toString('hex');
      
      // Constant time comparison to prevent timing attacks
      const isMatch = crypto.timingSafeEqual(
        Buffer.from(verifyHash, 'hex'),
        Buffer.from(storedHash, 'hex')
      );
      
      return {
        success: true,
        isValid: isMatch
      };
    } catch (error) {
      console.error('Password verification error:', error);
      return {
        success: false,
        error: error.message,
        isValid: false
      };
    }
  }
  
  // Generate RSA key pair for digital signatures
  generateKeyPair() {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096, // 4096-bit RSA
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: crypto.randomBytes(32).toString('hex')
        }
      });
      
      return {
        success: true,
        publicKey,
        privateKey
      };
    } catch (error) {
      console.error('Key pair generation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Digital signature
  signData(data, privateKey) {
    try {
      const sign = crypto.createSign('SHA512');
      sign.update(data);
      sign.end();
      const signature = sign.sign(privateKey, 'hex');
      
      return {
        success: true,
        signature
      };
    } catch (error) {
      console.error('Signing error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Verify signature
  verifySignature(data, signature, publicKey) {
    try {
      const verify = crypto.createVerify('SHA512');
      verify.update(data);
      verify.end();
      const isValid = verify.verify(publicKey, signature, 'hex');
      
      return {
        success: true,
        isValid
      };
    } catch (error) {
      console.error('Signature verification error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Generate secure token
  generateSecureToken(length = 64) {
    try {
      const token = crypto.randomBytes(length).toString('hex');
      return {
        success: true,
        token
      };
    } catch (error) {
      console.error('Token generation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Encrypt file buffer
  encryptFile(fileBuffer, customKey = null) {
    try {
      if (!Buffer.isBuffer(fileBuffer)) {
        throw new Error('Input must be a Buffer');
      }
      
      const key = customKey || this.encryptionKey;
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      
      const encrypted = Buffer.concat([
        cipher.update(fileBuffer),
        cipher.final()
      ]);
      
      const authTag = cipher.getAuthTag();
      
      return {
        success: true,
        encrypted,
        iv,
        authTag,
        originalSize: fileBuffer.length
      };
    } catch (error) {
      console.error('File encryption error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  // Health check
  healthCheck() {
    try {
      const testData = 'health-check';
      const encrypted = this.encryptData(testData);
      
      if (!encrypted.success) {
        return { success: false, error: 'Encryption failed' };
      }
      
      const decrypted = this.decryptData(encrypted);
      
      return {
        success: decrypted.success && decrypted.decrypted === testData,
        encryption: encrypted.success,
        decryption: decrypted.success,
        keyRotation: this.lastKeyRotation
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new MilitaryEncryptionService();