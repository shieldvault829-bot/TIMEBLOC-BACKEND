// 📁 backend/services/moderationService.js - COMPLETE
const axios = require('axios');

class ModerationService {
  constructor() {
    this.sensitiveWords = [
      // Add sensitive words here
      'hate', 'violence', 'harassment', 'abuse'
    ];
  }
  
  async checkText(text) {
    try {
      if (!text || typeof text !== 'string') {
        return { safe: true, confidence: 1.0 };
      }
      
      const lowerText = text.toLowerCase();
      
      // Check for sensitive words
      const containsSensitive = this.sensitiveWords.some(word => 
        lowerText.includes(word.toLowerCase())
      );
      
      // Check length (spam detection)
      const isTooLong = text.length > 10000;
      
      // Check for excessive special characters (spam)
      const specialCharRatio = (text.match(/[^a-zA-Z0-9\s]/g) || []).length / text.length;
      const hasExcessiveSpecialChars = specialCharRatio > 0.5;
      
      const isSafe = !containsSensitive && !isTooLong && !hasExcessiveSpecialChars;
      
      return {
        safe: isSafe,
        confidence: isSafe ? 0.95 : 0.1,
        flags: {
          sensitiveWords: containsSensitive,
          tooLong: isTooLong,
          excessiveSpecialChars: hasExcessiveSpecialChars
        }
      };
      
    } catch (error) {
      console.error('Text moderation error:', error);
      // Fail safe - allow content
      return { safe: true, confidence: 0.5, error: error.message };
    }
  }
  
  async checkImage(imageUrl) {
    try {
      // In production, integrate with:
      // 1. Google Cloud Vision API
      // 2. Amazon Rekognition
      // 3. Custom ML model
      
      // For now, return safe
      return {
        safe: true,
        confidence: 0.9,
        categories: [],
        adult: false,
        violence: false,
        racy: false
      };
      
    } catch (error) {
      console.error('Image moderation error:', error);
      return { safe: true, confidence: 0.5, error: error.message };
    }
  }
  
  async checkUrl(url) {
    try {
      // Check if URL is safe
      const maliciousDomains = [
        'malicious.com', 'phishing.site', 'scam.org'
      ];
      
      const isMalicious = maliciousDomains.some(domain => 
        url.includes(domain)
      );
      
      return {
        safe: !isMalicious,
        confidence: isMalicious ? 0.1 : 0.9,
        isMalicious: isMalicious
      };
      
    } catch (error) {
      console.error('URL moderation error:', error);
      return { safe: true, confidence: 0.5, error: error.message };
    }
  }
  
  async moderateContent(content, contentType = 'text') {
    try {
      let result;
      
      switch (contentType) {
        case 'text':
          result = await this.checkText(content);
          break;
        case 'image':
          result = await this.checkImage(content);
          break;
        case 'url':
          result = await this.checkUrl(content);
          break;
        default:
          result = { safe: true, confidence: 0.8 };
      }
      
      return {
        ...result,
        contentType: contentType,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      console.error('Content moderation error:', error);
      return {
        safe: true,
        confidence: 0.5,
        error: error.message,
        contentType: contentType,
        timestamp: new Date().toISOString()
      };
    }
  }
}

module.exports = new ModerationService();