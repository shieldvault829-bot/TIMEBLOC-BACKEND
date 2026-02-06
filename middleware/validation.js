// ====================================
// INPUT VALIDATION & SANITIZATION
// ====================================
const validator = require('validator');

// Validation schemas
const validationRules = {
  register: {
    email: (value) => validator.isEmail(value) && value.length <= 100,
    password: (value) => 
      validator.isStrongPassword(value, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
      }),
    name: (value) => 
      typeof value === 'string' && 
      value.length >= 2 && 
      value.length <= 50 &&
      !/[<>{}[\]\\]/.test(value)
  },

  login: {
    email: (value) => validator.isEmail(value),
    password: (value) => typeof value === 'string' && value.length >= 8
  },

  payment: {
    amount: (value) => 
      !isNaN(parseFloat(value)) && 
      parseFloat(value) >= 1 && 
      parseFloat(value) <= 10000,
    currency: (value) => ['USD', 'EUR', 'GBP'].includes(value?.toUpperCase()),
    userEmail: (value) => validator.isEmail(value)
  },

  content: {
    text: (value) => 
      typeof value === 'string' && 
      value.length >= 1 && 
      value.length <= 10000,
    
    title: (value) => 
      typeof value === 'string' && 
      value.length >= 3 && 
      value.length <= 200 &&
      !/[<>{}[\]\\]/.test(value)
  }
};

// Main validation middleware
const validateRequest = (schemaName) => {
  return (req, res, next) => {
    try {
      const schema = validationRules[schemaName];
      if (!schema) {
        return next();
      }

      const errors = [];
      const data = { ...req.body, ...req.query, ...req.params };

      // Validate each field
      for (const [field, validatorFn] of Object.entries(schema)) {
        if (data[field] !== undefined && data[field] !== null) {
          if (!validatorFn(data[field])) {
            errors.push({
              field,
              value: data[field],
              error: `Invalid ${field} format or value`
            });
          }
        } else if (field !== 'optional') {
          errors.push({
            field,
            error: `${field} is required`
          });
        }
      }

      // Check for SQL injection attempts
      const sqlKeywords = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 
        'OR', 'AND', 'EXEC', 'EXECUTE', 'TRUNCATE'
      ];

      const checkSQLInjection = (obj) => {
        for (let key in obj) {
          if (typeof obj[key] === 'string') {
            const upperValue = obj[key].toUpperCase();
            if (sqlKeywords.some(keyword => 
              new RegExp(`\\b${keyword}\\b`).test(upperValue)
            )) {
              return true;
            }
          }
        }
        return false;
      };

      if (checkSQLInjection(data)) {
        console.warn(`🚨 SQL injection attempt detected: ${req.ip}`);
        return res.status(400).json({
          success: false,
          error: 'Invalid input detected',
          code: 'SECURITY_BLOCK'
        });
      }

      // Check for XSS attempts
      const xssPatterns = [
        /<script\b[^>]*>/i,
        /javascript:/i,
        /on\w+=/i,
        /eval\(/i,
        /alert\(/i
      ];

      const checkXSS = (obj) => {
        for (let key in obj) {
          if (typeof obj[key] === 'string') {
            if (xssPatterns.some(pattern => pattern.test(obj[key]))) {
              return true;
            }
          }
        }
        return false;
      };

      if (checkXSS(data)) {
        console.warn(`🚨 XSS attempt detected: ${req.ip}`);
        return res.status(400).json({
          success: false,
          error: 'Invalid input detected',
          code: 'SECURITY_BLOCK'
        });
      }

      if (errors.length > 0) {
        return res.status(400).json({
          success: false,
          errors,
          message: 'Validation failed',
          code: 'VALIDATION_FAILED'
        });
      }

      // Sanitize data
      const sanitize = (obj) => {
        const sanitized = {};
        for (let key in obj) {
          if (typeof obj[key] === 'string') {
            sanitized[key] = validator.escape(obj[key].trim());
          } else {
            sanitized[key] = obj[key];
          }
        }
        return sanitized;
      };

      req.body = sanitize(req.body);
      req.query = sanitize(req.query);
      req.params = sanitize(req.params);

      next();

    } catch (error) {
      console.error('Validation middleware error:', error);
      return res.status(500).json({
        success: false,
        error: 'Validation system error',
        code: 'VALIDATION_SYSTEM_ERROR'
      });
    }
  };
};

// Quick validation functions
const validators = {
  isEmail: validator.isEmail,
  isStrongPassword: (pass) => validator.isStrongPassword(pass, {
    minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1
  }),
  isAmount: (amount) => !isNaN(amount) && amount > 0 && amount <= 10000,
  isUUID: validator.isUUID
};

module.exports = {
  validateRequest,
  validators,
  validationRules
};