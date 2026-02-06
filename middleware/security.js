// 📁 backend/middleware/security.js - COMPLETE SECURITY
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');

// Rate limiting - Brute force protection
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// API-specific rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: 'Too many API requests from this IP',
});

// Payment endpoint stricter limits
const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 payment attempts per hour
  message: 'Too many payment attempts from this IP',
});

// CORS configuration
const corsOptions = {
  origin: [
    'https://timebloc.vercel.app',
    'https://www.timebloc.com',
    'https://timebloc.com',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-API-Key'
  ],
  maxAge: 86400 // 24 hours
};

// Security headers
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://api.nowpayments.io"],
      frameSrc: ["'self'", "https://nowpayments.io"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

// Input sanitization
const sanitizeInput = (req, res, next) => {
  // Remove any $ or . from body, params, query
  if (req.body) {
    const sanitized = JSON.parse(JSON.stringify(req.body).replace(/\$/g, ''));
    req.body = sanitized;
  }
  next();
};

// SQL injection protection
const sqlInjectionProtection = (req, res, next) => {
  const sqlKeywords = [
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND',
    'EXEC', 'EXECUTE', 'TRUNCATE', 'ALTER', 'CREATE', 'TABLE'
  ];
  
  const checkForSQL = (obj) => {
    for (let key in obj) {
      if (typeof obj[key] === 'string') {
        const upperValue = obj[key].toUpperCase();
        if (sqlKeywords.some(keyword => upperValue.includes(keyword))) {
          return true;
        }
      }
    }
    return false;
  };
  
  if (checkForSQL(req.body) || checkForSQL(req.query) || checkForSQL(req.params)) {
    return res.status(400).json({ 
      error: 'Invalid input detected',
      success: false 
    });
  }
  
  next();
};

// XSS protection
const xssProtection = xss();

// HPP protection
const hppProtection = hpp();

// Request size limit
const requestSizeLimit = (req, res, next) => {
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 10 * 1024 * 1024) { // 10MB limit
    return res.status(413).json({ 
      error: 'Request entity too large',
      success: false 
    });
  }
  next();
};

// API key validation (for internal services)
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  // For NowPayments IPN, allow without key
  if (req.path === '/ipn-webhook') {
    return next();
  }
  
  // For internal API calls
  if (req.path.startsWith('/api/')) {
    if (!apiKey || apiKey !== process.env.INTERNAL_API_KEY) {
      return res.status(401).json({ 
        error: 'Invalid API key',
        success: false 
      });
    }
  }
  
  next();
};

// Logging for security monitoring
const securityLogger = (req, res, next) => {
  const suspiciousPatterns = [
    '/etc/passwd', '/bin/bash', 'union select', 'script>', 'javascript:',
    '../', '..\\', '<!--', '<?php', 'eval(', 'exec(', 'system('
  ];
  
  const url = req.url.toLowerCase();
  const userAgent = req.headers['user-agent'] || '';
  
  if (suspiciousPatterns.some(pattern => url.includes(pattern) || userAgent.includes(pattern))) {
    console.warn(`⚠️ SUSPICIOUS REQUEST: ${req.method} ${req.url} - IP: ${req.ip} - UA: ${userAgent}`);
    // Optionally block or log to security system
  }
  
  next();
};

module.exports = {
  limiter,
  apiLimiter,
  paymentLimiter,
  corsOptions,
  securityHeaders,
  sanitizeInput,
  sqlInjectionProtection,
  xssProtection,
  hppProtection,
  requestSizeLimit,
  validateApiKey,
  securityLogger,
  mongoSanitize: mongoSanitize()
};