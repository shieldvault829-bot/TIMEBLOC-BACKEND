// ====================================
// ENHANCED RATE LIMITING MIDDLEWARE
// ====================================
const rateLimit = require('express-rate-limit');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// Store for tracking blocked IPs
const blockedIPs = new Map();
const suspiciousActivities = new Map();

// Clean up old blocked IPs every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of blockedIPs.entries()) {
    if (now - data.blockedAt > 3600000) { // 1 hour
      blockedIPs.delete(ip);
      console.log(`🟢 IP unblocked: ${ip}`);
    }
  }
}, 60000);

// Main rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    error: 'Too many requests from this IP. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    if (req.path === '/' || req.path === '/health') return true;
    
    // Check if IP is permanently blocked
    const ip = req.ip;
    if (blockedIPs.has(ip)) {
      const blockData = blockedIPs.get(ip);
      if (blockData.permanent) return false; // Don't skip, they're blocked
    }
    
    return false;
  },
  handler: (req, res) => {
    const ip = req.ip;
    
    // Track suspicious activity
    if (!suspiciousActivities.has(ip)) {
      suspiciousActivities.set(ip, { count: 1, firstSeen: Date.now() });
    } else {
      const data = suspiciousActivities.get(ip);
      data.count++;
      
      // If too many violations, block permanently
      if (data.count > 5) {
        blockedIPs.set(ip, {
          blockedAt: Date.now(),
          permanent: true,
          reason: 'Excessive rate limit violations'
        });
        console.log(`🔴 IP permanently blocked: ${ip}`);
      }
    }
    
    res.status(429).json({
      success: false,
      error: 'Too many requests. Please try again in 15 minutes.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 900 // 15 minutes in seconds
    });
  }
});

// Stricter limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 attempts per hour
  message: {
    success: false,
    error: 'Too many authentication attempts. Please try again later.',
    code: 'AUTH_RATE_LIMIT'
  },
  skipSuccessfulRequests: true // Don't count successful logins
});

// Payment endpoint limiter
const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 payment attempts per hour
  message: {
    success: false,
    error: 'Too many payment attempts. Please contact support.',
    code: 'PAYMENT_RATE_LIMIT'
  }
});

// User-specific rate limiting (prevents user ID spoofing)
const userSpecificLimiter = (req, res, next) => {
  const userId = req.user?.id || req.body?.userId;
  const ip = req.ip;
  
  if (!userId) return next();
  
  // Create unique key combining user ID and IP
  const key = `${userId}:${ip}`;
  
  if (!userSpecificLimiter.attempts) {
    userSpecificLimiter.attempts = new Map();
  }
  
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  
  if (!userSpecificLimiter.attempts.has(key)) {
    userSpecificLimiter.attempts.set(key, []);
  }
  
  const attempts = userSpecificLimiter.attempts.get(key);
  
  // Remove old attempts
  const validAttempts = attempts.filter(time => now - time < windowMs);
  
  // Check limit (50 requests per 15 minutes per user:IP)
  if (validAttempts.length >= 50) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests from your account.',
      code: 'USER_RATE_LIMIT'
    });
  }
  
  // Add current attempt
  validAttempts.push(now);
  userSpecificLimiter.attempts.set(key, validAttempts);
  
  next();
};

// Clean up user attempts store every hour
setInterval(() => {
  const now = Date.now();
  if (userSpecificLimiter.attempts) {
    for (const [key, attempts] of userSpecificLimiter.attempts.entries()) {
      const validAttempts = attempts.filter(time => now - time < 15 * 60 * 1000);
      if (validAttempts.length === 0) {
        userSpecificLimiter.attempts.delete(key);
      } else {
        userSpecificLimiter.attempts.set(key, validAttempts);
      }
    }
  }
}, 3600000);

// Middleware to check if IP is blocked
const checkBlockedIP = (req, res, next) => {
  const ip = req.ip;
  
  if (blockedIPs.has(ip)) {
    const blockData = blockedIPs.get(ip);
    
    if (blockData.permanent) {
      return res.status(403).json({
        success: false,
        error: 'Your IP address has been permanently blocked due to suspicious activity.',
        code: 'IP_PERMANENTLY_BLOCKED'
      });
    }
    
    // Check if temporary block has expired
    const blockTime = blockData.blockedAt;
    if (Date.now() - blockTime < 3600000) { // 1 hour block
      const remainingTime = Math.ceil((3600000 - (Date.now() - blockTime)) / 1000);
      return res.status(403).json({
        success: false,
        error: `IP temporarily blocked. Try again in ${remainingTime} seconds.`,
        code: 'IP_TEMPORARILY_BLOCKED'
      });
    } else {
      // Block expired
      blockedIPs.delete(ip);
    }
  }
  
  next();
};

module.exports = {
  apiLimiter,
  authLimiter,
  paymentLimiter,
  userSpecificLimiter,
  checkBlockedIP,
  blockedIPs, // For admin viewing if needed
  suspiciousActivities // For monitoring
};