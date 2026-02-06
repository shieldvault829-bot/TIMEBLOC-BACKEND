// ====================================
// JWT AUTHENTICATION MIDDLEWARE
// ====================================
const jwt = require('jsonwebtoken');
const { supabase } = require('../config/supabase');

const authMiddleware = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please provide a valid token.',
        code: 'NO_TOKEN'
      });
    }

    const token = authHeader.split(' ')[1];
    
    if (!token || token.length < 10) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token format',
        code: 'INVALID_TOKEN_FORMAT'
      });
    }

    // Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'timebloc-secret-key-change-in-production');
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          error: 'Token has expired. Please login again.',
          code: 'TOKEN_EXPIRED'
        });
      }
      return res.status(401).json({
        success: false,
        error: 'Invalid or tampered token',
        code: 'INVALID_TOKEN'
      });
    }

    // Check if user still exists in database
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, premium_status, premium_expiry, is_active, banned')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({
        success: false,
        error: 'User account not found or deleted',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check if user is banned
    if (user.banned) {
      return res.status(403).json({
        success: false,
        error: 'Account has been suspended. Please contact support.',
        code: 'ACCOUNT_BANNED'
      });
    }

    // Check if user is active
    if (user.is_active === false) {
      return res.status(403).json({
        success: false,
        error: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Check premium expiry
    const isPremium = user.premium_status === 'premium' && 
                     new Date(user.premium_expiry) > new Date();

    // Attach user info to request
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      premium: isPremium,
      premium_expiry: user.premium_expiry,
      token: token
    };

    // Log successful authentication (security audit)
    console.log(`✅ User authenticated: ${user.email} (${user.id}) - Premium: ${isPremium}`);

    next();

  } catch (error) {
    console.error('🔴 Auth middleware error:', error);
    
    // Never expose internal errors to client
    return res.status(500).json({
      success: false,
      error: 'Authentication system error',
      code: 'AUTH_SYSTEM_ERROR'
    });
  }
};

// Optional: Admin-only middleware
const adminMiddleware = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED'
    });
  }
  next();
};

// Optional: Premium-only middleware
const premiumMiddleware = (req, res, next) => {
  if (!req.user || !req.user.premium) {
    return res.status(403).json({
      success: false,
      error: 'Premium subscription required',
      code: 'PREMIUM_REQUIRED'
    });
  }
  next();
};

module.exports = {
  authMiddleware,
  adminMiddleware,
  premiumMiddleware
};