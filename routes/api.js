// 📁 backend/routes/api.js - COMPLETE VERSION
const express = require('express');
const router = express.Router();
const paymentService = require('../services/paymentService');
const encryptionService = require('../services/encryptionService');
const { supabase } = require('../config/supabase');

// ====================
// 1. USER AUTHENTICATION
// ====================

// Register User
router.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email, password and name are required' 
      });
    }
    
    // Check if user exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();
    
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        error: 'User already exists with this email' 
      });
    }
    
    // Create user
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        email: email,
        name: name,
        password_hash: password, // Note: In production, use bcrypt!
        premium_status: 'free',
        created_at: new Date().toISOString()
      }])
      .select('id, email, name, premium_status, created_at')
      .single();
    
    if (error) throw error;
    
    // Generate simple token (for demo - use JWT in production)
    const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');
    
    res.json({ 
      success: true, 
      message: 'Registration successful',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        premium: user.premium_status === 'premium'
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Registration failed' 
    });
  }
});

// Login User
router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, premium_status, password_hash, premium_expiry')
      .eq('email', email)
      .single();
    
    if (error || !user) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid email or password' 
      });
    }
    
    // Check password (DEMO - use bcrypt.compare in production)
    if (user.password_hash !== password) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid email or password' 
      });
    }
    
    // Generate token
    const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');
    
    // Check if premium is still valid
    const isPremium = user.premium_status === 'premium' && 
                     new Date(user.premium_expiry) > new Date();
    
    res.json({
      success: true,
      message: 'Login successful',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        premium: isPremium,
        premium_expiry: user.premium_expiry
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Login failed' 
    });
  }
});

// Get Current User
router.get('/auth/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authorization token required' 
      });
    }
    
    // Decode token
    const decoded = Buffer.from(token, 'base64').toString();
    const [userId] = decoded.split(':');
    
    if (!userId) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid token' 
      });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, premium_status, premium_expiry, created_at')
      .eq('id', userId)
      .single();
    
    if (error || !user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    // Check premium expiry
    const isPremium = user.premium_status === 'premium' && 
                     new Date(user.premium_expiry) > new Date();
    
    res.json({ 
      success: true, 
      user: {
        ...user,
        premium: isPremium
      }
    });
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Failed to get user' 
    });
  }
});

// ====================
// 2. PAYMENT APIs
// ====================

// Create Payment
router.post('/create-payment', async (req, res) => {
  try {
    const { userId, amount, currency = 'USD', product, userEmail } = req.body;
    
    // Validation
    if (!userId || !amount || !userEmail) {
      return res.status(400).json({ 
        success: false, 
        error: 'userId, amount and userEmail are required' 
      });
    }
    
    // Check if user exists
    const { data: user } = await supabase
      .from('users')
      .select('id, email')
      .eq('id', userId)
      .single();
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    // Create payment
    const paymentResult = await paymentService.createPayment(
      userId, amount, currency, product, userEmail
    );
    
    if (!paymentResult.success) {
      throw new Error(paymentResult.error || 'Payment creation failed');
    }
    
    // Save payment to database
    const { error: dbError } = await supabase
      .from('payments')
      .insert([{
        user_id: userId,
        payment_id: paymentResult.payment.payment_id,
        order_id: paymentResult.orderId,
        amount: amount,
        currency: currency,
        status: 'pending',
        invoice_url: paymentResult.payment.invoice_url,
        created_at: new Date().toISOString()
      }]);
    
    if (dbError) throw dbError;
    
    res.json({
      success: true,
      message: 'Payment created successfully',
      payment: paymentResult.payment,
      orderId: paymentResult.orderId
    });
    
  } catch (error) {
    console.error('Create payment error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Payment creation failed' 
    });
  }
});

// Verify Payment
router.get('/verify-payment/:orderId', async (req, res) => {
  try {
    const orderId = req.params.orderId;
    
    if (!orderId) {
      return res.status(400).json({ 
        success: false, 
        error: 'orderId is required' 
      });
    }
    
    const { data: payment, error } = await supabase
      .from('payments')
      .select('*')
      .eq('order_id', orderId)
      .single();
    
    if (error || !payment) {
      return res.status(404).json({ 
        success: false, 
        error: 'Payment not found' 
      });
    }
    
    res.json({
      success: true,
      payment: payment,
      isCompleted: payment.status === 'completed'
    });
    
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Payment verification failed' 
    });
  }
});

// ====================
// 3. CONTENT ENCRYPTION APIs
// ====================

// Encrypt Content
router.post('/content/encrypt', async (req, res) => {
  try {
    const { content, userId } = req.body;
    
    if (!content || !userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'content and userId are required' 
      });
    }
    
    // Get user's encryption key
    const { data: user } = await supabase
      .from('users')
      .select('encryption_key')
      .eq('id', userId)
      .single();
    
    const encryptionKey = user?.encryption_key || process.env.DEFAULT_ENCRYPTION_KEY;
    
    if (!encryptionKey) {
      return res.status(500).json({ 
        success: false, 
        error: 'Encryption key not found' 
      });
    }
    
    const encrypted = encryptionService.encryptData(content, encryptionKey);
    
    res.json({ 
      success: true,
      message: 'Content encrypted successfully',
      encrypted: encrypted.encrypted,
      iv: encrypted.iv,
      authTag: encrypted.authTag
    });
    
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Encryption failed' 
    });
  }
});

// Decrypt Content
router.post('/content/decrypt', async (req, res) => {
  try {
    const { encrypted, iv, authTag, userId } = req.body;
    
    if (!encrypted || !iv || !authTag || !userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'All fields are required: encrypted, iv, authTag, userId' 
      });
    }
    
    // Get user's encryption key
    const { data: user } = await supabase
      .from('users')
      .select('encryption_key')
      .eq('id', userId)
      .single();
    
    const encryptionKey = user?.encryption_key || process.env.DEFAULT_ENCRYPTION_KEY;
    
    if (!encryptionKey) {
      return res.status(500).json({ 
        success: false, 
        error: 'Decryption key not found' 
      });
    }
    
    const decrypted = encryptionService.decryptData(
      { encrypted, iv, authTag },
      encryptionKey
    );
    
    res.json({ 
      success: true,
      message: 'Content decrypted successfully',
      decrypted: decrypted
    });
    
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Decryption failed' 
    });
  }
});

// ====================
// 4. USER PROFILE API
// ====================

// Get User by ID
router.get('/user/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, premium_status, premium_expiry, created_at')
      .eq('id', userId)
      .single();
    
    if (error || !user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    // Check premium expiry
    const isPremium = user.premium_status === 'premium' && 
                     new Date(user.premium_expiry) > new Date();
    
    res.json({ 
      success: true, 
      user: {
        ...user,
        premium: isPremium
      }
    });
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Failed to get user' 
    });
  }
});

// ====================
// EXPORT
// ====================
module.exports = router;