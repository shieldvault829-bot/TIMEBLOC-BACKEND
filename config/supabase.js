// 📁 backend/config/supabase.js
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// Validate environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ =======================================');
  console.error('❌ SUPABASE CREDENTIALS MISSING');
  console.error('❌ =======================================');
  console.error('❌ Required environment variables:');
  console.error('❌ 1. SUPABASE_URL');
  console.error('❌ 2. SUPABASE_SERVICE_KEY');
  console.error('❌ =======================================');
  console.error('❌ Add these in Railway dashboard:');
  console.error('❌ - SUPABASE_URL = https://xxxx.supabase.co');
  console.error('❌ - SUPABASE_SERVICE_KEY = sbp_xxxxxxxx');
  console.error('❌ =======================================');
  
  // Create dummy client for development
  if (process.env.NODE_ENV === 'development') {
    console.warn('⚠️ Running in development mode with dummy client');
    module.exports = { 
      supabase: createDummyClient(),
      testConnection: async () => true 
    };
    return;
  }
  
  process.exit(1);
}

// Create Supabase client with enhanced configuration
const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    autoRefreshToken: true,
    persistSession: false,
    detectSessionInUrl: false
  },
  global: {
    headers: {
      'x-application-name': 'timebloc-backend',
      'x-application-version': '1.0.0'
    }
  },
  db: {
    schema: 'public'
  }
});

// ====================================
// PAYMENT HELPER FUNCTIONS
// ====================================

/**
 * Create a new payment record
 */
async function createPaymentRecord(paymentData) {
  try {
    const { data, error } = await supabase
      .from('payments')
      .insert([{
        user_id: paymentData.userId,
        payment_id: paymentData.paymentId,
        order_id: paymentData.orderId,
        amount: paymentData.amount,
        currency: paymentData.currency || 'USD',
        status: 'pending',
        payment_status: 'pending',
        invoice_url: paymentData.invoiceUrl,
        pay_address: paymentData.payAddress,
        pay_amount: paymentData.payAmount,
        pay_currency: paymentData.payCurrency || 'usdt',
        payment_details: paymentData.details || {}
      }])
      .select()
      .single();

    if (error) throw error;
    return { success: true, data };
  } catch (error) {
    console.error('Payment record creation error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Update payment status
 */
async function updatePaymentStatus(orderId, status, paymentData = {}) {
  try {
    const updateData = {
      status: status,
      payment_status: paymentData.payment_status || status,
      updated_at: new Date().toISOString(),
      ...paymentData
    };

    // If payment is completed, set completed_at
    if (status === 'completed') {
      updateData.completed_at = new Date().toISOString();
      updateData.actually_paid = paymentData.actually_paid;
    }

    const { data, error } = await supabase
      .from('payments')
      .update(updateData)
      .eq('order_id', orderId)
      .select()
      .single();

    if (error) throw error;
    return { success: true, data };
  } catch (error) {
    console.error('Payment status update error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Get payment by order ID
 */
async function getPaymentByOrderId(orderId) {
  try {
    const { data, error } = await supabase
      .from('payments')
      .select(`
        *,
        users:user_id (email, name, premium_status)
      `)
      .eq('order_id', orderId)
      .single();

    if (error) throw error;
    return { success: true, data };
  } catch (error) {
    console.error('Get payment error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Get user payments
 */
async function getUserPayments(userId, limit = 10) {
  try {
    const { data, error } = await supabase
      .from('payments')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;
    return { success: true, data };
  } catch (error) {
    console.error('Get user payments error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Update user subscription after successful payment
 */
async function updateUserSubscription(userId, plan, expiryDate) {
  try {
    // Update user
    const { error: userError } = await supabase
      .from('users')
      .update({
        premium_status: 'premium',
        premium_expiry: expiryDate,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId);

    if (userError) throw userError;

    // Create subscription record
    const { error: subError } = await supabase
      .from('subscriptions')
      .insert([{
        user_id: userId,
        plan: plan,
        status: 'active',
        starts_at: new Date().toISOString(),
        ends_at: expiryDate,
        auto_renew: true
      }]);

    if (subError) throw subError;

    return { success: true };
  } catch (error) {
    console.error('Update user subscription error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if user has active subscription
 */
async function checkUserSubscription(userId) {
  try {
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('premium_status, premium_expiry')
      .eq('id', userId)
      .single();

    if (userError) throw userError;

    const isPremium = user.premium_status === 'premium' && 
                     new Date(user.premium_expiry) > new Date();

    return {
      success: true,
      isPremium,
      expiryDate: user.premium_expiry,
      status: user.premium_status
    };
  } catch (error) {
    console.error('Check subscription error:', error);
    return { success: false, error: error.message };
  }
}

// ====================================
// USER MANAGEMENT FUNCTIONS
// ====================================

/**
 * Create or get user
 */
async function getOrCreateUser(email, name) {
  try {
    // Check if user exists
    const { data: existingUser, error: fetchError } = await supabase
      .from('users')
      .select('id, email, name, premium_status')
      .eq('email', email)
      .single();

    if (!fetchError && existingUser) {
      return { success: true, user: existingUser, isNew: false };
    }

    // Create new user
    const { data: newUser, error: createError } = await supabase
      .from('users')
      .insert([{
        email: email,
        name: name,
        password_hash: crypto.randomBytes(16).toString('hex'), // Temporary
        premium_status: 'free'
      }])
      .select('id, email, name, premium_status')
      .single();

    if (createError) throw createError;
    return { success: true, user: newUser, isNew: true };
  } catch (error) {
    console.error('Get or create user error:', error);
    return { success: false, error: error.message };
  }
}

// ====================================
// CONNECTION TEST
// ====================================

async function testConnection() {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('count')
      .limit(1);

    if (error) {
      console.error('❌ Supabase connection failed:', error.message);
      
      // Check if tables need to be created
      if (error.code === '42P01') { // Table doesn't exist
        console.warn('⚠️ Tables not found. Run the SQL setup script in Supabase.');
      }
      
      return false;
    }

    console.log('✅ Supabase connected successfully');
    
    // Test payments table
    const { error: paymentsError } = await supabase
      .from('payments')
      .select('count')
      .limit(1);
    
    if (paymentsError && paymentsError.code === '42P01') {
      console.warn('⚠️ Payments table not found. Run the SQL setup.');
    } else {
      console.log('✅ Payments table ready');
    }
    
    return true;
  } catch (error) {
    console.error('❌ Supabase connection test failed:', error.message);
    return false;
  }
}

// ====================================
// DUMMY CLIENT FOR DEVELOPMENT
// ====================================

function createDummyClient() {
  console.warn('⚠️ Using dummy Supabase client for development');
  
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          single: async () => ({ data: null, error: null })
        }),
        limit: async () => ({ data: [], error: null })
      }),
      insert: () => ({
        select: () => ({
          single: async () => ({ data: { id: 'dummy-id' }, error: null })
        })
      }),
      update: () => ({
        eq: () => ({
          select: () => ({
            single: async () => ({ data: {}, error: null })
          })
        })
      })
    })
  };
}

// ====================================
// EXPORT
// ====================================

module.exports = { 
  supabase,
  testConnection,
  
  // Payment functions
  createPaymentRecord,
  updatePaymentStatus,
  getPaymentByOrderId,
  getUserPayments,
  updateUserSubscription,
  checkUserSubscription,
  
  // User functions
  getOrCreateUser
};