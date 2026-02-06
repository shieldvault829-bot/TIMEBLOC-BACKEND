// 📁 backend/services/paymentService.js - UPDATED
const axios = require('axios');
const crypto = require('crypto');
const { 
  createPaymentRecord, 
  updatePaymentStatus, 
  updateUserSubscription,
  getPaymentByOrderId 
} = require('../config/supabase');

class PaymentService {
  constructor() {
    this.apiKey = process.env.NOWPAYMENTS_API_KEY;
    this.baseURL = process.env.NOWPAYMENTS_API_URL || 'https://api.nowpayments.io/v1';
    this.ipnSecretKey = process.env.NOWPAYMENTS_IPN_SECRET;
  }
  
  async createPayment(userId, amount, currency = 'USD', product = 'premium_monthly', userEmail) {
    try {
      console.log(`Creating payment: User=${userId}, Amount=${amount}, Email=${userEmail}`);
      
      // Validate
      if (!userId || !amount || !userEmail) {
        throw new Error('Missing required parameters');
      }
      
      // Generate order ID
      const orderId = `timebloc_${userId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
      
      // Call NowPayments API
      const response = await axios.post(
        `${this.baseURL}/payment`,
        {
          price_amount: parseFloat(amount).toFixed(2),
          price_currency: currency.toUpperCase(),
          pay_currency: 'usdt',
          ipn_callback_url: `${process.env.BACKEND_URL || 'https://your-backend.railway.app'}/ipn-webhook`,
          order_id: orderId,
          order_description: `TimeBloc ${product}`,
          success_url: `${process.env.FRONTEND_URL || 'https://timebloc.vercel.app'}/payment/success?order=${orderId}`,
          cancel_url: `${process.env.FRONTEND_URL || 'https://timebloc.vercel.app'}/payment/cancel`,
          customer_email: userEmail
        },
        {
          headers: {
            'x-api-key': this.apiKey,
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );
      
      console.log('NowPayments response:', response.data);
      
      // Save to database using new config function
      const paymentResult = await createPaymentRecord({
        userId: userId,
        paymentId: response.data.payment_id,
        orderId: orderId,
        amount: amount,
        currency: currency,
        invoiceUrl: response.data.invoice_url,
        payAddress: response.data.pay_address,
        payAmount: response.data.pay_amount,
        payCurrency: response.data.pay_currency,
        details: response.data
      });
      
      if (!paymentResult.success) {
        console.warn('Payment record saved with warnings:', paymentResult.error);
      }
      
      return {
        success: true,
        payment: response.data,
        orderId: orderId
      };
      
    } catch (error) {
      console.error('Payment creation error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      
      throw new Error(`Payment creation failed: ${error.message}`);
    }
  }
  
  async verifyPayment(paymentId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/payment/${paymentId}`,
        {
          headers: { 'x-api-key': this.apiKey },
          timeout: 5000
        }
      );
      
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      console.error('Payment verification error:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }
  
  async processIPN(paymentData) {
    try {
      console.log('Processing IPN:', paymentData.order_id);
      
      // Verify signature if secret is available
      if (this.ipnSecretKey) {
        const dataString = JSON.stringify(paymentData, Object.keys(paymentData).sort());
        const signature = crypto
          .createHmac('sha512', this.ipnSecretKey)
          .update(dataString)
          .digest('hex');
        
        if (signature !== paymentData.ipn_signature) {
          console.error('Invalid IPN signature');
          return { success: false, error: 'Invalid signature' };
        }
      }
      
      const paymentStatus = paymentData.payment_status;
      const orderId = paymentData.order_id;
      
      // Update payment in database
      const updateResult = await updatePaymentStatus(orderId, 
        paymentStatus === 'finished' ? 'completed' : paymentStatus,
        {
          payment_status: paymentStatus,
          actually_paid: paymentData.actually_paid,
          payment_details: paymentData
        }
      );
      
      if (!updateResult.success) {
        console.error('Failed to update payment:', updateResult.error);
      }
      
      // Handle successful payment
      if (paymentStatus === 'finished' || paymentStatus === 'confirmed') {
        const parts = orderId.split('_');
        if (parts.length >= 2) {
          const userId = parts[1];
          
          // Calculate expiry (1 month from now)
          const expiryDate = new Date();
          expiryDate.setMonth(expiryDate.getMonth() + 1);
          
          // Update user subscription
          const subscriptionResult = await updateUserSubscription(
            userId, 
            'premium_monthly', 
            expiryDate.toISOString()
          );
          
          if (subscriptionResult.success) {
            console.log(`✅ User ${userId} upgraded to premium`);
            
            return { 
              success: true, 
              userId: userId,
              orderId: orderId,
              amount: paymentData.price_amount,
              currency: paymentData.price_currency
            };
          }
        }
      }
      
      return { 
        success: paymentStatus === 'finished', 
        status: paymentStatus,
        orderId: orderId
      };
      
    } catch (error) {
      console.error('IPN processing error:', error);
      return { 
        success: false, 
        error: error.message 
      };
    }
  }
  
  async checkPaymentByOrderId(orderId) {
    try {
      const result = await getPaymentByOrderId(orderId);
      return result;
    } catch (error) {
      console.error('Check payment error:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new PaymentService();