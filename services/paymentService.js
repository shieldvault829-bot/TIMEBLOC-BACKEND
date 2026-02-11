// backend/services/paymentService.js
const axios = require('axios');

class PaymentService {
  constructor() {
    this.apiKey = process.env.NOWPAYMENTS_API_KEY;
    this.baseURL = 'https://api.nowpayments.io/v1';
  }
  
  async createPayment(amount, currency, orderId, description) {
    try {
      const response = await axios.post(
        `${this.baseURL}/payment`,
        {
          price_amount: amount,
          price_currency: currency,
          pay_currency: 'usdt',
          ipn_callback_url: `${process.env.BACKEND_URL}/api/ipn-webhook`,
          order_id: orderId,
          order_description: description,
          success_url: `${process.env.FRONTEND_URL}/payment/success`,
          cancel_url: `${process.env.FRONTEND_URL}/payment/cancel`
        },
        {
          headers: {
            'x-api-key': this.apiKey,
            'Content-Type': 'application/json'
          }
        }
      );
      
      return {
        success: true,
        payment: response.data
      };
    } catch (error) {
      console.error('Payment error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data || error.message
      };
    }
  }
}

module.exports = new PaymentService();