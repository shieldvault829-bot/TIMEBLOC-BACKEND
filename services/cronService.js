// 📁 backend/services/cronService.js
const cron = require('node-cron');
const { supabase } = require('../config/supabase');

class CronService {
  constructor() {
    this.initCronJobs();
  }
  
  initCronJobs() {
    // Check expired subscriptions every day at midnight
    cron.schedule('0 0 * * *', async () => {
      console.log('⏰ Running subscription check...');
      await this.checkExpiredSubscriptions();
    });
    
    // Clean up old payments every Sunday at 2 AM
    cron.schedule('0 2 * * 0', async () => {
      console.log('🧹 Cleaning up old payments...');
      await this.cleanupOldPayments();
    });
    
    // Check pending payments every hour
    cron.schedule('0 * * * *', async () => {
      console.log('🔄 Checking pending payments...');
      await this.checkPendingPayments();
    });
    
    console.log('✅ Cron jobs initialized');
  }
  
  async checkExpiredSubscriptions() {
    try {
      const now = new Date().toISOString();
      
      const { data: expiredUsers, error } = await supabase
        .from('users')
        .select('id, email, premium_expiry')
        .eq('premium_status', 'premium')
        .lt('premium_expiry', now);
      
      if (error) throw error;
      
      if (expiredUsers.length > 0) {
        const userIds = expiredUsers.map(user => user.id);
        
        // Update to free
        await supabase
          .from('users')
          .update({ premium_status: 'free' })
          .in('id', userIds);
        
        console.log(`📉 Downgraded ${userIds.length} expired subscriptions`);
      }
      
    } catch (error) {
      console.error('Subscription check error:', error);
    }
  }
  
  async cleanupOldPayments() {
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      const { error } = await supabase
        .from('payments')
        .delete()
        .lt('created_at', thirtyDaysAgo.toISOString())
        .neq('status', 'completed');
      
      if (error) throw error;
      
    } catch (error) {
      console.error('Cleanup error:', error);
    }
  }
  
  async checkPendingPayments() {
    try {
      // Logic to verify pending payments
      // Could integrate with payment service
      console.log('Pending payments check completed');
      
    } catch (error) {
      console.error('Pending payments check error:', error);
    }
  }
}

module.exports = new CronService();