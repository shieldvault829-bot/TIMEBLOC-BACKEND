// services/badgeService.js - COMPLETE BADGE SYSTEM
const { supabase } = require('../config/supabase');

class BadgeService {
  constructor() {
    this.badgeTypes = {
      REFERRAL: 'referral',
      CREATOR: 'creator',
      SUBSCRIPTION: 'subscription',
      MONTHLY_TOP: 'monthly_top',
      LIFETIME_REFERRAL: 'lifetime_referral'
    };
  }

  async awardBadge(userId, badgeType, metadata = {}) {
    try {
      // Get badge details
      const { data: badge, error } = await supabase
        .from('badges')
        .select('*')
        .eq('type', badgeType)
        .single();

      if (error || !badge) {
        console.error('Badge not found:', badgeType);
        return { success: false, error: 'Badge not found' };
      }

      // Check if user already has this badge
      const { data: existing } = await supabase
        .from('user_badges')
        .select('id')
        .eq('user_id', userId)
        .eq('badge_id', badge.id)
        .eq('is_active', true)
        .single();

      if (existing) {
        return { success: true, message: 'Badge already awarded', badge };
      }

      // Award badge
      const { data: userBadge, error: awardError } = await supabase
        .from('user_badges')
        .insert([{
          user_id: userId,
          badge_id: badge.id,
          earned_at: new Date().toISOString(),
          metadata: metadata
        }])
        .select()
        .single();

      if (awardError) throw awardError;

      // Update user badges array
      await supabase.rpc('append_to_array', {
        table_name: 'users',
        column_name: 'badges',
        row_id: userId,
        value_to_append: badge.id
      });

      // Send notification
      await this.sendBadgeNotification(userId, badge);

      return { 
        success: true, 
        message: 'Badge awarded successfully',
        badge: badge,
        userBadge: userBadge
      };

    } catch (error) {
      console.error('Badge award error:', error);
      return { success: false, error: error.message };
    }
  }

  async checkMonthlyBadges() {
    try {
      // Get top monthly referrer
      const { data: topReferrer } = await supabase
        .from('users')
        .select('id, name, monthly_referrals_count')
        .order('monthly_referrals_count', { ascending: false })
        .limit(1)
        .single();

      if (topReferrer && topReferrer.monthly_referrals_count > 0) {
        await this.awardBadge(topReferrer.id, this.badgeTypes.MONTHLY_TOP, {
          referrals: topReferrer.monthly_referrals_count,
          month: new Date().getMonth(),
          year: new Date().getFullYear()
        });
      }

      // Get top creator (most posts this month)
      const currentMonth = new Date().getMonth();
      const currentYear = new Date().getFullYear();
      
      const { data: topCreator } = await supabase
        .rpc('get_top_creator_this_month', {
          p_month: currentMonth + 1,
          p_year: currentYear
        });

      if (topCreator && topCreator.posts_count > 0) {
        await this.awardBadge(topCreator.user_id, this.badgeTypes.CREATOR, {
          posts_count: topCreator.posts_count,
          month: currentMonth,
          year: currentYear
        });
      }

      return { success: true, message: 'Monthly badges checked' };
    } catch (error) {
      console.error('Monthly badge check error:', error);
      return { success: false, error: error.message };
    }
  }

  async sendBadgeNotification(userId, badge) {
    try {
      await supabase
        .from('notifications')
        .insert([{
          user_id: userId,
          type: 'badge_awarded',
          title: 'New Badge Unlocked! 🏆',
          message: `You earned the "${badge.name}" badge!`,
          data: { badge_id: badge.id, badge_name: badge.name }
        }]);
    } catch (error) {
      console.error('Badge notification error:', error);
    }
  }

  async getUserBadges(userId) {
    try {
      const { data: badges, error } = await supabase
        .from('user_badges')
        .select(`
          *,
          badge:badges(*)
        `)
        .eq('user_id', userId)
        .eq('is_active', true)
        .order('earned_at', { ascending: false });

      if (error) throw error;

      return { success: true, badges };
    } catch (error) {
      console.error('Get user badges error:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new BadgeService();