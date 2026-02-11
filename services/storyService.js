// services/storyService.js - STORIES SYSTEM
const { supabase } = require('../config/supabase');

class StoryService {
  constructor() {
    this.storyDuration = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  }

  async createStory(userId, mediaUrl, mediaType, caption = '') {
    try {
      // Check if user has active subscription for story features
      const { data: user } = await supabase
        .from('users')
        .select('subscription_tier')
        .eq('id', userId)
        .single();

      if (!user) {
        return { success: false, error: 'User not found' };
      }

      // Free users can create 3 stories per day
      if (user.subscription_tier === 'free') {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const { count } = await supabase
          .from('stories')
          .select('*', { count: 'exact', head: true })
          .eq('user_id', userId)
          .gte('created_at', today.toISOString());

        if (count >= 3) {
          return { 
            success: false, 
            error: 'Free users limited to 3 stories per day. Upgrade to premium!' 
          };
        }
      }

      // Create story
      const { data: story, error } = await supabase
        .from('stories')
        .insert([{
          user_id: userId,
          media_url: mediaUrl,
          media_type: mediaType,
          caption: caption,
          duration: 24
        }])
        .select()
        .single();

      if (error) throw error;

      // Notify followers
      await this.notifyFollowers(userId, story.id);

      return { 
        success: true, 
        story,
        message: 'Story created successfully'
      };

    } catch (error) {
      console.error('Create story error:', error);
      return { success: false, error: error.message };
    }
  }

  async getStoriesForUser(userId, viewerId = null) {
    try {
      // Get users that the current user follows
      const { data: following } = await supabase
        .from('follows')
        .select('following_id')
        .eq('follower_id', viewerId || userId);

      const followingIds = following?.map(f => f.following_id) || [];
      
      // Include current user's own stories
      followingIds.push(userId);

      // Get active stories from followed users
      const now = new Date().toISOString();
      const { data: stories, error } = await supabase
        .from('stories')
        .select(`
          *,
          user:users(id, name, username, avatar_url)
        `)
        .in('user_id', followingIds)
        .gt('expires_at', now)
        .order('created_at', { ascending: false });

      if (error) throw error;

      // Group by user
      const groupedStories = this.groupStoriesByUser(stories);

      return { success: true, stories: groupedStories };
    } catch (error) {
      console.error('Get stories error:', error);
      return { success: false, error: error.message };
    }
  }

  async viewStory(storyId, viewerId) {
    try {
      // Check if already viewed
      const { data: existingView } = await supabase
        .from('story_views')
        .select('id')
        .eq('story_id', storyId)
        .eq('viewer_id', viewerId)
        .single();

      if (existingView) {
        return { success: true, message: 'Already viewed' };
      }

      // Record view
      const { error } = await supabase
        .from('story_views')
        .insert([{
          story_id: storyId,
          viewer_id: viewerId
        }]);

      if (error) throw error;

      // Update view count
      await supabase.rpc('increment_story_views', { story_id: storyId });

      return { success: true, message: 'Story viewed' };
    } catch (error) {
      console.error('View story error:', error);
      return { success: false, error: error.message };
    }
  }

  async notifyFollowers(userId, storyId) {
    try {
      // Get followers
      const { data: followers } = await supabase
        .from('follows')
        .select('follower_id')
        .eq('following_id', userId);

      if (!followers || followers.length === 0) return;

      // Create notifications
      const notifications = followers.map(follower => ({
        user_id: follower.follower_id,
        type: 'new_story',
        title: 'New Story Available',
        message: 'Check out the new story from a user you follow!',
        data: { story_id: storyId, user_id: userId }
      }));

      await supabase
        .from('notifications')
        .insert(notifications);

    } catch (error) {
      console.error('Story notification error:', error);
    }
  }

  groupStoriesByUser(stories) {
    const grouped = {};
    
    stories.forEach(story => {
      const userId = story.user.id;
      
      if (!grouped[userId]) {
        grouped[userId] = {
          user: story.user,
          stories: []
        };
      }
      
      grouped[userId].stories.push(story);
    });

    return Object.values(grouped);
  }

  async cleanupExpiredStories() {
    try {
      const now = new Date().toISOString();
      
      const { error } = await supabase
        .from('stories')
        .delete()
        .lt('expires_at', now);

      if (error) throw error;

      console.log('Expired stories cleaned up');
      return { success: true };
    } catch (error) {
      console.error('Cleanup stories error:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new StoryService();