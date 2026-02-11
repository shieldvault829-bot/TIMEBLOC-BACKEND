const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { supabase } = require('../config/supabase');
const crypto = require('crypto');

router.post('/register', async (req, res) => {
    try {
        const { email, password, username, name } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const { data, error } = await supabase
            .from('users')
            .insert([{
                email,
                username,
                name,
                password_hash: hashedPassword
            }])
            .select()
            .single();

        if (error) throw error;

        const token = jwt.sign(
            { userId: data.id, email: data.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token, user: data });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .single();

        if (error || !user) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ success: true, token, user });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/create-payment', async (req, res) => {
    try {
        const { userId, amount, currency, product } = req.body;
        
        const orderId = `timebloc_${userId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
        
        const response = await fetch('https://api.nowpayments.io/v1/payment', {
            method: 'POST',
            headers: {
                'x-api-key': process.env.NOWPAYMENTS_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                price_amount: amount,
                price_currency: currency,
                pay_currency: 'usdt',
                order_id: orderId,
                order_description: `TimeBloc ${product}`,
                ipn_callback_url: `${process.env.BACKEND_URL}/api/ipn-webhook`,
                success_url: `${process.env.FRONTEND_URL}/payment/success`,
                cancel_url: `${process.env.FRONTEND_URL}/payment/cancel`
            })
        });

        const paymentData = await response.json();

        await supabase.from('payments').insert([{
            user_id: userId,
            order_id: orderId,
            amount,
            currency,
            status: 'pending',
            payment_id: paymentData.payment_id,
            invoice_url: paymentData.invoice_url
        }]);

        res.json({ success: true, payment: paymentData, orderId });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/create-post', async (req, res) => {
    try {
        const { userId, content, privacy, scheduled_for, hashtags, media_urls } = req.body;
        
        const postData = {
            user_id: userId,
            content,
            privacy: privacy || 'public',
            media_urls: media_urls || [],
            hashtags: hashtags || [],
            scheduled_for: scheduled_for || null,
            published_at: scheduled_for ? null : new Date().toISOString()
        };

        const { data, error } = await supabase
            .from('posts')
            .insert([postData])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, post: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (error) throw error;

        const { data: badges } = await supabase
            .from('user_badges')
            .select('badge:badges(*)')
            .eq('user_id', userId)
            .eq('is_active', true);

        const { data: posts } = await supabase
            .from('posts')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(20);

        res.json({ 
            success: true, 
            user, 
            badges: badges?.map(b => b.badge) || [],
            posts: posts || []
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/follow', async (req, res) => {
    try {
        const { followerId, followingId } = req.body;
        
        const { data, error } = await supabase
            .from('follows')
            .insert([{
                follower_id: followerId,
                following_id: followingId
            }])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, follow: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/like', async (req, res) => {
    try {
        const { userId, postId } = req.body;
        
        const { data, error } = await supabase
            .from('likes')
            .insert([{
                user_id: userId,
                post_id: postId
            }])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, like: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/create-story', async (req, res) => {
    try {
        const { userId, media_url, media_type, caption } = req.body;
        
        const { data, error } = await supabase
            .from('stories')
            .insert([{
                user_id: userId,
                media_url,
                media_type,
                caption,
                duration: 24
            }])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, story: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/referral', async (req, res) => {
    try {
        const { referrerId, referredEmail } = req.body;
        
        const { data: referredUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', referredEmail)
            .single();

        if (!referredUser) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const { data, error } = await supabase
            .from('referrals')
            .insert([{
                referrer_id: referrerId,
                referred_id: referredUser.id,
                status: 'completed'
            }])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, referral: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/upload-gallery', async (req, res) => {
    try {
        const { userId, file_name, file_url, file_type, file_size, privacy } = req.body;
        
        const { data, error } = await supabase
            .from('user_gallery')
            .insert([{
                user_id: userId,
                file_name,
                file_url,
                file_type,
                file_size,
                privacy: privacy || 'private'
            }])
            .select()
            .single();

        if (error) throw error;

        res.json({ success: true, file: data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/dashboard/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const { data: user } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        const { data: posts } = await supabase
            .from('posts')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(10);

        const { data: notifications } = await supabase
            .from('notifications')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(10);

        const { data: badges } = await supabase
            .from('user_badges')
            .select('badge:badges(*)')
            .eq('user_id', userId)
            .eq('is_active', true);

        res.json({
            success: true,
            user,
            posts: posts || [],
            notifications: notifications || [],
            badges: badges?.map(b => b.badge) || []
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.post('/ipn-webhook', async (req, res) => {
    try {
        const paymentData = req.body;
        
        const { error } = await supabase
            .from('payments')
            .update({
                status: paymentData.payment_status,
                completed_at: new Date().toISOString()
            })
            .eq('order_id', paymentData.order_id);

        if (error) throw error;

        if (paymentData.payment_status === 'finished') {
            const orderParts = paymentData.order_id.split('_');
            if (orderParts.length >= 2) {
                const userId = orderParts[1];
                const expiry = new Date();
                expiry.setMonth(expiry.getMonth() + 1);
                
                await supabase
                    .from('users')
                    .update({
                        subscription_tier: 'premium',
                        subscription_expiry: expiry.toISOString()
                    })
                    .eq('id', userId);
            }
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        service: 'TimeBloc Backend API'
    });
});

module.exports = router;