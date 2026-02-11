const crypto = require('crypto');

function generateOrderId(userId) {
    return `timebloc_${userId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function encryptText(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex')
    };
}

function decryptText(encryptedData, key) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        Buffer.from(key, 'hex'),
        Buffer.from(encryptedData.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function generateReferralCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `TIMEBLOC-${code}`;
}

function checkNSFW(text) {
    const nsfwKeywords = [
        'porn', 'xxx', 'adult', 'nsfw', 'sex', 'nude',
        'drugs', 'violence', 'hate', 'racist', 'gambling'
    ];
    const lowerText = text.toLowerCase();
    const matches = nsfwKeywords.filter(keyword => lowerText.includes(keyword));
    return {
        isNSFW: matches.length > 0,
        score: matches.length / nsfwKeywords.length,
        matchedKeywords: matches
    };
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getSubscriptionFeatures(tier) {
    const features = {
        free: ['3 daily posts', 'Basic editing', '500MB storage'],
        student: ['10 daily posts', 'Advanced editing', '5GB storage', 'Student badge'],
        family: ['25 daily posts', 'Pro editing', '20GB storage', 'Family badge'],
        premium: ['Unlimited posts', 'AI editing', '50GB storage', 'Premium badge'],
        elite: ['Everything', '100GB storage', 'Team features', 'Elite badge']
    };
    return features[tier] || features.free;
}

module.exports = {
    generateOrderId,
    encryptText,
    decryptText,
    generateReferralCode,
    checkNSFW,
    formatFileSize,
    getSubscriptionFeatures
};