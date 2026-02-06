// 📁 backend/services/authService.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { supabase } = require('../config/supabase');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'timebloc-secret-key-change-in-production';
    this.saltRounds = 10;
  }
  
  async hashPassword(password) {
    try {
      return await bcrypt.hash(password, this.saltRounds);
    } catch (error) {
      throw new Error('Password hashing failed');
    }
  }
  
  async comparePassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      throw new Error('Password comparison failed');
    }
  }
  
  generateToken(userId, email) {
    return jwt.sign(
      { userId, email },
      this.jwtSecret,
      { expiresIn: '7d' }
    );
  }
  
  verifyToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
  
  async registerUser(email, password, name) {
    try {
      // Check if user exists
      const { data: existingUser } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();
      
      if (existingUser) {
        throw new Error('User already exists');
      }
      
      // Hash password
      const hashedPassword = await this.hashPassword(password);
      
      // Create user
      const { data: user, error } = await supabase
        .from('users')
        .insert([{
          email: email,
          name: name,
          password_hash: hashedPassword,
          premium_status: 'free'
        }])
        .select()
        .single();
      
      if (error) throw error;
      
      // Generate token
      const token = this.generateToken(user.id, user.email);
      
      return {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name
        },
        token: token
      };
      
    } catch (error) {
      throw error;
    }
  }
  
  async loginUser(email, password) {
    try {
      // Get user
      const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();
      
      if (error || !user) {
        throw new Error('Invalid credentials');
      }
      
      // Check password
      const passwordValid = await this.comparePassword(password, user.password_hash);
      
      if (!passwordValid) {
        throw new Error('Invalid credentials');
      }
      
      // Generate token
      const token = this.generateToken(user.id, user.email);
      
      return {
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          premium: user.premium_status === 'premium'
        },
        token: token
      };
      
    } catch (error) {
      throw error;
    }
  }
}

module.exports = new AuthService();

