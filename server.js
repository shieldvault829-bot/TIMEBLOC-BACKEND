const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// ✅ HEALTH CHECK MUST BE FIRST - NO MIDDLEWARE BEFORE
app.get('/', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        service: 'TimeBloc Backend',
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        timestamp: new Date().toISOString()
    });
});

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple CORS
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// Test route
app.get('/test', (req, res) => {
    res.json({ message: 'API is working' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Health check: http://0.0.0.0:${PORT}/health`);
    console.log(`✅ Home: http://0.0.0.0:${PORT}/`);
});
 