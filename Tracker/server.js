const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection for Replit
// Replit provides PostgreSQL database via their workspace
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/ticketmanager',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'ticketmanager-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize database tables
async function initializeDatabase() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        uuid TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        name TEXT,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Allowed emails table (whitelist)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS allowed_emails (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        added_by INTEGER,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(added_by) REFERENCES users(id)
      )
    `);
    
    // Create default admin user if not exists
    const adminEmail = 'nidhin@platinumrx.in';
    const adminPassword = bcrypt.hashSync('Nidhin@007', 10);
    
    const userResult = await pool.query(
      "SELECT id FROM users WHERE email = $1", 
      [adminEmail]
    );
    
    if (userResult.rows.length === 0) {
      const newUser = await pool.query(
        "INSERT INTO users (uuid, email, password, name, role) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        [uuidv4(), adminEmail, adminPassword, 'Admin User', 'admin']
      );
      
      // Add admin email to whitelist
      await pool.query(
        "INSERT INTO allowed_emails (email, added_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING",
        [adminEmail, newUser.rows[0].id]
      );
      
      console.log("Admin user created successfully");
    }
    
    console.log("Database initialized successfully");
  } catch (error) {
    console.error("Error initializing database:", error);
  }
}

// Initialize database when server starts
initializeDatabase();

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Admin middleware
const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Check if email is whitelisted
    const allowedEmailResult = await pool.query(
      "SELECT * FROM allowed_emails WHERE email = $1", 
      [email]
    );
    
    if (allowedEmailResult.rows.length === 0) {
      return res.status(401).json({ error: 'Your email is not authorized to access this system. Please contact administrator.' });
    }
    
    // Check user credentials
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1", 
      [email]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = userResult.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Set session
    req.session.user = {
      id: user.id,
      uuid: user.uuid,
      email: user.email,
      name: user.name,
      role: user.role
    };
    
    if (rememberMe) {
      req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    }
    
    res.json({ 
      message: 'Login successful',
      user: req.session.user
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});

// Get current user
app.get('/api/user', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// Serve static files from public directory
app.use(express.static('public'));

// For all other routes, serve the main app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`TicketManager server running on port ${PORT}`);
  console.log(`Open in browser: https://${process.env.REPL_SLUG}.${process.env.REPL_OWNER}.repl.co`);
});
