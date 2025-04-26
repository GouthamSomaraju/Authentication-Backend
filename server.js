const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// 🌐 Enable frontend connection
app.use(cors());
app.use(express.json());

// ✅ Create async MySQL connection
let db;

async function connectToDatabase() {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      ssl: {
        rejectUnauthorized: false // 👉 needed if using Render or cloud-hosted DB with SSL
      }
    });

    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
      )
    `);

    console.log('✅ MySQL connected and users table ready');
  } catch (error) {
    console.error('❌ MySQL connection error:', error.message);
    process.exit(1); // Stop server if DB fails
  }
}

// 🔐 Signup Route
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  console.log('📥 Signup request:', req.body);

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('❌ Signup error:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ message: 'Email already exists' });
    } else {
      res.status(500).json({ message: 'Internal server error' });
    }
  }
});

// 🔓 Login Route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('📥 Login request:', req.body);

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, users[0].password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    res.status(200).json({ message: 'Login successful' });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ✅ Health check (optional)
app.get('/', (req, res) => {
  res.send('✅ Auth API is running');
});

// 🚀 Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  connectToDatabase(); // connect DB when server starts
});
