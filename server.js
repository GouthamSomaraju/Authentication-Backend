const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// 🌐 Allow frontend to connect
app.use(cors());
app.use(express.json());

// ✅ MySQL connection using pool
const db = mysql.createPool({
  host: process.env.DB_HOST,     // e.g., 'localhost' or Render DB host
  user: process.env.DB_USER,     // e.g., 'root'
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
}).promise();

// 🧪 Test connection
db.query('SELECT 1')
  .then(() => console.log('✅ Connected to MySQL database'))
  .catch((err) => console.error('❌ Database connection error:', err));

// 🧾 Create users table if not exists
const createTable = `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  )
`;

db.query(createTable)
  .then(() => console.log('✅ Users table ready'))
  .catch((err) => console.error('❌ Table creation error:', err));


// 🚀 Signup route
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  console.log('📥 Signup request:', req.body);

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
    await db.query(sql, [email, hashedPassword]);

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


// 🔐 Login route
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  console.log('📥 Login request:', req.body);

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    res.status(200).json({ message: 'Login successful' });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
