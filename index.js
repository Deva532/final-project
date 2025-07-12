require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// Konfigurasi koneksi database
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'userdb'
};

// Middleware autentikasi
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.user = user;
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
}

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute(
    'INSERT INTO users (username, password, status, deleted) VALUES (?, ?, ?, ?)',
    [username, hashed, 'active', 0]
  );
  res.json({ message: 'User registered' });
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT * FROM users WHERE username = ? AND deleted = 0', [username]);
  if (rows.length === 0) return res.status(404).json({ message: 'User not found' });
  const valid = await bcrypt.compare(password, rows[0].password);
  if (!valid) return res.status(401).json({ message: 'Wrong password' });
  const token = jwt.sign({ id: rows[0].id, username }, process.env.JWT_SECRET || 'secret123', { expiresIn: '1h' });
  res.json({ token });
});

// Get user data
app.get('/user/:id', authMiddleware, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT id, username, status FROM users WHERE id = ? AND deleted = 0', [req.params.id]);
  res.json(rows[0]);
});

// Update user data
app.put('/user/:id', authMiddleware, async (req, res) => {
  const { username } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE users SET username = ? WHERE id = ? AND deleted = 0', [username, req.params.id]);
  res.json({ message: 'User updated' });
});

// Set user status
app.patch('/user/:id/status', authMiddleware, async (req, res) => {
  const { status } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE users SET status = ? WHERE id = ? AND deleted = 0', [status, req.params.id]);
  res.json({ message: 'Status updated' });
});

// Soft delete user
app.delete('/user/:id', authMiddleware, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE users SET deleted = 1 WHERE id = ?', [req.params.id]);
  res.json({ message: 'User soft deleted' });
});

// Menjalankan server
app.listen(3000, () => {
  console.log('API running on port 3000');
});