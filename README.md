# Vulnarable Web App

> **Intentionally Vulnerable Web Application for Security Education**

[![Node.js](https://img.shields.io/badge/Node.js-20+-green)](https://nodejs.org)
[![Express](https://img.shields.io/badge/Express-4.x-blue)](https://expressjs.com)
[![SQLite](https://img.shields.io/badge/Database-SQLite-orange)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-Educational-red)]()

---

> **CẢNH BÁO:** App này được cố tình tạo ra với nhiều lỗ hổng bảo mật nghiêm trọng.  
> **TUYỆT ĐỐI KHÔNG** deploy lên internet hoặc môi trường production.  
> Chỉ sử dụng trên máy local hoặc môi trường học tập có kiểm soát.

---

## Mục tiêu

Vulnarable Web App là một ứng dụng web được cố ý viết với các lỗ hổng bảo mật phổ biến nhất theo **OWASP Top 10**, giúp người học:

- Hiểu cách các lỗ hổng bảo mật hoạt động trong thực tế
- Thực hành khai thác trong môi trường an toàn
- Học cách fix từng loại lỗ hổng
- Làm quen với các công cụ như BurpSuite

---

## Cấu trúc Project

```
vuln-web-app/
│
├── app/                     # Source code chính
│   ├── server.js            # Main server (Express)
│   ├── package.json
│   ├── public/
│   │   ├── css/style.css    # Stylesheet
│   │   └── uploads/         # Uploaded files (writable)
│   └── views/               # EJS templates
│       ├── index.ejs
│       ├── login.ejs
│       ├── comments.ejs     # XSS point
│       ├── profile.ejs      # IDOR point
│       ├── upload.ejs       # File upload point
│       ├── search.ejs       # SQLi point
│       ├── change-password.ejs  # CSRF point
│       └── partials/
│
├── database/
│   ├── init.sql             # Schema + seed data
│   └── vuln.db              # SQLite database (auto-created)
│
├── writeups/                # Hướng dẫn khai thác
│   ├── sql-injection.md
│   ├── xss.md
│   ├── file-upload.md
│   ├── idor.md
│   ├── broken-auth.md
│   └── csrf.md
│
├── docker-compose.yml
├── Dockerfile
├── setup.sh
└── README.md
```

---

## Cài Đặt & Chạy

### Yêu cầu

- Node.js >= 18
- npm

### Cách 1: Script tự động

```bash
git clone <repo-url>
cd vuln-web-app
chmod +x setup.sh
./setup.sh

# Sau đó chạy:
cd app
node server.js
```

### Cách 2: Thủ công

```bash
cd vuln-web-app/app
npm install
node server.js
```

### Cách 3: Docker

```bash
docker-compose up
```

**Mở trình duyệt:** `http://localhost:3000`

---

## Tài khoản Test

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin123 | admin |
| user     | 123456   | user  |
| alice    | alice2024| user  |
| bob      | bob2024  | user  |

---

## Danh Sách Lỗ Hổng

### 1. SQL Injection — `/login`, `/search`

Câu query được build bằng string concatenation, không dùng parameterized query.

**Payload login bypass:**
```
Username: ' OR 1=1 --
Password: anything
```

**Payload dump database (search box):**
```
' UNION SELECT id,username,password,email,role,bio,avatar,created_at FROM users --
```

[Writeup đầy đủ](./writeups/sql-injection.md)

---

### 2. XSS (Cross-Site Scripting) — `/comments`

Comment được lưu raw và render bằng `<%- %>` (unescaped) trong EJS.

**Payload:**
```html
<script>alert(document.cookie)</script>
<img src=x onerror="alert('XSS')">
```

[Writeup đầy đủ](./writeups/xss.md)

---

### 3. Unrestricted File Upload — `/upload`

Không có validation về loại file, extension, hoặc content.

**Attack:** Upload file `.html` hoặc `.svg` chứa JavaScript -> browser execute khi truy cập.

[Writeup đầy đủ](./writeups/file-upload.md)

---

### 4. Broken Authentication — Login system

- Password lưu **plaintext** trong SQLite
- Session secret: `"123456"` (cực kỳ yếu)
- Cookie `httpOnly: false` -> JS đọc được
- Không có rate limiting -> brute force

[Writeup đầy đủ](./writeups/broken-auth.md)

---

### 5. IDOR (Insecure Direct Object Reference) — `/profile?id=X`

Không có authorization check — bất kỳ user nào cũng có thể xem profile của người khác bằng cách thay số ID.

**Attack:** `/profile?id=1` -> xem profile admin

[Writeup đầy đủ](./writeups/idor.md)

---

### 6. CSRF — `/change-password`

Form đổi password không có CSRF token. Không yêu cầu nhập password hiện tại.

**Attack:** Tạo trang HTML tự submit form đến `/change-password` khi nạn nhân truy cập.

[Writeup đầy đủ](./writeups/csrf.md)

---

## Vulnerability Map

```
http://localhost:3000/
│
├── /login              <- SQL Injection (login bypass)
├── /search             <- SQL Injection (UNION-based dump)
├── /comments           <- Stored XSS
├── /upload             <- Unrestricted File Upload
├── /profile?id=X       <- IDOR
├── /change-password    <- CSRF + Broken Auth
└── /debug/session      <- Information Disclosure
```

---

## Quick Test Checklist

- [ ] SQL Injection login bypass: `' OR 1=1 --`
- [ ] SQL Injection data dump via search UNION
- [ ] XSS stored payload: `<script>alert(1)</script>`
- [ ] XSS cookie theft: `<img src=x onerror="alert(document.cookie)">`
- [ ] Upload file `.html` với script, truy cập URL
- [ ] IDOR: `/profile?id=1` khi đang login là user
- [ ] Cookie theft → paste vào browser → session hijack
- [ ] CSRF: tạo form tự submit đổi password

---

## Công Cụ Khuyến Nghị

| Tool | Dùng cho |
|------|---------|
| **BurpSuite Community** | Intercept, modify, replay requests |
| **Firefox DevTools** | Inspect cookies, DOM, network |
| **curl / httpie** | Command-line HTTP requests |
| **sqlmap** | Automated SQLi testing |
| **DirBuster / gobuster** | Directory enumeration |

---

## Học Thêm

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) (free!)
- [HackTheBox](https://hackthebox.com)
- [TryHackMe](https://tryhackme.com)
- [PentesterLab](https://pentesterlab.com)

---

## Legal & Ethics

App này **chỉ dành cho mục đích học tập**. Việc tấn công hệ thống thực không có phép là **vi phạm pháp luật**. Chỉ test trên hệ thống bạn sở hữu hoặc có sự cho phép rõ ràng.

---

*Made for security education*