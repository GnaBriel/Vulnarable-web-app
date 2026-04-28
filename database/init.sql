-- VulnWebApp - Database Initialization
-- FOR EDUCATIONAL PURPOSES ONLY - DO NOT USE IN PRODUCTION

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,        --  VULN: plaintext password
    email TEXT,
    role TEXT DEFAULT 'user',
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT 'default.png',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT NOT NULL,         --  VULN: no sanitization → XSS
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Seed Data (test users)

INSERT OR IGNORE INTO users (username, password, email, role, bio) VALUES
    ('admin',  'admin123',  'admin@vulnapp.local',  'admin', 'I am the administrator.'),
    ('user',   '123456',    'user@vulnapp.local',   'user',  'Regular user account.'),
    ('alice',  'alice2024', 'alice@vulnapp.local',  'user',  'Alice''s profile. Secret data inside!'),
    ('bob',    'bob2024',   'bob@vulnapp.local',    'user',  'Bob''s profile.');

INSERT OR IGNORE INTO posts (user_id, title, content) VALUES
    (1, 'Welcome to VulnWebApp', 'This app is intentionally vulnerable for learning purposes.'),
    (2, 'My First Post', 'Hello world! This is a test post.');

INSERT OR IGNORE INTO comments (user_id, content) VALUES
    (1, 'Great app for learning security!'),
    (2, 'I love this platform.');