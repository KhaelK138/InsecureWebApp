CREATE TABLE IF NOT EXISTS comments (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   username TEXT,
   content TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0,
    admin INTEGER DEFAULT 0
);
