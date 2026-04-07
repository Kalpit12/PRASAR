const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const dbPath = path.join(__dirname, "..", "data", "prasar.db");
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('ADMIN', 'KARYAKAR')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'INACTIVE')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  event_date TEXT NOT NULL,
  venue TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dignitaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  designation TEXT,
  organization TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS invitations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dignitary_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  custom_message TEXT,
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT', 'SENT')),
  sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (dignitary_id) REFERENCES dignitaries(id) ON DELETE RESTRICT,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS communications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dignitary_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('PHONE_CALL', 'WHATSAPP', 'EMAIL', 'VISIT', 'PDF_SENT', 'GIFT')),
  notes TEXT NOT NULL,
  happened_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (dignitary_id) REFERENCES dignitaries(id) ON DELETE RESTRICT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
);
`);

module.exports = db;
