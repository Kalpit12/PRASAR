const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for Postgres connection.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK (role IN ('ADMIN', 'KARYAKAR')),
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      event_date TEXT NOT NULL,
      event_time TEXT,
      venue TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS dignitaries (
      id BIGSERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      designation TEXT,
      organization TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id BIGSERIAL PRIMARY KEY,
      dignitary_id BIGINT NOT NULL REFERENCES dignitaries(id) ON DELETE RESTRICT,
      event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
      custom_message TEXT,
      status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SENT')),
      sent_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS communications (
      id BIGSERIAL PRIMARY KEY,
      dignitary_id BIGINT NOT NULL REFERENCES dignitaries(id) ON DELETE RESTRICT,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      type TEXT NOT NULL CHECK (type IN ('PHONE_CALL', 'WHATSAPP', 'EMAIL', 'VISIT', 'PDF_SENT', 'GIFT')),
      notes TEXT NOT NULL,
      happened_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE events ADD COLUMN IF NOT EXISTS event_time TEXT;
  `);
}

module.exports = {
  query: (text, params) => pool.query(text, params),
  init,
};
