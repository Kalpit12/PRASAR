const fs = require("fs");
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const { Pool } = require("pg");
const schemaSql = fs.readFileSync(path.join(__dirname, "..", "sql", "schema.sql"), "utf8");

function schemaStatements(sql) {
  return sql
    .replace(/--[^\n]*/g, "")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is required for Postgres connection.");
}

const isServerless = Boolean(process.env.VERCEL);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(String(process.env.DATABASE_URL || ""))
    ? false
    : { rejectUnauthorized: process.env.PGSSL_REJECT_UNAUTHORIZED === "1" },
  // Supabase pooler may close idle clients (57P01); keep fewer, shorter-lived ones.
  // Vercel functions should not hold a large pool across isolates.
  max: isServerless ? 1 : 10,
  idleTimeoutMillis: isServerless ? 5_000 : 20_000,
  connectionTimeoutMillis: 15_000,
  allowExitOnIdle: isServerless,
});

// Idle clients can be terminated by the server/pooler. Without this listener,
// Node treats the pool "error" event as unhandled and crashes the process.
pool.on("error", (err) => {
  const code = err && err.code ? String(err.code) : "";
  const msg = err && err.message ? err.message : String(err);
  if (code === "57P01" || /terminating connection/i.test(msg)) {
    console.warn("Postgres idle connection closed; pool will reconnect on next query.", code || msg);
    return;
  }
  console.error("Unexpected Postgres pool error:", code || msg);
});

async function init() {
  for (const statement of schemaStatements(schemaSql)) {
    await pool.query(statement);
  }

  await pool.query(`
    UPDATE dignitaries
    SET status = 'ACTIVE'
    WHERE status IS NULL OR UPPER(TRIM(status)) NOT IN ('ACTIVE', 'INACTIVE');

    UPDATE dignitaries
    SET approval_status = 'APPROVED'
    WHERE approval_status IS NULL OR TRIM(approval_status) = '';
  `);

  await pool.query(`
    UPDATE events
    SET status = 'PUBLISHED'
    WHERE status IS NULL OR UPPER(TRIM(status)) NOT IN ('DRAFT', 'PUBLISHED');
  `);

  await pool.query(`
    UPDATE users
    SET gender = NULL
    WHERE gender IS NOT NULL AND UPPER(TRIM(gender)) NOT IN ('MALE', 'FEMALE');
  `);

  await pool.query(`
    UPDATE invitations
    SET rsvp_channels = json_build_array(UPPER(TRIM(rsvp_status)))::text
    WHERE rsvp_status IN ('BY_WHATSAPP', 'BY_EMAIL', 'IN_PERSON', 'BY_PHONE')
      AND (
        rsvp_channels IS NULL
        OR TRIM(rsvp_channels) = ''
        OR TRIM(rsvp_channels) = '[]'
      )
  `);

  // Backfill RSVP tokens for older invitations
  await pool.query(`
    UPDATE invitations
    SET rsvp_token = encode(gen_random_bytes(18), 'hex')
    WHERE rsvp_token IS NULL OR TRIM(rsvp_token) = ''
  `).catch(async () => {
    // gen_random_bytes may be unavailable; fall back to uuid-like text
    const missing = await pool.query(
      `SELECT id FROM invitations WHERE rsvp_token IS NULL OR TRIM(rsvp_token) = ''`
    );
    for (const row of missing.rows) {
      const token = `rsvp_${row.id}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
      await pool.query(`UPDATE invitations SET rsvp_token = $1 WHERE id = $2`, [token, row.id]);
    }
  });

  // Backfill day-wise attendance from the older invitation-level flag.
  await pool.query(`
    UPDATE invitations
    SET day_attendance = json_build_object(
      '0', COALESCE(to_char(attended_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), '1')
    )::text
    WHERE attended IS TRUE
      AND (day_attendance IS NULL OR btrim(day_attendance) IN ('', '{}'))
  `);

  // Backfill day-wise ladies/gents from the older invitation-level counts.
  await pool.query(`
    UPDATE invitations
    SET day_counts = json_build_object(
      '0', json_build_object('ladies', COALESCE(ladies_count, 0), 'gents', COALESCE(gents_count, 0))
    )::text
    WHERE (COALESCE(ladies_count, 0) > 0 OR COALESCE(gents_count, 0) > 0)
      AND (day_counts IS NULL OR btrim(day_counts) IN ('', '{}'))
  `);
  await pool.query(`
    INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at)
    SELECT i.dignitary_id,
           u.id,
           CASE i.rsvp_status
             WHEN 'BY_WHATSAPP' THEN 'WHATSAPP'
             WHEN 'BY_EMAIL' THEN 'EMAIL'
             WHEN 'IN_PERSON' THEN 'VISIT'
             WHEN 'BY_PHONE' THEN 'PHONE_CALL'
           END,
           'RSVP recorded via ' ||
             CASE i.rsvp_status
               WHEN 'BY_WHATSAPP' THEN 'WhatsApp'
               WHEN 'BY_EMAIL' THEN 'Email'
               WHEN 'IN_PERSON' THEN 'in-person'
               WHEN 'BY_PHONE' THEN 'phone'
             END ||
             ' for ' || e.title || '.',
           COALESCE(i.sent_at, i.created_at, NOW())
    FROM invitations i
    JOIN dignitaries d ON d.id = i.dignitary_id
    JOIN events e ON e.id = i.event_id
    JOIN users u
      ON UPPER(TRIM(u.role)) = 'KARYAKAR'
     AND LOWER(TRIM(u.full_name)) = LOWER(TRIM(d.karyakar_name))
    WHERE i.rsvp_status IN ('BY_WHATSAPP', 'BY_EMAIL', 'IN_PERSON', 'BY_PHONE')
      AND NOT EXISTS (
        SELECT 1
        FROM communications c
        WHERE c.dignitary_id = i.dignitary_id
          AND c.user_id = u.id
          AND c.notes LIKE 'RSVP recorded via%'
          AND c.notes LIKE ('%' || e.title || '%')
      )
  `);
}

module.exports = {
  query: (text, params) => pool.query(text, params),
  init,
};
