/**
 * Create Hemant / Punil / Rakesh admin accounts and remove demo admin.
 * Passwords are set when you run generate-volunteer-credentials-pdf.js (same PDF as volunteers).
 *
 * Usage: node scripts/setup-admin-accounts.js
 */
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const { Pool } = require("pg");

const ADMINS = [
  { fullName: "Hemant Patel", email: "hemant.patel@prasar.admin" },
  { fullName: "Punil Patel", email: "punil.patel@prasar.admin" },
  { fullName: "Rakesh Patel", email: "rakesh.patel@prasar.admin" },
];

const DEMO_ADMIN_EMAILS = ["admin@prasar.test", "admin@prasar.local"];

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 1,
  });

  const upserted = [];
  for (const admin of ADMINS) {
    const result = await pool.query(
      `INSERT INTO users (full_name, email, role, status)
       VALUES ($1, $2, 'ADMIN', 'ACTIVE')
       ON CONFLICT (email) DO UPDATE SET
         full_name = EXCLUDED.full_name,
         role = 'ADMIN',
         status = 'ACTIVE'
       RETURNING id, full_name, email`,
      [admin.fullName, admin.email]
    );
    upserted.push(result.rows[0]);
  }

  const removed = await pool.query(
    `DELETE FROM users
     WHERE UPPER(TRIM(role)) = 'ADMIN'
       AND (
         LOWER(TRIM(email)) = ANY($1::text[])
         OR LOWER(TRIM(full_name)) IN ('administrator', 'admin user')
       )
     RETURNING id, full_name, email`,
    [DEMO_ADMIN_EMAILS.map((e) => e.toLowerCase())]
  );

  console.log(JSON.stringify({ admins: upserted, removed: removed.rows }, null, 2));
  await pool.end().catch(() => {});
  process.exit(0);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
