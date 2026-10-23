require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
/**
 * Load public/FINAL PR GUEST LIST - Copy.xlsx into Postgres.
 * Creates one karyakar account per person named in BAPS appointed lead.
 *
 * Usage: DATABASE_URL=... node scripts/import-guest-list.js
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");
const { Pool } = require("pg");
const leads = require("../src/leads");
const { clearAllGuestData } = require("../src/clear-guests");

const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };
function hashUserPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 64, SCRYPT_OPTS);
  return `v1$${salt.toString("base64")}$${hash.toString("base64")}`;
}
function slugText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .replace(/\.+/g, ".");
}
function clean(value, max) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, max);
}

function loadRows(xlsxPath) {
  const out = path.join(process.env.TEMP || "/tmp", "prasar-xlsx-import");
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  execFileSync("tar", ["-xf", xlsxPath, "-C", out]);
  const sstXml = fs.readFileSync(path.join(out, "xl", "sharedStrings.xml"), "utf8");
  const sheetXml = fs.readFileSync(path.join(out, "xl", "worksheets", "sheet1.xml"), "utf8");
  const strings = [];
  for (const match of sstXml.matchAll(/<si>([\s\S]*?)<\/si>/g)) {
    strings.push(
      [...match[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)]
        .map((part) =>
          part[1]
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
        )
        .join("")
    );
  }
  const rows = new Map();
  for (const cell of sheetXml.matchAll(/<c r="([A-Z]+)(\d+)"([^>]*)>(?:<v>([\s\S]*?)<\/v>)?/g)) {
    const col = [...cell[1]].reduce((n, ch) => n * 26 + (ch.charCodeAt(0) - 64), 0);
    const rowNum = Number(cell[2]);
    let value = cell[4] == null ? "" : cell[4];
    if (cell[3].includes('t="s"')) value = strings[Number(value)] || "";
    if (!rows.has(rowNum)) rows.set(rowNum, []);
    rows.get(rowNum)[col - 1] = String(value).replace(/\s+/g, " ").trim();
  }
  const header = (rows.get(1) || []).map((h) => String(h || "").toLowerCase().replace(/[^a-z0-9]/g, ""));
  const idx = (name) => header.indexOf(name);
  const records = [];
  for (const rowNum of [...rows.keys()].filter((n) => n > 1).sort((a, b) => a - b)) {
    const row = rows.get(rowNum);
    const at = (name) => clean(row[idx(name)] || "", 500);
    records.push({
      guestListNo: at("no"),
      fullName: at("name"),
      organization: at("organisation"),
      designation: at("position"),
      phone: at("mobile"),
      email: at("email").toLowerCase(),
      karyakarName: at("bapsappointedlead"),
      protocolNotes: at("notes"),
    });
  }
  return records;
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  const xlsxPath = path.join(__dirname, "..", "public", "FINAL PR GUEST LIST - Copy.xlsx");
  const rawRows = loadRows(xlsxPath).filter((row) => row.fullName || row.organization || row.email);
  const prepared = rawRows.map((row, i) => {
    const fullName = row.fullName || row.organization || `Imported Guest ${i + 1}`;
    let email = row.email;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const fingerprint = crypto.createHash("sha1").update(`${fullName}|${row.organization}|${row.phone}|${row.karyakarName}|${row.protocolNotes}`).digest("hex").slice(0, 6);
      email = `${slugText(`${fullName}.${row.organization}.${row.phone}.${row.karyakarName}`) || `imported.${i + 1}`}.${fingerprint}@import.prasar.local`;
    }
    return {
      ...row,
      guestListNo: clean(row.guestListNo, 20),
      fullName: clean(fullName, 120),
      email,
      designation: clean(row.designation, 120),
      organization: clean(row.organization, 160),
      phone: clean(row.phone, 40),
      protocolNotes: clean(row.protocolNotes, 2000),
      karyakarName: clean(row.karyakarName, 200),
    };
  });
  const plan = leads.planGuestImport(prepared);
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 1 });
  await pool.query("ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS guest_list_no TEXT");
  if (process.env.REPLACE_ALL === "1") {
    await clearAllGuestData(pool);
  }
  const password = String(process.env.PRASAR_VOLUNTEER_INITIAL_PASSWORD || "").trim() || crypto.randomBytes(9).toString("base64url");
  const existing = await pool.query("SELECT id, full_name, email FROM users WHERE UPPER(TRIM(role)) = 'KARYAKAR'");
  const byKey = new Map();
  for (const user of existing.rows) {
    const key = leads.personKey(user.full_name);
    const prev = byKey.get(key);
    const prevIsSheet = prev && String(prev.email || "").endsWith("@volunteer.prasar.local");
    const userIsSheet = String(user.email || "").endsWith("@volunteer.prasar.local");
    const prevIsSlash = prev && String(prev.full_name).includes("/");
    const userIsSlash = String(user.full_name).includes("/");
    if (!prev || (prevIsSlash && !userIsSlash) || (prevIsSheet && !userIsSheet && !userIsSlash)) byKey.set(key, user);
  }
  let created = 0;
  let matched = 0;
  const keptIds = [];
  for (const volunteer of plan.volunteers) {
    const found = byKey.get(volunteer.key);
    if (found) {
      const nextEmail = String(found.email || "").endsWith("@volunteer.prasar.local") ? volunteer.email : found.email;
      if (found.full_name !== volunteer.fullName || found.email !== nextEmail) {
        await pool.query("UPDATE users SET full_name = $1, email = $2 WHERE id = $3", [volunteer.fullName, nextEmail, found.id]);
      }
      keptIds.push(found.id);
      matched++;
      continue;
    }
    const inserted = await pool.query(
      `INSERT INTO users (full_name, email, role, status, password_hash)
       VALUES ($1, $2, 'KARYAKAR', 'ACTIVE', $3)
       ON CONFLICT (email) DO NOTHING
       RETURNING id`,
      [volunteer.fullName, volunteer.email, hashUserPassword(password)]
    );
    if (inserted.rows[0]) {
      keptIds.push(inserted.rows[0].id);
      created++;
    } else matched++;
  }
  if (keptIds.length) {
    await pool.query(
      `DELETE FROM users
       WHERE UPPER(TRIM(role)) = 'KARYAKAR'
         AND email LIKE '%@volunteer.prasar.local'
         AND NOT (id = ANY($1::bigint[]))`,
      [keptIds]
    );
  }

  if (process.env.REPLACE_ALL !== "1") {
    await pool.query("DELETE FROM dignitaries WHERE email LIKE '%@import.prasar.local'");
  }
  let added = 0;
  let updated = 0;
  for (const guest of plan.guests) {
    const result = await pool.query(
      `INSERT INTO dignitaries (
         full_name, email, designation, organization, phone, category,
         karyakar_name, karyakar_name_secondary, karyakar_name_tertiary, protocol_notes, guest_list_no
       ) VALUES ($1, $2, $3, $4, $5, 'Government', $6, $7, $8, $9, $10)
       ON CONFLICT (email) DO UPDATE SET
         full_name = EXCLUDED.full_name,
         karyakar_name = EXCLUDED.karyakar_name,
         karyakar_name_secondary = EXCLUDED.karyakar_name_secondary,
         karyakar_name_tertiary = EXCLUDED.karyakar_name_tertiary,
         designation = CASE WHEN EXCLUDED.designation <> '' THEN EXCLUDED.designation ELSE dignitaries.designation END,
         organization = CASE WHEN EXCLUDED.organization <> '' THEN EXCLUDED.organization ELSE dignitaries.organization END,
         phone = COALESCE(EXCLUDED.phone, dignitaries.phone),
         protocol_notes = CASE WHEN EXCLUDED.protocol_notes <> '' THEN EXCLUDED.protocol_notes ELSE dignitaries.protocol_notes END,
         guest_list_no = COALESCE(EXCLUDED.guest_list_no, dignitaries.guest_list_no)
       RETURNING (xmax = 0) AS inserted`,
      [
        guest.fullName,
        guest.email,
        guest.designation || "",
        guest.organization || "",
        guest.phone || null,
        guest.karyakarName || null,
        guest.karyakarNameSecondary || null,
        guest.karyakarNameTertiary || null,
        guest.protocolNotes || "",
        guest.guestListNo || null,
      ]
    );
    if (result.rows[0] && result.rows[0].inserted) added++;
    else updated++;
  }

  const totals = await pool.query("SELECT COUNT(*)::int AS guests FROM dignitaries");
  const sample = await pool.query(
    `SELECT karyakar_name, COUNT(*)::int AS guests
     FROM dignitaries
     WHERE karyakar_name IS NOT NULL AND karyakar_name <> ''
     GROUP BY karyakar_name
     ORDER BY guests DESC, karyakar_name
     LIMIT 8`
  );
  console.log(JSON.stringify({
    replaceAll: process.env.REPLACE_ALL === "1",
    guests: plan.guests.length,
    volunteers: plan.volunteers.length,
    created,
    matched,
    added,
    updated,
    guestTotal: totals.rows[0].guests,
    sample: sample.rows,
  }));
  pool.end().catch(() => {});
  process.exit(0);
}

module.exports = { loadRows, clean, slugText, hashUserPassword };

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
