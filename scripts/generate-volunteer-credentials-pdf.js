/**
 * Set unique name-based passwords and write PRASAR login credentials PDF (admins + volunteers).
 *
 * Usage: node scripts/generate-volunteer-credentials-pdf.js
 */
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const fs = require("fs");
const path = require("path");
const PDFDocument = require("pdfkit");
const { Pool } = require("pg");
const leads = require("../src/leads");
const importGuest = require("./import-guest-list");
const { hashUserPassword, buildPassword } = require("./credential-passwords");

const APP_URL = String(process.env.PUBLIC_APP_URL || "https://prasar.vercel.app").replace(/\/$/, "");

function drawTable(doc, title, rows, startY) {
  let y = startY ?? doc.y;
  doc.font("Helvetica-Bold").fontSize(11).fillColor("#111111").text(title, 48, y);
  y += 20;

  const colName = 48;
  const colEmail = 220;
  const colPass = 420;
  const rowH = 18;

  doc.font("Helvetica-Bold").fontSize(9);
  doc.text("Name", colName, y, { width: 165 });
  doc.text("Login email", colEmail, y, { width: 190 });
  doc.text("Password", colPass, y, { width: 120 });
  y += rowH;
  doc.moveTo(colName, y).lineTo(552, y).strokeColor("#cccccc").stroke();
  y += 6;

  doc.font("Helvetica").fontSize(8.5);
  for (const row of rows) {
    if (y > 720) {
      doc.addPage();
      y = 48;
    }
    doc.text(row.full_name, colName, y, { width: 165 });
    doc.text(row.email, colEmail, y, { width: 190 });
    doc.font("Helvetica-Bold").text(row.password, colPass, y, { width: 120 });
    doc.font("Helvetica");
    y += rowH;
  }
  doc.y = y + 12;
}

async function loadVolunteersFromSheet() {
  const xlsxPath = path.join(__dirname, "..", "public", "FINAL PR GUEST LIST - Copy.xlsx");
  const rawRows = importGuest.loadRows(xlsxPath).filter((row) => row.fullName || row.organization || row.email);
  const prepared = rawRows.map((row, i) => ({
    karyakarName: importGuest.clean(row.karyakarName, 200),
    fullName: importGuest.clean(row.fullName || row.organization || `Imported Guest ${i + 1}`, 120),
  }));
  const plan = leads.planGuestImport(prepared);
  return plan.volunteers
    .map((volunteer) => ({ full_name: volunteer.fullName, email: volunteer.email, role: "KARYAKAR" }))
    .sort((a, b) => a.full_name.localeCompare(b.full_name));
}

async function loadAccounts() {
  if (!process.env.DATABASE_URL) {
    const volunteers = await loadVolunteersFromSheet();
    const admins = [
      { full_name: "Hemant Patel", email: "hemant.patel@prasar.admin", role: "ADMIN" },
      { full_name: "Punil Patel", email: "punil.patel@prasar.admin", role: "ADMIN" },
      { full_name: "Rakesh Patel", email: "rakesh.patel@prasar.admin", role: "ADMIN" },
    ];
    return { admins, volunteers };
  }
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 1,
  });
  try {
    const admins = await pool.query(
      `SELECT id, full_name, email, 'ADMIN' AS role
       FROM users
       WHERE UPPER(TRIM(role)) = 'ADMIN' AND UPPER(TRIM(status)) = 'ACTIVE'
       ORDER BY full_name`
    );
    const volunteers = await pool.query(
      `SELECT id, full_name, email, 'KARYAKAR' AS role
       FROM users
       WHERE UPPER(TRIM(role)) = 'KARYAKAR'
         AND UPPER(TRIM(status)) = 'ACTIVE'
         AND email LIKE '%@volunteer.prasar.local'
       ORDER BY full_name`
    );
    return { admins: admins.rows, volunteers: volunteers.rows };
  } finally {
    await pool.end().catch(() => {});
  }
}

async function applyPasswords(rows) {
  if (!process.env.DATABASE_URL || process.env.APPLY_PASSWORDS === "0") return false;
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 1,
  });
  try {
    for (const row of rows) {
      let id = row.id;
      if (!id) {
        const found = await pool.query(
          `SELECT id FROM users WHERE LOWER(TRIM(email)) = LOWER(TRIM($1)) LIMIT 1`,
          [row.email]
        );
        id = found.rows[0]?.id;
      }
      if (!id) continue;
      await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
        hashUserPassword(row.password),
        id,
      ]);
    }
    return true;
  } finally {
    await pool.end().catch(() => {});
  }
}

async function main() {
  const outPath = path.resolve(process.cwd(), process.env.OUT || path.join("data", "volunteer-logins.pdf"));
  const jsonPath = outPath.replace(/\.pdf$/i, ".json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });

  const { admins, volunteers } = await loadAccounts();
  const used = new Set();
  const adminRows = admins.map((user) => ({
    id: user.id,
    full_name: user.full_name,
    email: user.email,
    role: "ADMIN",
    password: buildPassword(user.full_name, user.email, "ADMIN", used),
  }));
  const volunteerRows = volunteers.map((user) => ({
    id: user.id,
    full_name: user.full_name,
    email: user.email,
    role: "KARYAKAR",
    password: buildPassword(user.full_name, user.email, "KARYAKAR", used),
  }));
  const allRows = [...adminRows, ...volunteerRows];

  const applied = await applyPasswords(allRows);
  fs.writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        applied,
        admins: adminRows.map(({ id, role, ...rest }) => rest),
        volunteers: volunteerRows.map(({ id, role, ...rest }) => rest),
      },
      null,
      2
    ),
    "utf8"
  );

  await new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 48, size: "A4" });
    const stream = fs.createWriteStream(outPath);
    doc.pipe(stream);

    doc.font("Helvetica-Bold").fontSize(16).text("PRASAR — Login credentials", { align: "left" });
    doc.moveDown(0.4);
    doc
      .font("Helvetica")
      .fontSize(10)
      .fillColor("#333333")
      .text(`Site: ${APP_URL}`, { link: APP_URL, underline: true })
      .text(`Generated: ${new Date().toISOString().slice(0, 10)}`)
      .text("Administrators: choose Administrator on the login screen. Volunteers: choose PR Karyakar.", { width: 500 })
      .text("Keep this document confidential.", { width: 500 });

    doc.moveDown(0.8);
    drawTable(doc, "Administrators", adminRows);
    drawTable(doc, "PR Karyakar (volunteers)", volunteerRows);

    doc.font("Helvetica-Oblique").fontSize(8).fillColor("#666666").text(
      "Password format: first name + last name + unique 4 digits (e.g. HemantPatel2847).",
      { width: 500 }
    );

    doc.end();
    stream.on("finish", resolve);
    stream.on("error", reject);
  });

  console.log(
    JSON.stringify({
      ok: true,
      admins: adminRows.length,
      volunteers: volunteerRows.length,
      pdf: outPath,
      json: jsonPath,
      passwordsAppliedToDatabase: applied,
    })
  );
  process.exit(0);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
