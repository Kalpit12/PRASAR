const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const nodemailer = require("nodemailer");
const PDFDocument = require("pdfkit");
const db = require("./db");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const prototypeFile = path.join(__dirname, "..", "Prasar-Prototype.html");
const secretsFile = path.join(__dirname, "..", "data", "runtime-secrets.json");
let fileSecrets = {};
fs.mkdirSync(path.dirname(secretsFile), { recursive: true });
if (fs.existsSync(secretsFile)) {
  try {
    fileSecrets = JSON.parse(fs.readFileSync(secretsFile, "utf8"));
  } catch {
    fileSecrets = {};
  }
}
if (!fileSecrets.PRASAR_API_KEY || !fileSecrets.PRASAR_BACKUP_KEY) {
  const generated = {
    PRASAR_API_KEY: crypto.randomBytes(48).toString("base64url"),
    PRASAR_BACKUP_KEY: crypto.randomBytes(48).toString("base64url"),
    created_at: new Date().toISOString(),
  };
  fileSecrets = generated;
  fs.writeFileSync(secretsFile, JSON.stringify(generated, null, 2));
}
const API_KEY = process.env.PRASAR_API_KEY || fileSecrets.PRASAR_API_KEY || "";
const BACKUP_KEY = process.env.PRASAR_BACKUP_KEY || fileSecrets.PRASAR_BACKUP_KEY || "";
if (!API_KEY) {
  console.error("FATAL: PRASAR_API_KEY is missing. Set PRASAR_API_KEY or ensure data/runtime-secrets.json is writable.");
  process.exit(1);
}
const allowedOrigins = new Set(["http://localhost:3000", "http://127.0.0.1:3000"]);
if (process.env.RENDER_EXTERNAL_URL) allowedOrigins.add(process.env.RENDER_EXTERNAL_URL);
const backupDir = path.join(__dirname, "..", "data", "backups");
fs.mkdirSync(backupDir, { recursive: true });

console.log("PRASAR API key source:", process.env.PRASAR_API_KEY ? "env" : "data/runtime-secrets.json");
if (API_KEY) console.log("PRASAR API key: loaded (length " + API_KEY.length + ", not logged)");
console.log(
  "PRASAR backup key source:",
  process.env.PRASAR_BACKUP_KEY ? "env" : "data/runtime-secrets.json"
);

function requireApiKey(req, res, next) {
  if (!API_KEY) {
    return res.status(503).json({ error: "Server misconfigured: API key not set." });
  }
  const origin = req.header("origin") || "";
  const referer = req.header("referer") || "";
  const secFetchSite = (req.header("sec-fetch-site") || "").toLowerCase();
  const trustedOriginFromReferer = (() => {
    try {
      return new URL(referer).origin;
    } catch {
      return "";
    }
  })();
  const trustedOrigin =
    (origin && allowedOrigins.has(origin)) ||
    (trustedOriginFromReferer && allowedOrigins.has(trustedOriginFromReferer)) ||
    (!origin && (secFetchSite === "same-origin" || secFetchSite === "same-site"));

  const key = req.header("x-prasar-api-key");
  if (key === API_KEY || trustedOrigin) return next();
  return res.status(401).json({ error: "Unauthorized." });
}

app.use(
  helmet({
    contentSecurityPolicy: false,
    referrerPolicy: { policy: "no-referrer" },
  })
);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.has(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "x-prasar-api-key"],
  })
);
app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
  })
);
app.use(express.json({ limit: "256kb" }));
app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// Public health check (Render will call this without auth headers)
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.use("/api", requireApiKey);
app.use("/local-app", express.static(path.join(__dirname, "..", "public")));
app.get("/favicon.ico", (_req, res) => res.status(204).end());
app.get("/__reload-hash", (_req, res) => {
  try {
    const stat = fs.statSync(prototypeFile);
    res.json({ hash: String(stat.mtimeMs) });
  } catch {
    res.status(500).json({ error: "reload hash unavailable" });
  }
});
app.get("/", (_req, res) => {
  res.sendFile(prototypeFile);
});

const outboxDir = path.join(__dirname, "..", "data", "outbox");
fs.mkdirSync(outboxDir, { recursive: true });

const mailer = nodemailer.createTransport({
  streamTransport: true,
  newline: "unix",
  buffer: true,
});

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function badRequest(res, message) {
  return res.status(400).json({ error: message });
}

function cleanText(value, maxLen = 200) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/\s+/g, " ").slice(0, maxLen);
}
function looksLikeEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}
function slugText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ".")
    .replace(/^\.+|\.+$/g, "")
    .replace(/\.+/g, ".");
}

async function createEncryptedBackup() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const tables = ["users", "dignitaries", "events", "invitations", "communications"];
  const dump = {};
  for (const table of tables) {
    const result = await db.query(`SELECT * FROM ${table} ORDER BY id ASC`);
    dump[table] = result.rows;
  }
  const raw = Buffer.from(JSON.stringify({ created_at: new Date().toISOString(), data: dump }, null, 2), "utf8");
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  if (!BACKUP_KEY) {
    const plainPath = path.join(backupDir, `prasar-backup-${stamp}.json`);
    fs.writeFileSync(plainPath, raw);
    return { file: plainPath, hash, encrypted: false };
  }
  const iv = crypto.randomBytes(12);
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(BACKUP_KEY, salt, 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(raw), cipher.final()]);
  const tag = cipher.getAuthTag();
  const outPath = path.join(backupDir, `prasar-backup-${stamp}.enc`);
  const payload = Buffer.concat([Buffer.from("PRASAR01"), salt, iv, tag, encrypted]);
  fs.writeFileSync(outPath, payload);
  return { file: outPath, hash, encrypted: true };
}

// Users
app.get("/api/users", async (_req, res) => {
  try {
    const result = await db.query("SELECT id, full_name, email, role, status, created_at FROM users ORDER BY id DESC");
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load users." });
  }
});

app.post("/api/users", async (req, res) => {
  const { fullName, email, role, status } = req.body || {};
  if (!fullName || !email || !role) {
    return badRequest(res, "fullName, email, and role are required.");
  }
  if (!isEmail(email)) return badRequest(res, "Invalid email.");
  if (!["ADMIN", "KARYAKAR"].includes(role)) return badRequest(res, "Invalid role.");
  const safeStatus = status === "INACTIVE" ? "INACTIVE" : "ACTIVE";

  try {
    const result = await db.query(
      "INSERT INTO users (full_name, email, role, status) VALUES ($1, $2, $3, $4) RETURNING *",
      [cleanText(fullName, 120), cleanText(email, 180).toLowerCase(), role, safeStatus]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create user." });
  }
});

// Dignitaries
app.get("/api/dignitaries", async (_req, res) => {
  try {
    const result = await db.query(
      "SELECT id, full_name, email, designation, organization, created_at FROM dignitaries ORDER BY id DESC"
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load dignitaries." });
  }
});

app.post("/api/dignitaries", async (req, res) => {
  const { fullName, email, designation, organization } = req.body || {};
  if (!fullName || !email) return badRequest(res, "fullName and email are required.");
  if (!isEmail(email)) return badRequest(res, "Invalid email.");

  try {
    const result = await db.query(
      "INSERT INTO dignitaries (full_name, email, designation, organization) VALUES ($1, $2, $3, $4) RETURNING *",
      [
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        cleanText(designation, 120),
        cleanText(organization, 160),
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create dignitary." });
  }
});

app.post("/api/dignitaries/import", async (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : null;
  if (!rows) return badRequest(res, "rows[] is required.");
  if (rows.length > 5000) return badRequest(res, "Too many rows. Max 5000 per import.");

  const stats = {
    total: rows.length,
    added: 0,
    skipped: 0,
    invalid: 0,
    duplicate: 0,
    generatedEmail: 0,
    generatedName: 0,
    failed: 0,
  };

  for (let i = 0; i < rows.length; i++) {
    const raw = rows[i] || {};
    let fullName = cleanText(raw.fullName || "", 120);
    const designation = cleanText(raw.designation || "", 120);
    const organization = cleanText(raw.organization || "", 160);
    const rawEmail = cleanText(raw.email || "", 180).toLowerCase();

    // Skip totally blank rows (prevents creating fake "Imported Dignitary N" records)
    if (!fullName && !designation && !organization && !rawEmail) {
      stats.skipped++;
      continue;
    }
    if (!fullName) {
      fullName = organization || `Imported Dignitary ${i + 1}`;
      stats.generatedName++;
    }

    let email = rawEmail;
    if (!looksLikeEmail(email)) {
      const base = slugText(fullName) || `imported.${Date.now()}.${i + 1}`;
      email = `${base}@import.prasar.local`;
      stats.generatedEmail++;
    }

    let inserted = false;
    for (let attempt = 0; attempt < 5; attempt++) {
      const tryEmail = attempt === 0 ? email : `${email.split("@")[0]}+${attempt}@${email.split("@")[1] || "import.prasar.local"}`;
      try {
        const result = await db.query(
          "INSERT INTO dignitaries (full_name, email, designation, organization) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING RETURNING id",
          [fullName, tryEmail, designation, organization]
        );
        if (result.rows[0]) {
          stats.added++;
          inserted = true;
          break;
        }
      } catch {
        // keep trying next fallback email
      }
    }

    if (!inserted) {
      stats.skipped++;
      stats.duplicate++;
    }
  }

  return res.json({ ok: true, stats });
});

app.delete("/api/dignitaries/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid dignitary id.");
  try {
    const inUse = await db.query("SELECT 1 FROM invitations WHERE dignitary_id = $1 LIMIT 1", [id]);
    if (inUse.rows[0]) {
      return res.status(409).json({ error: "Cannot delete dignitary with invitations. Delete related invitations first." });
    }
    const result = await db.query("DELETE FROM dignitaries WHERE id = $1 RETURNING id", [id]);
    if (!result.rows[0]) return res.status(404).json({ error: "Dignitary not found." });
    return res.json({ ok: true, deletedId: id });
  } catch {
    return res.status(500).json({ error: "Failed to delete dignitary." });
  }
});

// Events
app.get("/api/events", async (_req, res) => {
  try {
    const result = await db.query("SELECT id, title, event_date, event_time, venue, created_at FROM events ORDER BY event_date DESC");
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load events." });
  }
});

app.post("/api/events", async (req, res) => {
  const { title, eventDate, eventTime, venue } = req.body || {};
  if (!title || !eventDate || !venue) {
    return badRequest(res, "title, eventDate, and venue are required.");
  }
  try {
    const result = await db.query("INSERT INTO events (title, event_date, event_time, venue) VALUES ($1, $2, $3, $4) RETURNING *", [
      cleanText(title, 160),
      eventDate,
      cleanText(eventTime || "", 20),
      cleanText(venue, 180),
    ]);
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create event." });
  }
});

// Invitations
app.get("/api/invitations", async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT i.id, i.custom_message, i.status, i.sent_at, i.created_at,
             d.id AS dignitary_id, d.full_name AS dignitary_name, d.email AS dignitary_email,
             e.id AS event_id, e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      ORDER BY i.id DESC
    `);
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load invitations." });
  }
});

app.post("/api/invitations", async (req, res) => {
  const { dignitaryId, eventId, customMessage } = req.body || {};
  if (!dignitaryId || !eventId) return badRequest(res, "dignitaryId and eventId are required.");
  try {
    const dignitary = await db.query("SELECT id FROM dignitaries WHERE id = $1", [dignitaryId]);
    const event = await db.query("SELECT id FROM events WHERE id = $1", [eventId]);
    if (!dignitary.rows[0] || !event.rows[0]) return badRequest(res, "Invalid dignitaryId or eventId.");

    const result = await db.query(
      "INSERT INTO invitations (dignitary_id, event_id, custom_message) VALUES ($1, $2, $3) RETURNING *",
      [dignitaryId, eventId, cleanText(customMessage, 2000)]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create invitation." });
  }
});

app.get("/api/invitations/:id/preview", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.designation, d.organization, d.email,
             e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = $1
    `, [req.params.id]);
    const invite = result.rows[0];
    if (!invite) return res.status(404).json({ error: "Invitation not found." });
    return res.json(invite);
  } catch {
    return res.status(500).json({ error: "Failed to preview invitation." });
  }
});

app.get("/api/invitations/:id/pdf", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.designation, d.organization, d.email,
             e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = $1
    `, [req.params.id]);
    const invite = result.rows[0];
    if (!invite) return res.status(404).json({ error: "Invitation not found." });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename=invitation-${invite.id}.pdf`);

    const doc = new PDFDocument({ size: "A4", margin: 50 });
    doc.pipe(res);
    doc.fontSize(20).text("PRASAR Invitation", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`To: ${invite.dignitary_name}`);
    doc.text(`Email: ${invite.email}`);
    doc.text(`Designation: ${invite.designation || "-"}`);
    doc.text(`Organization: ${invite.organization || "-"}`);
    doc.moveDown();
    doc.text(`Event: ${invite.event_title}`);
    doc.text(`Date: ${invite.event_date}`);
    doc.text(`Venue: ${invite.venue}`);
    doc.moveDown();
    doc.text("Message:");
    doc.text(invite.custom_message || "You are cordially invited.", { lineGap: 4 });
    doc.end();
  } catch {
    return res.status(500).json({ error: "Failed to render PDF." });
  }
});

app.post("/api/invitations/:id/send-email", async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return badRequest(res, "userId is required.");
  const sender = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
  if (!sender.rows[0]) return badRequest(res, "Invalid userId.");

  const inviteResult = await db.query(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.email,
             e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = $1
    `, [req.params.id]);
  const invite = inviteResult.rows[0];
  if (!invite) return res.status(404).json({ error: "Invitation not found." });

  const subject = `Invitation: ${invite.event_title}`;
  const html = `
    <h2>PRASAR Invitation</h2>
    <p>Dear ${invite.dignitary_name},</p>
    <p>${invite.custom_message || "You are cordially invited to this event."}</p>
    <p><strong>Event:</strong> ${invite.event_title}<br/>
    <strong>Date:</strong> ${invite.event_date}<br/>
    <strong>Venue:</strong> ${invite.venue}</p>
  `;

  const info = await mailer.sendMail({
    from: "prasar-local@localhost",
    to: invite.email,
    subject,
    html,
  });

  const emlPath = path.join(outboxDir, `invitation-${invite.id}-${Date.now()}.eml`);
  fs.writeFileSync(emlPath, info.message);

  await db.query("UPDATE invitations SET status = 'SENT', sent_at = NOW() WHERE id = $1", [invite.id]);
  const dignitaryIdResult = await db.query("SELECT dignitary_id FROM invitations WHERE id = $1", [invite.id]);
  await db.query(
    "INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES ($1, $2, $3, $4, NOW())",
    [dignitaryIdResult.rows[0].dignitary_id, userId, "EMAIL", `Invitation email generated locally for ${invite.event_title}`]
  );

  res.json({ ok: true, outboxFile: path.basename(emlPath) });
});

// Communications
app.get("/api/communications", async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT c.id, c.type, c.notes, c.happened_at, c.created_at,
             d.full_name AS dignitary_name,
             u.full_name AS user_name
      FROM communications c
      JOIN dignitaries d ON d.id = c.dignitary_id
      JOIN users u ON u.id = c.user_id
      ORDER BY c.happened_at DESC, c.id DESC
    `);
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load communications." });
  }
});

app.post("/api/communications", async (req, res) => {
  const { dignitaryId, userId, type, notes, happenedAt } = req.body || {};
  if (!dignitaryId || !userId || !type || !notes || !happenedAt) {
    return badRequest(res, "dignitaryId, userId, type, notes, happenedAt are required.");
  }
  const allowedTypes = ["PHONE_CALL", "WHATSAPP", "EMAIL", "VISIT", "PDF_SENT", "GIFT"];
  if (!allowedTypes.includes(type)) return badRequest(res, "Invalid communication type.");
  const dignitary = await db.query("SELECT id FROM dignitaries WHERE id = $1", [dignitaryId]);
  const user = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
  if (!dignitary.rows[0] || !user.rows[0]) return badRequest(res, "Invalid dignitaryId or userId.");
  const dt = new Date(happenedAt);
  if (Number.isNaN(dt.getTime())) return badRequest(res, "Invalid happenedAt date.");

  try {
    const result = await db.query(
      "INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [dignitaryId, userId, type, cleanText(notes, 3000), dt.toISOString()]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create communication." });
  }
});

app.post("/api/system/backup", async (_req, res) => {
  try {
    const details = await createEncryptedBackup();
    if (!details) return res.status(404).json({ error: "Database backup source not found." });
    return res.json({
      ok: true,
      backupFile: path.basename(details.file),
      sha256: details.hash,
      encrypted: details.encrypted,
    });
  } catch (_err) {
    return res.status(500).json({ error: "Backup failed." });
  }
});

setInterval(() => {
  createEncryptedBackup()
    .then((details) => {
      if (details) console.log(`Backup created: ${path.basename(details.file)}`);
    })
    .catch(() => {
      console.error("Scheduled backup failed.");
    });
}, 6 * 60 * 60 * 1000);

app.use((_req, res) => {
  res.status(404).json({ error: "Not found." });
});

app.use((err, _req, res, _next) => {
  if (String(err.message || "").includes("CORS blocked")) {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  return res.status(500).json({ error: "Internal server error." });
});

db
  .init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PRASAR server running at port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database schema:", err.message);
    process.exit(1);
  });
