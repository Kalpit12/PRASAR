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
const PORT = 3000;
const prototypeFile = path.join(__dirname, "..", "Prasar-Prototype.html");
const secretsFile = path.join(__dirname, "..", "data", "runtime-secrets.json");
let fileSecrets = {};
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
  const key = req.header("x-prasar-api-key");
  if (!key || key !== API_KEY) return res.status(401).json({ error: "Unauthorized." });
  return next();
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

function createEncryptedBackup() {
  const dbPath = path.join(__dirname, "..", "data", "prasar.db");
  if (!fs.existsSync(dbPath)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const raw = fs.readFileSync(dbPath);
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  if (!BACKUP_KEY) {
    const plainPath = path.join(backupDir, `prasar-backup-${stamp}.db`);
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

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// Users
app.get("/api/users", (_req, res) => {
  const rows = db
    .prepare("SELECT id, full_name, email, role, status, created_at FROM users ORDER BY id DESC")
    .all();
  res.json(rows);
});

app.post("/api/users", (req, res) => {
  const { fullName, email, role, status } = req.body || {};
  if (!fullName || !email || !role) {
    return badRequest(res, "fullName, email, and role are required.");
  }
  if (!isEmail(email)) return badRequest(res, "Invalid email.");
  if (!["ADMIN", "KARYAKAR"].includes(role)) return badRequest(res, "Invalid role.");
  const safeStatus = status === "INACTIVE" ? "INACTIVE" : "ACTIVE";

  try {
    const result = db
      .prepare("INSERT INTO users (full_name, email, role, status) VALUES (?, ?, ?, ?)")
      .run(cleanText(fullName, 120), cleanText(email, 180).toLowerCase(), role, safeStatus);
    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    res.status(201).json(row);
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create user." });
  }
});

// Dignitaries
app.get("/api/dignitaries", (_req, res) => {
  const rows = db
    .prepare("SELECT id, full_name, email, designation, organization, created_at FROM dignitaries ORDER BY id DESC")
    .all();
  res.json(rows);
});

app.post("/api/dignitaries", (req, res) => {
  const { fullName, email, designation, organization } = req.body || {};
  if (!fullName || !email) return badRequest(res, "fullName and email are required.");
  if (!isEmail(email)) return badRequest(res, "Invalid email.");

  try {
    const result = db
      .prepare("INSERT INTO dignitaries (full_name, email, designation, organization) VALUES (?, ?, ?, ?)")
      .run(
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        cleanText(designation, 120),
        cleanText(organization, 160)
      );
    const row = db.prepare("SELECT * FROM dignitaries WHERE id = ?").get(result.lastInsertRowid);
    res.status(201).json(row);
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create dignitary." });
  }
});

// Events
app.get("/api/events", (_req, res) => {
  const rows = db
    .prepare("SELECT id, title, event_date, venue, created_at FROM events ORDER BY event_date DESC")
    .all();
  res.json(rows);
});

app.post("/api/events", (req, res) => {
  const { title, eventDate, venue } = req.body || {};
  if (!title || !eventDate || !venue) {
    return badRequest(res, "title, eventDate, and venue are required.");
  }
  const result = db
    .prepare("INSERT INTO events (title, event_date, venue) VALUES (?, ?, ?)")
    .run(cleanText(title, 160), eventDate, cleanText(venue, 180));
  const row = db.prepare("SELECT * FROM events WHERE id = ?").get(result.lastInsertRowid);
  res.status(201).json(row);
});

// Invitations
app.get("/api/invitations", (_req, res) => {
  const rows = db
    .prepare(`
      SELECT i.id, i.custom_message, i.status, i.sent_at, i.created_at,
             d.id AS dignitary_id, d.full_name AS dignitary_name, d.email AS dignitary_email,
             e.id AS event_id, e.title AS event_title, e.event_date, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      ORDER BY i.id DESC
    `)
    .all();
  res.json(rows);
});

app.post("/api/invitations", (req, res) => {
  const { dignitaryId, eventId, customMessage } = req.body || {};
  if (!dignitaryId || !eventId) return badRequest(res, "dignitaryId and eventId are required.");
  const dignitary = db.prepare("SELECT * FROM dignitaries WHERE id = ?").get(dignitaryId);
  const event = db.prepare("SELECT * FROM events WHERE id = ?").get(eventId);
  if (!dignitary || !event) return badRequest(res, "Invalid dignitaryId or eventId.");

  const result = db
    .prepare("INSERT INTO invitations (dignitary_id, event_id, custom_message) VALUES (?, ?, ?)")
    .run(dignitaryId, eventId, cleanText(customMessage, 2000));
  const row = db.prepare("SELECT * FROM invitations WHERE id = ?").get(result.lastInsertRowid);
  res.status(201).json(row);
});

app.get("/api/invitations/:id/preview", (req, res) => {
  const invite = db
    .prepare(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.designation, d.organization, d.email,
             e.title AS event_title, e.event_date, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = ?
    `)
    .get(req.params.id);
  if (!invite) return res.status(404).json({ error: "Invitation not found." });
  res.json(invite);
});

app.get("/api/invitations/:id/pdf", (req, res) => {
  const invite = db
    .prepare(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.designation, d.organization, d.email,
             e.title AS event_title, e.event_date, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = ?
    `)
    .get(req.params.id);
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
});

app.post("/api/invitations/:id/send-email", async (req, res) => {
  const { userId } = req.body || {};
  if (!userId) return badRequest(res, "userId is required.");
  const sender = db.prepare("SELECT id FROM users WHERE id = ?").get(userId);
  if (!sender) return badRequest(res, "Invalid userId.");

  const invite = db
    .prepare(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.email,
             e.title AS event_title, e.event_date, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = ?
    `)
    .get(req.params.id);
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

  db.prepare("UPDATE invitations SET status = 'SENT', sent_at = datetime('now') WHERE id = ?").run(invite.id);
  db.prepare("INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES (?, ?, ?, ?, datetime('now'))")
    .run(
      db.prepare("SELECT dignitary_id FROM invitations WHERE id = ?").get(invite.id).dignitary_id,
      userId,
      "EMAIL",
      `Invitation email generated locally for ${invite.event_title}`
    );

  res.json({ ok: true, outboxFile: path.basename(emlPath) });
});

// Communications
app.get("/api/communications", (_req, res) => {
  const rows = db
    .prepare(`
      SELECT c.id, c.type, c.notes, c.happened_at, c.created_at,
             d.full_name AS dignitary_name,
             u.full_name AS user_name
      FROM communications c
      JOIN dignitaries d ON d.id = c.dignitary_id
      JOIN users u ON u.id = c.user_id
      ORDER BY c.happened_at DESC, c.id DESC
    `)
    .all();
  res.json(rows);
});

app.post("/api/communications", (req, res) => {
  const { dignitaryId, userId, type, notes, happenedAt } = req.body || {};
  if (!dignitaryId || !userId || !type || !notes || !happenedAt) {
    return badRequest(res, "dignitaryId, userId, type, notes, happenedAt are required.");
  }
  const allowedTypes = ["PHONE_CALL", "WHATSAPP", "EMAIL", "VISIT", "PDF_SENT", "GIFT"];
  if (!allowedTypes.includes(type)) return badRequest(res, "Invalid communication type.");
  const dignitary = db.prepare("SELECT id FROM dignitaries WHERE id = ?").get(dignitaryId);
  const user = db.prepare("SELECT id FROM users WHERE id = ?").get(userId);
  if (!dignitary || !user) return badRequest(res, "Invalid dignitaryId or userId.");
  const dt = new Date(happenedAt);
  if (Number.isNaN(dt.getTime())) return badRequest(res, "Invalid happenedAt date.");

  const result = db
    .prepare("INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES (?, ?, ?, ?, ?)")
    .run(dignitaryId, userId, type, cleanText(notes, 3000), dt.toISOString());
  const row = db.prepare("SELECT * FROM communications WHERE id = ?").get(result.lastInsertRowid);
  res.status(201).json(row);
});

app.post("/api/system/backup", (_req, res) => {
  try {
    const details = createEncryptedBackup();
    if (!details) return res.status(404).json({ error: "Database file not found." });
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
  try {
    const details = createEncryptedBackup();
    if (details) console.log(`Backup created: ${path.basename(details.file)}`);
  } catch {
    console.error("Scheduled backup failed.");
  }
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

app.listen(PORT, () => {
  console.log(`PRASAR local server running at http://localhost:${PORT}`);
});
