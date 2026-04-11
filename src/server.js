require("dotenv").config({ quiet: true });
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const db = require("./db");
const postmark = require("./postmark");
const invitationRender = require("./invitationRender");

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
if (process.env.ALLOWED_ORIGINS) {
  for (const o of process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)) {
    allowedOrigins.add(o);
  }
}
const isProduction = process.env.NODE_ENV === "production";
/** If "0", browser requests must send x-prasar-api-key (no same-origin bypass). */
const trustSameOriginWithoutKey = process.env.PRASAR_TRUST_SAME_ORIGIN_WITHOUT_KEY !== "0";
/** Optional: require this header on POST /api/system/backup (in addition to normal API access). */
const backupHttpToken = String(process.env.PRASAR_BACKUP_HTTP_TOKEN || "").trim();

if (process.env.TRUST_PROXY === "1" || process.env.RENDER === "true" || isProduction) {
  app.set("trust proxy", 1);
}

const backupDir = path.join(__dirname, "..", "data", "backups");
fs.mkdirSync(backupDir, { recursive: true });

console.log("PRASAR API key source:", process.env.PRASAR_API_KEY ? "env" : "data/runtime-secrets.json");
if (API_KEY) console.log("PRASAR API key: loaded (length " + API_KEY.length + ", not logged)");
console.log(
  "PRASAR backup key source:",
  process.env.PRASAR_BACKUP_KEY ? "env" : "data/runtime-secrets.json"
);

function constantTimeCompareStrings(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Omit maxmem so Node uses its default (portable on small Render instances). */
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };
function hashUserPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 64, SCRYPT_OPTS);
  return `v1$${salt.toString("base64")}$${hash.toString("base64")}`;
}
function verifyUserPassword(plain, stored) {
  if (typeof stored !== "string" || !stored.startsWith("v1$")) return false;
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  try {
    const salt = Buffer.from(parts[2], "base64");
    const expected = Buffer.from(parts[3], "base64");
    const hash = crypto.scryptSync(String(plain), salt, 64, SCRYPT_OPTS);
    if (hash.length !== expected.length) return false;
    return crypto.timingSafeEqual(hash, expected);
  } catch {
    return false;
  }
}

/** true = match, false = no match, null = unknown hash format */
function verifyStoredPassword(plain, stored) {
  const s = typeof stored === "string" ? stored.trim() : "";
  if (!s) return false;
  if (s.startsWith("v1$")) return verifyUserPassword(plain, s);
  if (/^\$2[aby]\$\d{2}\$/.test(s)) {
    try {
      return bcrypt.compareSync(String(plain), s);
    } catch {
      return false;
    }
  }
  return null;
}

function normalizeLoginIdentifier(raw) {
  return String(raw || "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
}

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

  const key = req.header("x-prasar-api-key") || "";
  if (constantTimeCompareStrings(key, API_KEY)) return next();
  if (trustSameOriginWithoutKey && trustedOrigin) return next();
  return res.status(401).json({ error: "Unauthorized." });
}

app.use(
  helmet({
    contentSecurityPolicy: false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    hsts: isProduction ? { maxAge: 15552000, includeSubDomains: true } : false,
  })
);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.has(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"));
    },
    methods: ["GET", "POST", "PATCH"],
    allowedHeaders: ["Content-Type", "x-prasar-api-key", "x-prasar-backup-token"],
  })
);
app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.PRASAR_API_RATE_LIMIT_MAX || 500),
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const invitationEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.PRASAR_EMAIL_RATE_LIMIT_PER_HOUR || 120),
  message: { error: "Too many invitation emails. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(express.json({ limit: "12mb" }));
app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// Public health check (Render will call this without auth headers)
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

const karyakarLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.PRASAR_KARYAKAR_LOGIN_MAX_PER_15M || 40),
  message: { error: "Too many login attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/api/auth/karyakar-login", karyakarLoginLimiter, async (req, res) => {
  const raw =
    (typeof req.body?.identifier === "string" && req.body.identifier) ||
    (typeof req.body?.email === "string" && req.body.email) ||
    (typeof req.body?.login === "string" && req.body.login) ||
    "";
  const identifier = normalizeLoginIdentifier(raw);
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!identifier || !password) return badRequest(res, "identifier and password are required.");

  try {
    let result;
    if (isEmail(identifier)) {
      result = await db.query(
        `SELECT id, full_name, email, "role", status, assigned_area, phone, password_hash
         FROM users
         WHERE UPPER(TRIM("role")) = 'KARYAKAR' AND LOWER(TRIM(email)) = LOWER(TRIM($1))
         LIMIT 1`,
        [identifier]
      );
    } else {
      const nameKey = identifier.toLowerCase().replace(/\s+/g, " ");
      result = await db.query(
        `SELECT id, full_name, email, "role", status, assigned_area, phone, password_hash
         FROM users
         WHERE UPPER(TRIM("role")) = 'KARYAKAR'
           AND LOWER(regexp_replace(trim(full_name), '[[:space:]]+', ' ', 'g')) = $1
         LIMIT 1`,
        [nameKey]
      );
    }
    const row = result.rows[0];
    if (!row || String(row.role || "").trim().toUpperCase() !== "KARYAKAR") {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    if (row.status === "INACTIVE") {
      return res.status(403).json({ error: "This account is inactive. Contact an administrator." });
    }
    const phRaw = row.password_hash;
    if (phRaw == null || String(phRaw).trim() === "") {
      return res.status(401).json({
        error:
          "No login password is saved for this account yet. An admin must open User Management → Edit this user, set “New login password”, and Save.",
        code: "PASSWORD_NOT_SET",
      });
    }
    const ph = String(phRaw).trim();
    const match = verifyStoredPassword(password, ph);
    if (match === null) {
      return res.status(401).json({
        error:
          "The saved password uses an unsupported format. An admin must set the password again in User Management → Edit (PRASAR uses a secure hash in the app).",
        code: "PASSWORD_UNSUPPORTED_FORMAT",
      });
    }
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }
    return res.json({
      user: {
        id: row.id,
        fullName: row.full_name,
        email: row.email,
        role: "KARYAKAR",
        assignedArea: row.assigned_area || "",
        phone: row.phone || "",
        status: row.status,
      },
    });
  } catch {
    return res.status(500).json({ error: "Login failed." });
  }
});

app.use("/api", requireApiKey);
app.use("/local-app", express.static(path.join(__dirname, "..", "public")));
app.get("/favicon.ico", (_req, res) => res.status(204).end());
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

if (postmark.isConfigured()) {
  console.log("Email: Postmark enabled (POSTMARK_API_KEY set).");
} else {
  console.log("Email: Postmark not configured; invitation emails write to data/outbox (.eml). Set POSTMARK_API_KEY + POSTMARK_SENDER_EMAIL.");
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function badRequest(res, message) {
  return res.status(400).json({ error: message });
}

/** Optional client-generated PDF (jsPDF from invitation preview). Max ~10MB. */
function decodeClientInvitationPdf(pdfBase64) {
  if (typeof pdfBase64 !== "string" || !pdfBase64.trim()) return null;
  try {
    const buf = Buffer.from(pdfBase64.trim(), "base64");
    if (buf.length < 8 || buf.length > 10 * 1024 * 1024) return null;
    if (buf.slice(0, 4).toString("ascii") !== "%PDF") return null;
    return buf;
  } catch {
    return null;
  }
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
app.get("/api/reload-hash", (_req, res) => {
  try {
    const stat = fs.statSync(prototypeFile);
    res.json({ hash: String(stat.mtimeMs) });
  } catch {
    res.status(500).json({ error: "reload hash unavailable" });
  }
});

app.get("/api/users", async (_req, res) => {
  try {
    const result = await db.query(
      "SELECT id, full_name, email, role, status, phone, assigned_area, created_at FROM users ORDER BY id DESC"
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load users." });
  }
});

app.post("/api/users", async (req, res) => {
  const { fullName, email, role, status, phone, assignedArea, password } = req.body || {};
  if (!fullName || !email || !role) {
    return badRequest(res, "fullName, email, and role are required.");
  }
  if (!isEmail(email)) return badRequest(res, "Invalid email.");
  if (!["ADMIN", "KARYAKAR"].includes(role)) return badRequest(res, "Invalid role.");
  const safeStatus = status === "INACTIVE" ? "INACTIVE" : "ACTIVE";
  const phoneVal = cleanText(phone || "", 40);
  const areaVal = cleanText(assignedArea || "", 200);
  let passwordHash = null;
  if (role === "KARYAKAR") {
    if (typeof password !== "string" || password.length < 8) {
      return badRequest(res, "password is required for karyakar accounts (at least 8 characters).");
    }
    passwordHash = hashUserPassword(password);
  }

  try {
    const result = await db.query(
      `INSERT INTO users (full_name, email, role, status, phone, assigned_area, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, full_name, email, role, status, phone, assigned_area, created_at`,
      [
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        role,
        safeStatus,
        phoneVal || null,
        areaVal || null,
        passwordHash,
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create user." });
  }
});

app.patch("/api/users/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid user id.");
  const { fullName, email, role, status, phone, assignedArea, password } = req.body || {};

  try {
    const cur = await db.query("SELECT id, email FROM users WHERE id = $1", [id]);
    if (!cur.rows[0]) return res.status(404).json({ error: "User not found." });
    const nextEmail = email != null ? cleanText(String(email), 180).toLowerCase() : null;
    if (nextEmail && !isEmail(nextEmail)) return badRequest(res, "Invalid email.");
    if (nextEmail) {
      const clash = await db.query("SELECT id FROM users WHERE LOWER(email) = $1 AND id <> $2 LIMIT 1", [
        nextEmail,
        id,
      ]);
      if (clash.rows[0]) return badRequest(res, "Email already exists.");
    }

    const sets = [];
    const vals = [];
    let i = 1;
    if (fullName != null) {
      sets.push(`full_name = $${i++}`);
      vals.push(cleanText(String(fullName), 120));
    }
    if (nextEmail != null) {
      sets.push(`email = $${i++}`);
      vals.push(nextEmail);
    }
    if (role != null) {
      const r = String(role).toUpperCase();
      if (!["ADMIN", "KARYAKAR"].includes(r)) return badRequest(res, "Invalid role.");
      sets.push(`role = $${i++}`);
      vals.push(r);
    }
    if (status != null) {
      const s = String(status).toUpperCase() === "INACTIVE" ? "INACTIVE" : "ACTIVE";
      sets.push(`status = $${i++}`);
      vals.push(s);
    }
    if (phone != null) {
      sets.push(`phone = $${i++}`);
      vals.push(cleanText(String(phone), 40) || null);
    }
    if (assignedArea != null) {
      sets.push(`assigned_area = $${i++}`);
      vals.push(cleanText(String(assignedArea), 200) || null);
    }
    if (typeof password === "string" && password.length > 0) {
      if (password.length < 8) return badRequest(res, "Password must be at least 8 characters.");
      sets.push(`password_hash = $${i++}`);
      vals.push(hashUserPassword(password));
    }

    if (!sets.length) return badRequest(res, "No fields to update.");
    vals.push(id);
    const q = `UPDATE users SET ${sets.join(", ")} WHERE id = $${i} RETURNING id, full_name, email, role, status, phone, assigned_area, created_at`;
    const result = await db.query(q, vals);
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to update user." });
  }
});

// Dignitaries
app.get("/api/dignitaries", async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT id, full_name, email, designation, organization, phone, category, karyakar_name,
              salutation, post_nominals, dietary, interest_tags, protocol_notes, created_at
       FROM dignitaries ORDER BY id DESC`
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load dignitaries." });
  }
});

app.post("/api/dignitaries", async (req, res) => {
  const {
    fullName,
    email,
    designation,
    organization,
    phone,
    category,
    karyakarName,
    salutation,
    postNominals,
    dietary,
    interestTags,
    protocolNotes,
  } = req.body || {};
  if (!fullName || !email) return badRequest(res, "fullName and email are required.");
  if (!isEmail(email)) return badRequest(res, "Invalid email.");

  const phoneVal = cleanText(phone || "", 40);
  let cat = cleanText(category || "", 40);
  if (!cat) cat = "Government";
  const kar = cleanText(karyakarName || "", 120);
  const sal = cleanText(salutation || "", 40);
  const postN = cleanText(postNominals || "", 120);
  const diet = cleanText(dietary || "", 80);
  const tags = cleanText(interestTags || "", 500);
  const proto = cleanText(protocolNotes || "", 2000);

  try {
    const result = await db.query(
      `INSERT INTO dignitaries (
         full_name, email, designation, organization, phone, category, karyakar_name,
         salutation, post_nominals, dietary, interest_tags, protocol_notes
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        cleanText(designation, 120),
        cleanText(organization, 160),
        phoneVal || null,
        cat,
        kar || null,
        sal || null,
        postN || null,
        diet || null,
        tags || null,
        proto || null,
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
    const phone = cleanText(raw.phone || raw.whatsapp || "", 40);
    let category = cleanText(raw.category || "", 40);
    if (!category) category = "Government";
    const karyakarName = cleanText(raw.karyakarName || raw.karyakar || "", 120);
    const salutation = cleanText(raw.salutation || raw.title || "", 40);
    const postNominals = cleanText(raw.postNominals || raw.postnominals || raw.credentials || "", 120);
    const dietary = cleanText(raw.dietary || "", 80);
    const interestTags = cleanText(raw.interestTags || raw.tags || raw.interests || "", 500);
    const protocolNotes = cleanText(raw.protocolNotes || raw.notes || "", 2000);

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
          `INSERT INTO dignitaries (
             full_name, email, designation, organization, phone, category, karyakar_name,
             salutation, post_nominals, dietary, interest_tags, protocol_notes
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           ON CONFLICT (email) DO NOTHING RETURNING id`,
          [
            fullName,
            tryEmail,
            designation,
            organization,
            phone || null,
            category,
            karyakarName || null,
            salutation || null,
            postNominals || null,
            dietary || null,
            interestTags || null,
            protocolNotes || null,
          ]
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
    const result = await db.query(
      "SELECT id, title, event_date, event_time, venue, description, created_at FROM events ORDER BY event_date DESC"
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load events." });
  }
});

app.post("/api/events", async (req, res) => {
  const { title, eventDate, eventTime, venue, description } = req.body || {};
  if (!title || !eventDate || !venue) {
    return badRequest(res, "title, eventDate, and venue are required.");
  }
  try {
    const result = await db.query(
      "INSERT INTO events (title, event_date, event_time, venue, description) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [
        cleanText(title, 160),
        eventDate,
        cleanText(eventTime || "", 20),
        cleanText(venue, 180),
        typeof description === "string" ? cleanText(description, 4000) : "",
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create event." });
  }
});

app.patch("/api/events/:id", async (req, res) => {
  const id = Number(req.params.id);
  const { title, eventDate, eventTime, venue, description } = req.body || {};
  if (!Number.isInteger(id) || id < 1) {
    return badRequest(res, "Invalid event id.");
  }
  if (!title || !eventDate || !venue) {
    return badRequest(res, "title, eventDate, and venue are required.");
  }
  try {
    const result = await db.query(
      `UPDATE events SET title = $1, event_date = $2, event_time = $3, venue = $4, description = $5
       WHERE id = $6 RETURNING *`,
      [
        cleanText(title, 160),
        eventDate,
        cleanText(eventTime || "", 20),
        cleanText(venue, 180),
        typeof description === "string" ? cleanText(description, 4000) : "",
        id,
      ]
    );
    if (!result.rowCount) {
      return res.status(404).json({ error: "Event not found." });
    }
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to update event." });
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

    const pdfBuf = await invitationRender.renderInvitationPdfBuffer(invite);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename=invitation-${invite.id}.pdf`);
    return res.send(pdfBuf);
  } catch {
    return res.status(500).json({ error: "Failed to render PDF." });
  }
});

app.post("/api/invitations/:id/send-email", invitationEmailLimiter, async (req, res) => {
  const { userId, pdfBase64, emailSubject } = req.body || {};
  if (!userId) return badRequest(res, "userId is required.");
  const sender = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
  if (!sender.rows[0]) return badRequest(res, "Invalid userId.");

  const inviteResult = await db.query(`
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.designation, d.organization, d.email,
             e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = $1
    `, [req.params.id]);
  const invite = inviteResult.rows[0];
  if (!invite) return res.status(404).json({ error: "Invitation not found." });
  if (!isEmail(invite.email)) {
    return badRequest(res, "Dignitary email is missing or invalid; cannot send.");
  }

  let pdfBuf = decodeClientInvitationPdf(pdfBase64);
  if (!pdfBuf) {
    try {
      pdfBuf = await invitationRender.renderInvitationPdfBuffer(invite);
    } catch (_e) {
      return res.status(500).json({ error: "Failed to build invitation PDF." });
    }
  }

  const customSub = typeof emailSubject === "string" ? emailSubject.trim() : "";
  const subjectClean = customSub ? cleanText(customSub, 200) : "";
  const subject = subjectClean || `Invitation: ${invite.event_title}`;
  const html = invitationRender.buildInvitationEmailHtml(invite);
  const dateLine = invitationRender.formatDateDisplay(invite.event_date);
  const textBody = [
    `Dear ${invite.dignitary_name},`,
    "",
    invite.custom_message ? String(invite.custom_message).trim() : "You are cordially invited.",
    "",
    `Event: ${invite.event_title}`,
    `Date: ${dateLine}`,
    invite.event_time ? `Time: ${invite.event_time}` : "",
    `Venue: ${invite.venue}`,
    "",
    "A formal PDF invitation is attached to this email.",
    "",
    "— BAPS Africa",
  ]
    .filter(Boolean)
    .join("\n");
  const pdfName = `PRASAR-Invitation-${invite.id}.pdf`;
  const attach = [
    {
      name: pdfName,
      contentBase64: pdfBuf.toString("base64"),
      contentType: "application/pdf",
    },
  ];

  let delivery = { provider: "local", outboxFile: null, messageId: null };

  if (postmark.isConfigured()) {
    const pm = await postmark.sendEmail({
      to: invite.email,
      subject,
      htmlBody: html,
      textBody,
      tag: "invitation",
      attachments: attach,
    });
    if (!pm.success) {
      if (!isProduction) {
        console.error("Postmark send failed:", pm.error);
      } else {
        console.error("Postmark send failed (details omitted in production).");
      }
      return res.status(502).json({
        error: isProduction ? "Email delivery failed. Try again or contact support." : pm.error || "Postmark send failed.",
      });
    }
    delivery = { provider: "postmark", outboxFile: null, messageId: pm.messageId };
  } else {
    const info = await mailer.sendMail({
      from: "prasar-local@localhost",
      to: invite.email,
      subject,
      html,
      text: textBody,
      attachments: [{ filename: pdfName, content: pdfBuf, contentType: "application/pdf" }],
    });
    const emlPath = path.join(outboxDir, `invitation-${invite.id}-${Date.now()}.eml`);
    fs.writeFileSync(emlPath, info.message);
    delivery = { provider: "local", outboxFile: path.basename(emlPath), messageId: null };
  }

  await db.query("UPDATE invitations SET status = 'SENT', sent_at = NOW() WHERE id = $1", [invite.id]);
  const dignitaryIdResult = await db.query("SELECT dignitary_id FROM invitations WHERE id = $1", [invite.id]);
  const commNote =
    delivery.provider === "postmark"
      ? `Invitation email sent via Postmark for ${invite.event_title}`
      : `Invitation email saved to outbox (${delivery.outboxFile}) for ${invite.event_title}`;
  await db.query(
    "INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES ($1, $2, $3, $4, NOW())",
    [dignitaryIdResult.rows[0].dignitary_id, userId, "EMAIL", commNote]
  );

  res.json({
    ok: true,
    provider: delivery.provider,
    messageId: delivery.messageId,
    outboxFile: delivery.outboxFile,
  });
});

// Communications
app.get("/api/communications", async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT c.id, c.dignitary_id, c.type, c.notes, c.happened_at, c.created_at,
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

app.post("/api/system/backup", async (req, res) => {
  if (backupHttpToken) {
    const t = String(req.header("x-prasar-backup-token") || "").trim();
    if (!constantTimeCompareStrings(t, backupHttpToken)) {
      return res.status(403).json({ error: "Forbidden." });
    }
  }
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
