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
const whatsapp = require("./whatsapp");
const invitationRender = require("./invitationRender");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isVercel = Boolean(process.env.VERCEL);
const prototypeFile = path.join(__dirname, "..", "Prasar-Prototype.html");
const dataRoot = isVercel ? path.join("/tmp", "prasar-data") : path.join(__dirname, "..", "data");
const secretsFile = path.join(dataRoot, "runtime-secrets.json");
let fileSecrets = {};
try {
  fs.mkdirSync(path.dirname(secretsFile), { recursive: true });
} catch {
  /* Vercel filesystem may be read-only outside /tmp */
}
if (fs.existsSync(secretsFile)) {
  try {
    fileSecrets = JSON.parse(fs.readFileSync(secretsFile, "utf8"));
  } catch {
    fileSecrets = {};
  }
}
if (!process.env.PRASAR_API_KEY || !process.env.PRASAR_BACKUP_KEY) {
  if (!fileSecrets.PRASAR_API_KEY || !fileSecrets.PRASAR_BACKUP_KEY) {
    const generated = {
      PRASAR_API_KEY: crypto.randomBytes(48).toString("base64url"),
      PRASAR_BACKUP_KEY: crypto.randomBytes(48).toString("base64url"),
      created_at: new Date().toISOString(),
    };
    fileSecrets = { ...fileSecrets, ...generated };
    try {
      fs.writeFileSync(secretsFile, JSON.stringify(fileSecrets, null, 2));
    } catch (err) {
      if (!isVercel) throw err;
      console.warn("Could not persist runtime secrets; set PRASAR_API_KEY and PRASAR_BACKUP_KEY on Vercel.");
    }
  }
}
const API_KEY = process.env.PRASAR_API_KEY || fileSecrets.PRASAR_API_KEY || "";
const BACKUP_KEY = process.env.PRASAR_BACKUP_KEY || fileSecrets.PRASAR_BACKUP_KEY || "";
if (!API_KEY) {
  console.error("FATAL: PRASAR_API_KEY is missing. Set PRASAR_API_KEY or ensure data/runtime-secrets.json is writable.");
  if (!isVercel) process.exit(1);
}
const allowedOrigins = new Set(["http://localhost:3000", "http://127.0.0.1:3000"]);
function addAllowedOrigin(raw) {
  const value = String(raw || "").trim().replace(/\/$/, "");
  if (!value) return;
  allowedOrigins.add(/^https?:\/\//i.test(value) ? value : `https://${value}`);
}
addAllowedOrigin(process.env.RENDER_EXTERNAL_URL);
addAllowedOrigin(process.env.PUBLIC_APP_URL);
addAllowedOrigin(process.env.VERCEL_PROJECT_PRODUCTION_URL);
addAllowedOrigin(process.env.VERCEL_BRANCH_URL);
addAllowedOrigin(process.env.VERCEL_URL);
if (process.env.ALLOWED_ORIGINS) {
  for (const o of process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)) {
    addAllowedOrigin(o);
  }
}
let bootPromise;
function ensureBooted() {
  if (!bootPromise) {
    bootPromise = db
      .init()
      .then(async () => {
        await ensureBootstrapAdmin();
        await ensureBootstrapVolunteer();
        await db.query(`DELETE FROM sessions WHERE expires_at < NOW()`).catch(() => {});
      })
      .catch((err) => {
        bootPromise = null;
        throw err;
      });
  }
  return bootPromise;
}
app.use(async (_req, _res, next) => {
  try {
    await ensureBooted();
    next();
  } catch (err) {
    console.error("PRASAR boot failed:", err && err.message ? err.message : err);
    return _res.status(503).json({ error: "Service unavailable." });
  }
});
const isProduction = process.env.NODE_ENV === "production";
/** Optional: require this header on POST /api/system/backup (in addition to normal API access). */
const backupHttpToken = String(process.env.PRASAR_BACKUP_HTTP_TOKEN || "").trim();
const SESSION_COOKIE = "prasar_sid";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

if (process.env.TRUST_PROXY === "1" || process.env.RENDER === "true" || isVercel || isProduction) {
  app.set("trust proxy", 1);
}

const backupDir = path.join(dataRoot, "backups");
try {
  fs.mkdirSync(backupDir, { recursive: true });
} catch {
  /* ignore */
}

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
  /** Format: v1$<saltBase64>$<hashBase64> → ["v1", salt, hash] */
  if (parts.length < 3) return false;
  try {
    const salt = Buffer.from(parts[1], "base64");
    const expected = Buffer.from(parts[2], "base64");
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

function parseCookies(req) {
  const header = String(req.headers.cookie || "");
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      out[k] = part.slice(idx + 1).trim();
    }
  }
  return out;
}

function sessionCookieFlags() {
  const parts = ["Path=/", "HttpOnly", "SameSite=Lax"];
  if (isProduction) parts.push("Secure");
  return parts.join("; ");
}

function setSessionCookie(res, token) {
  res.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; ${sessionCookieFlags()}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  );
}

function clearSessionCookie(res) {
  res.append("Set-Cookie", `${SESSION_COOKIE}=; ${sessionCookieFlags()}; Max-Age=0`);
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + SESSION_TTL_MS);
  await db.query(`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)`, [
    token,
    userId,
    expires.toISOString(),
  ]);
  return token;
}

async function destroySession(token) {
  if (!token) return;
  await db.query(`DELETE FROM sessions WHERE token = $1`, [token]);
}

async function loadSessionUser(token) {
  if (!token) return null;
  const result = await db.query(
    `SELECT s.token, s.expires_at, u.id, u.full_name, u.email, u.role, u.status, u.assigned_area, u.phone
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token = $1
     LIMIT 1`,
    [token]
  );
  const row = result.rows[0];
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    await db.query(`DELETE FROM sessions WHERE token = $1`, [token]);
    return null;
  }
  if (String(row.status || "").toUpperCase() === "INACTIVE") return null;
  return row;
}

function publicUserPayload(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    role: String(row.role || "").trim().toUpperCase(),
    assignedArea: row.assigned_area || "",
    phone: row.phone || "",
    status: row.status,
  };
}

function isPublicApiPath(reqPath) {
  const p = String(reqPath || "");
  return p === "/health" || p === "/reload-hash";
}

async function requireAuth(req, res, next) {
  if (isPublicApiPath(req.path)) return next();
  if (!API_KEY) {
    return res.status(503).json({ error: "Server misconfigured: API key not set." });
  }
  const key = req.header("x-prasar-api-key") || "";
  if (constantTimeCompareStrings(key, API_KEY)) {
    req.auth = { via: "api-key", role: "ADMIN", id: 0, full_name: "API Key", email: "" };
    return next();
  }
  try {
    const token = parseCookies(req)[SESSION_COOKIE] || "";
    const user = await loadSessionUser(token);
    if (!user) return res.status(401).json({ error: "Unauthorized." });
    req.auth = {
      via: "session",
      role: String(user.role || "").trim().toUpperCase(),
      id: user.id,
      full_name: user.full_name,
      email: user.email,
    };
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized." });
  }
}

function requireAdmin(req, res, next) {
  if (String(req.auth?.role || "").toUpperCase() !== "ADMIN") {
    return res.status(403).json({ error: "Admin access required." });
  }
  return next();
}

const LOGIN_FAIL_MESSAGE = "Invalid email or password.";

async function findUsersForLogin(identifier, preferredRole) {
  const cols = `id, full_name, email, "role", status, assigned_area, phone, password_hash`;
  if (isEmail(identifier)) {
    return db.query(
      `SELECT ${cols}
       FROM users
       WHERE LOWER(TRIM(email)) = LOWER(TRIM($1))
       LIMIT 1`,
      [identifier]
    );
  }
  const nameKey = identifier.toLowerCase().replace(/\s+/g, " ");
  const roleHint = String(preferredRole || "")
    .trim()
    .toUpperCase();
  const roleOrder =
    roleHint === "ADMIN"
      ? `CASE WHEN UPPER(TRIM("role")) = 'ADMIN' THEN 0 WHEN UPPER(TRIM("role")) = 'KARYAKAR' THEN 1 ELSE 2 END`
      : roleHint === "KARYAKAR"
        ? `CASE WHEN UPPER(TRIM("role")) = 'KARYAKAR' THEN 0 WHEN UPPER(TRIM("role")) = 'ADMIN' THEN 1 ELSE 2 END`
        : `CASE WHEN UPPER(TRIM("role")) = 'ADMIN' THEN 0 WHEN UPPER(TRIM("role")) = 'KARYAKAR' THEN 1 ELSE 2 END`;
  return db.query(
    `SELECT ${cols}
     FROM users
     WHERE LOWER(regexp_replace(trim(full_name), '[[:space:]]+', ' ', 'g')) = $1
     ORDER BY ${roleOrder}, id ASC`,
    [nameKey]
  );
}

async function loginWithPassword(req, res, allowedRoles) {
  const raw =
    (typeof req.body?.identifier === "string" && req.body.identifier) ||
    (typeof req.body?.email === "string" && req.body.email) ||
    (typeof req.body?.login === "string" && req.body.login) ||
    "";
  const identifier = normalizeLoginIdentifier(raw);
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const preferredRole =
    typeof req.body?.role === "string"
      ? req.body.role
      : typeof req.body?.loginRole === "string"
        ? req.body.loginRole
        : "";
  if (!identifier || !password) return badRequest(res, "identifier and password are required.");

  try {
    const result = await findUsersForLogin(identifier, preferredRole);
    const candidates = (result.rows || []).filter((row) =>
      allowedRoles.includes(String(row?.role || "").trim().toUpperCase())
    );
    if (!candidates.length) {
      return res.status(401).json({ error: LOGIN_FAIL_MESSAGE });
    }
    let matched = null;
    for (const row of candidates) {
      if (String(row.status || "").toUpperCase() === "INACTIVE") continue;
      const phRaw = row.password_hash;
      if (phRaw == null || String(phRaw).trim() === "") continue;
      const ok = verifyStoredPassword(password, String(phRaw).trim());
      if (ok === true) {
        matched = row;
        break;
      }
    }
    if (!matched) {
      return res.status(401).json({ error: LOGIN_FAIL_MESSAGE });
    }
    await db.query(`DELETE FROM sessions WHERE user_id = $1 OR expires_at < NOW()`, [matched.id]);
    const token = await createSession(matched.id);
    setSessionCookie(res, token);
    return res.json({ user: publicUserPayload(matched) });
  } catch {
    return res.status(500).json({ error: "Login failed." });
  }
}

async function ensureBootstrapUser({ emailEnv, passwordEnv, role, fullName, label }) {
  const email = String(process.env[emailEnv] || "")
    .trim()
    .toLowerCase();
  const password = String(process.env[passwordEnv] || "");
  if (!email && !password) return false;
  if (!email || !password) {
    console.error(`${emailEnv} and ${passwordEnv} must both be set; ${label} bootstrap skipped.`);
    return true;
  }
  if (!isEmail(email)) {
    console.error(`${emailEnv} is not a valid email; ${label} bootstrap skipped.`);
    return true;
  }
  if (password.length < 8) {
    console.error(`${passwordEnv} must be at least 8 characters; ${label} bootstrap skipped.`);
    return true;
  }
  const hash = hashUserPassword(password);
  const existing = await db.query(`SELECT id FROM users WHERE LOWER(TRIM(email)) = $1 LIMIT 1`, [email]);
  if (existing.rows[0]) {
    await db.query(`UPDATE users SET password_hash = $1, role = $2, status = 'ACTIVE' WHERE id = $3`, [
      hash,
      role,
      existing.rows[0].id,
    ]);
    console.log(`Bootstrap ${label} password updated for`, email);
  } else {
    await db.query(
      `INSERT INTO users (full_name, email, role, status, password_hash)
       VALUES ($1, $2, $3, 'ACTIVE', $4)`,
      [fullName, email, role, hash]
    );
    console.log(`Bootstrap ${label} created:`, email);
  }
  return true;
}

async function ensureBootstrapAdmin() {
  const didBootstrap = await ensureBootstrapUser({
    emailEnv: "PRASAR_BOOTSTRAP_ADMIN_EMAIL",
    passwordEnv: "PRASAR_BOOTSTRAP_ADMIN_PASSWORD",
    role: "ADMIN",
    fullName: "Administrator",
    label: "admin",
  });
  if (didBootstrap) return;
  const usable = await db.query(
    `SELECT COUNT(*)::int AS n
     FROM users
     WHERE UPPER(TRIM(role)) = 'ADMIN'
       AND password_hash IS NOT NULL
       AND TRIM(password_hash) <> ''`
  );
  if (!usable.rows[0]?.n) {
    console.warn(
      "WARNING: No administrator can log in. Set PRASAR_BOOTSTRAP_ADMIN_EMAIL and PRASAR_BOOTSTRAP_ADMIN_PASSWORD, then restart."
    );
  }
}

async function ensureBootstrapVolunteer() {
  await ensureBootstrapUser({
    emailEnv: "PRASAR_BOOTSTRAP_VOLUNTEER_EMAIL",
    passwordEnv: "PRASAR_BOOTSTRAP_VOLUNTEER_PASSWORD",
    role: "KARYAKAR",
    fullName: "Test Volunteer",
    label: "volunteer",
  });
}

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        fontSrc: ["'self'", "data:", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://cdn.jsdelivr.net"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
      },
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    hsts: isProduction ? { maxAge: 15552000, includeSubDomains: true } : false,
  })
);
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.has(origin)) return cb(null, true);
      try {
        const host = new URL(origin).hostname;
        if (isVercel && host.endsWith(".vercel.app")) return cb(null, true);
      } catch {
        /* ignore */
      }
      return cb(new Error("CORS blocked"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "x-prasar-api-key", "x-prasar-backup-token"],
    credentials: true,
  })
);
app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.PRASAR_API_RATE_LIMIT_MAX || 5000),
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      const p = String(req.path || "");
      // Mounted at /api → paths are relative (e.g. /reload-hash, /health).
      if (p === "/health" || p === "/reload-hash") return true;
      // Local development should never lock out the browser UI.
      const ip = String(req.ip || "");
      if (
        !isProduction &&
        (ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip === "localhost")
      ) {
        return true;
      }
      return false;
    },
  })
);

const invitationEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.PRASAR_EMAIL_RATE_LIMIT_PER_HOUR || 120),
  message: { error: "Too many invitation emails. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
const invitationWhatsAppLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.PRASAR_WHATSAPP_RATE_LIMIT_PER_HOUR || 120),
  message: { error: "Too many invitation WhatsApp messages. Try again later." },
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

const rsvpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.PRASAR_RSVP_RATE_LIMIT_MAX || 60),
  message: { error: "Too many RSVP attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/api/auth/login", karyakarLoginLimiter, async (req, res) => {
  // Role dropdown is only a UI hint; authenticate by identifier + password.
  return loginWithPassword(req, res, ["ADMIN", "KARYAKAR"]);
});

app.post("/api/auth/karyakar-login", karyakarLoginLimiter, async (req, res) => {
  return loginWithPassword(req, res, ["KARYAKAR"]);
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    await destroySession(parseCookies(req)[SESSION_COOKIE] || "");
  } catch {
    /* ignore */
  }
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.get("/api/auth/me", async (req, res) => {
  const key = req.header("x-prasar-api-key") || "";
  if (API_KEY && constantTimeCompareStrings(key, API_KEY)) {
    return res.json({ user: { id: 0, fullName: "API Key", email: "", role: "ADMIN", via: "api-key" } });
  }
  try {
    const token = parseCookies(req)[SESSION_COOKIE] || "";
    const user = await loadSessionUser(token);
    if (!user) return res.json({ user: null });
    return res.json({
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: String(user.role || "").trim().toUpperCase(),
        via: "session",
      },
    });
  } catch {
    return res.json({ user: null });
  }
});

// Public RSVP (unguessable token only — guests confirm attendance via invite link)
app.get("/api/rsvp/:token", rsvpLimiter, async (req, res) => {
  const token = String(req.params.token || "").trim();
  if (!token) return res.status(400).json({ error: "Invalid RSVP token." });
  try {
    const result = await db.query(
      `SELECT i.id, i.rsvp_status, i.admin_approval,
              d.full_name AS dignitary_name, d.salutation,
              e.title AS event_title, e.event_date, e.event_time, e.venue
       FROM invitations i
       JOIN dignitaries d ON d.id = i.dignitary_id
       JOIN events e ON e.id = i.event_id
       WHERE i.rsvp_token = $1`,
      [token]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "RSVP link not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to load RSVP." });
  }
});

app.post("/api/rsvp/:token", rsvpLimiter, async (req, res) => {
  const token = String(req.params.token || "").trim();
  if (!token) return res.status(400).json({ error: "Invalid RSVP token." });
  const status = String(req.body?.rsvpStatus || req.body?.status || "")
    .trim()
    .toUpperCase();
  if (!["ACCEPTED", "DECLINED"].includes(status)) {
    return res.status(400).json({ error: "rsvpStatus must be ACCEPTED or DECLINED." });
  }
  try {
    const result = await db.query(
      `UPDATE invitations SET rsvp_status = $1 WHERE rsvp_token = $2
       RETURNING id, rsvp_status, admin_approval`,
      [status, token]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "RSVP link not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to submit RSVP." });
  }
});

app.use("/api", requireAuth);

app.use("/local-app", express.static(path.join(__dirname, "..", "public")));
const publicDir = path.join(__dirname, "..", "public");
app.get("/favicon.svg", (_req, res) => {
  res.type("image/svg+xml");
  res.sendFile(path.join(publicDir, "favicon.svg"));
});
app.get(["/favicon.png", "/favicon-32.png", "/favicon-180.png"], (req, res) => {
  res.type("image/png");
  res.sendFile(path.join(publicDir, path.basename(req.path)));
});
app.get("/favicon.ico", (_req, res) => {
  res.type("image/png");
  res.sendFile(path.join(publicDir, "favicon-32.png"));
});
app.get("/", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.sendFile(prototypeFile);
});
app.get("/rsvp", (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "rsvp.html"));
});
app.get("/rsvp.html", (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "rsvp.html"));
});

const outboxDir = path.join(dataRoot, "outbox");
try {
  fs.mkdirSync(outboxDir, { recursive: true });
} catch {
  /* ignore */
}

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
if (whatsapp.isConfigured()) {
  console.log("WhatsApp: Cloud API enabled (WHATSAPP_ACCESS_TOKEN + WHATSAPP_PHONE_NUMBER_ID set).");
} else {
  console.log("WhatsApp: Cloud API not configured. Set WHATSAPP_ACCESS_TOKEN + WHATSAPP_PHONE_NUMBER_ID.");
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

const GUEST_MESSAGE_PARAGRAPH_CUES = [
  "Jai Swaminarayan",
  "As the festival of lights",
  "May this beautiful festival",
  "We would be delighted to have you",
  "Please find the accompanying poster",
  "We look forward to welcoming you",
  "Kindly confirm your attendance",
  "Warm regards",
];

/** Split pasted invitation blocks into paragraphs when line breaks were lost. */
function normalizeGuestMessageParagraphs(text) {
  if (typeof text !== "string") return "";
  let s = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  if (!s) return "";
  if (s.includes("\n")) {
    return s
      .split("\n")
      .map((line) => line.replace(/[ \t]+/g, " ").trim())
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }
  s = s.replace(/(🪔 Celebrate the Spirit of Diwali with Us 🪔)\s+/u, "$1\n\n");
  for (const cue of GUEST_MESSAGE_PARAGRAPH_CUES) {
    const esc = cue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    s = s.replace(new RegExp(`([^\\n])\\s+(?=${esc})`), "$1\n\n");
  }
  return s.replace(/\n{3,}/g, "\n\n").trim();
}

/** Preserves paragraph breaks (blank lines); collapses only spaces/tabs within each line. */
function cleanMultilineText(value, maxLen = 4000) {
  if (typeof value !== "string") return "";
  let out = normalizeGuestMessageParagraphs(value);
  if (!out) return "";
  const lines = out.split("\n").map((line) => line.replace(/[ \t]+/g, " ").trim());
  out = lines.join("\n").replace(/\n{3,}/g, "\n\n");
  if (out.length > maxLen) out = out.slice(0, maxLen);
  return out;
}

const DEFAULT_LOOKUPS = {
  sectors: ["Government", "Corporate", "Academic", "Religious", "NGO"],
  subSectors: {
    Government: ["National Government", "County Government", "Judiciary", "Legislature", "Diplomatic / Embassy", "Security / Police", "Public Service"],
    Corporate: ["Banking & Finance", "Manufacturing", "Energy & Mining", "ICT / Technology", "Media & Communications", "Healthcare", "Hospitality & Tourism", "Retail & Trade", "Transport & Logistics", "Real Estate & Construction"],
    Academic: ["University", "College", "Research Institute", "School", "Professional Body"],
    Religious: ["Hindu", "Christian", "Muslim", "Interfaith", "Other Faith"],
    NGO: ["International NGO", "Local NGO", "Foundation", "Community Organization", "UN / Multilateral"],
  },
  salutations: ["Hon.", "Dr.", "Mr.", "Ms.", "Sheikh", "Prof."],
  vipCategories: ["V1", "V2", "V3"],
  dietary: ["None", "Strict Veg", "Jain", "Vegan", "Gluten-Free"],
  donationProjects: ["Akshardham", "Education", "Youth", "Interfaith", "General"],
  karyakarPages: {
    dashboard: true,
    about: true,
    dignitaries: true,
    events: true,
    invitations: true,
    "invitation-tracker": true,
    communications: true,
    attendance: true,
    hospitality: true,
    reports: true,
    donations: true,
  },
};

const KARYAKAR_PAGE_IDS = Object.keys(DEFAULT_LOOKUPS.karyakarPages);

function normalizeKaryakarPages(raw) {
  const src = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const out = {};
  for (const id of KARYAKAR_PAGE_IDS) {
    out[id] = src[id] === false ? false : true;
  }
  if (!Object.values(out).some(Boolean)) out.dashboard = true;
  return out;
}

function uniqLookupLabels(arr, maxLen, maxItems) {
  const out = [];
  const seen = new Set();
  for (const raw of Array.isArray(arr) ? arr : []) {
    const s = cleanText(String(raw || ""), maxLen);
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
    if (out.length >= maxItems) break;
  }
  return out;
}

function lookupListOrDefault(raw, fallback, maxLen, maxItems) {
  const list = uniqLookupLabels(raw, maxLen, maxItems);
  return list.length ? list : fallback.slice();
}

function normalizeLookups(raw) {
  const src = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const sectors = lookupListOrDefault(src.sectors, DEFAULT_LOOKUPS.sectors, 40, 40);
  const subIn = src.subSectors && typeof src.subSectors === "object" && !Array.isArray(src.subSectors) ? src.subSectors : {};
  const subSectors = {};
  for (const sec of sectors) {
    const hit = Object.keys(subIn).find((k) => k.toLowerCase() === sec.toLowerCase());
    const incoming = hit ? subIn[hit] : DEFAULT_LOOKUPS.subSectors[sec];
    subSectors[sec] = uniqLookupLabels(incoming, 80, 40);
  }
  return {
    sectors,
    subSectors,
    salutations: lookupListOrDefault(src.salutations, DEFAULT_LOOKUPS.salutations, 40, 30),
    vipCategories: lookupListOrDefault(src.vipCategories, DEFAULT_LOOKUPS.vipCategories, 20, 20),
    dietary: lookupListOrDefault(src.dietary, DEFAULT_LOOKUPS.dietary, 40, 20),
    donationProjects: lookupListOrDefault(src.donationProjects, DEFAULT_LOOKUPS.donationProjects, 80, 30),
    karyakarPages: normalizeKaryakarPages(src.karyakarPages),
  };
}

async function readStoredLookups() {
  try {
    const result = await db.query(`SELECT value FROM app_lookups WHERE key = 'form_options'`);
    if (!result.rows[0]?.value) return normalizeLookups(DEFAULT_LOOKUPS);
    try {
      return normalizeLookups(JSON.parse(result.rows[0].value));
    } catch {
      return normalizeLookups(DEFAULT_LOOKUPS);
    }
  } catch {
    return normalizeLookups(DEFAULT_LOOKUPS);
  }
}

function envDefaultEmailSettings() {
  return {
    senderEmail: cleanText(process.env.POSTMARK_SENDER_EMAIL || process.env.POSTMARK_FROM_EMAIL || "", 200),
    senderName: cleanText(process.env.POSTMARK_SENDER_NAME || "PRASAR", 120) || "PRASAR",
    replyTo: cleanText(process.env.POSTMARK_REPLY_TO || "", 200),
  };
}

function normalizeEmailSettings(raw) {
  const env = envDefaultEmailSettings();
  const src = raw && typeof raw === "object" ? raw : {};
  const senderEmail = cleanText(src.senderEmail || src.sender_email || "", 200);
  const senderName = cleanText(src.senderName || src.sender_name || "", 120);
  const replyTo = cleanText(src.replyTo || src.reply_to || "", 200);
  return {
    senderEmail: isEmail(senderEmail) ? senderEmail : env.senderEmail,
    senderName: senderName || env.senderName,
    replyTo: isEmail(replyTo) ? replyTo : (isEmail(env.replyTo) ? env.replyTo : ""),
  };
}

async function readEmailSettings() {
  try {
    const result = await db.query(`SELECT value FROM app_lookups WHERE key = 'email_settings'`);
    if (!result.rows[0]?.value) {
      return { ...normalizeEmailSettings(null), source: "env" };
    }
    try {
      return { ...normalizeEmailSettings(JSON.parse(result.rows[0].value)), source: "stored" };
    } catch {
      return { ...normalizeEmailSettings(null), source: "env" };
    }
  } catch {
    return { ...normalizeEmailSettings(null), source: "env" };
  }
}

function parseEventSchedule(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "string" || !raw.trim()) return [];
  try {
    const p = JSON.parse(raw);
    return Array.isArray(p) ? p : [];
  } catch {
    return [];
  }
}

function normalizeEventDays(body) {
  const raw = Array.isArray(body?.days)
    ? body.days
    : Array.isArray(body?.schedule)
      ? body.schedule
      : null;
  let days = [];
  if (raw && raw.length) {
    days = raw.map((d) => {
      const name = cleanText(String(d?.name || d?.title || d?.label || ""), 80);
      const row = {
        date: cleanText(String(d?.date || d?.eventDate || ""), 10),
        startTime: cleanText(String(d?.startTime || d?.start || ""), 20),
        endTime: cleanText(String(d?.endTime || d?.end || ""), 20),
      };
      if (name) row.name = name;
      return row;
    }).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d.date));
  } else if (body?.eventDate) {
    const name = cleanText(String(body.dayName || body.eventDayName || ""), 80);
    const row = {
      date: cleanText(String(body.eventDate), 10),
      startTime: cleanText(String(body.eventTime || body.startTime || ""), 20),
      endTime: cleanText(String(body.endTime || ""), 20),
    };
    if (name) row.name = name;
    days = [row].filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d.date));
  }
  days.sort((a, b) => String(a.date).localeCompare(String(b.date)));
  return days;
}

function eventTimeSummary(days) {
  if (!days.length) return "";
  const first = days[0];
  const span = [first.startTime, first.endTime].filter(Boolean).join(" – ");
  if (days.length === 1) return span;
  return `${days.length} days${span ? ` · ${span}` : ""}`;
}

function parseEventStatus(raw, fallback) {
  const s = String(raw || "")
    .trim()
    .toUpperCase();
  if (s === "DRAFT" || s === "PUBLISHED") return s;
  return fallback || "PUBLISHED";
}

function parseUserGender(raw) {
  const s = String(raw || "")
    .trim()
    .toUpperCase();
  if (s === "MALE" || s === "M") return "MALE";
  if (s === "FEMALE" || s === "F") return "FEMALE";
  return null;
}

function withEventSchedule(row) {
  if (!row) return row;
  const schedule = parseEventSchedule(row.schedule);
  const att = row.attendance_enabled;
  return {
    ...row,
    schedule,
    status: parseEventStatus(row.status, "PUBLISHED"),
    attendance_enabled: att === true || att === "t" || att === "true" || att === 1 || att === "1",
  };
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
  const tables = [
    "users",
    "dignitaries",
    "events",
    "invitations",
    "communications",
    "donations",
    "notifications",
  ];
  const dump = {};
  for (const table of tables) {
    const result = await db.query(`SELECT * FROM ${table} ORDER BY id ASC`);
    dump[table] =
      table === "users"
        ? result.rows.map((row) => {
            const copy = { ...row };
            delete copy.password_hash;
            return copy;
          })
        : result.rows;
  }
  const raw = Buffer.from(JSON.stringify({ created_at: new Date().toISOString(), data: dump }, null, 2), "utf8");
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  if (!BACKUP_KEY) {
    throw new Error("PRASAR_BACKUP_KEY is required; refusing plaintext backups.");
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
app.get("/api/email/delivery-status", async (_req, res) => {
  const postmarkConfigured = postmark.isConfigured();
  const emailSettings = await readEmailSettings();
  return res.json({
    postmarkConfigured,
    mode: postmarkConfigured ? "postmark" : "local",
    senderEmail: emailSettings.senderEmail || "",
    senderName: emailSettings.senderName || "",
  });
});

app.get("/api/settings/email", requireAdmin, async (_req, res) => {
  try {
    const settings = await readEmailSettings();
    return res.json({
      postmarkConfigured: postmark.isConfigured(),
      senderEmail: settings.senderEmail || "",
      senderName: settings.senderName || "",
      replyTo: settings.replyTo || "",
      source: settings.source || "env",
    });
  } catch {
    return res.status(500).json({ error: "Failed to load email settings." });
  }
});

app.put("/api/settings/email", requireAdmin, async (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const senderEmail = cleanText(body.senderEmail || body.sender_email || "", 200);
  const senderName = cleanText(body.senderName || body.sender_name || "", 120);
  const replyTo = cleanText(body.replyTo || body.reply_to || "", 200);
  if (!isEmail(senderEmail)) {
    return badRequest(res, "A valid sender email is required.");
  }
  if (replyTo && !isEmail(replyTo)) {
    return badRequest(res, "Reply-to email is invalid.");
  }
  const saved = {
    senderEmail,
    senderName: senderName || "PRASAR",
    replyTo: replyTo || "",
  };
  try {
    await db.query(
      `INSERT INTO app_lookups (key, value, updated_at) VALUES ('email_settings', $1, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [JSON.stringify(saved)]
    );
    return res.json({
      postmarkConfigured: postmark.isConfigured(),
      ...saved,
      source: "stored",
    });
  } catch {
    return res.status(500).json({ error: "Failed to save email settings." });
  }
});
app.get("/api/whatsapp/delivery-status", (_req, res) => {
  const configured = whatsapp.isConfigured();
  return res.json({
    configured,
    mode: configured ? "cloud-api" : "not-configured",
  });
});

app.get("/api/users", async (req, res) => {
  try {
    if (String(req.auth?.role || "").toUpperCase() !== "ADMIN") {
      const result = await db.query(
        `SELECT id, full_name, role, status
         FROM users
         WHERE UPPER(TRIM(status)) = 'ACTIVE'
         ORDER BY full_name ASC`
      );
      return res.json(result.rows);
    }
    const result = await db.query(
      "SELECT id, full_name, email, role, status, phone, assigned_area, gender, created_at FROM users ORDER BY id DESC"
    );
    return res.json(result.rows);
  } catch (err) {
    console.error("Load users failed:", err.message || err);
    return res.status(500).json({ error: "Failed to load users." });
  }
});

app.post("/api/users", requireAdmin, async (req, res) => {
  const { fullName, email, role, status, phone, assignedArea, password, gender } = req.body || {};
  if (!fullName || !email || !role) {
    return badRequest(res, "fullName, email, and role are required.");
  }
  if (!isEmail(email)) return badRequest(res, "Invalid email.");
  if (!["ADMIN", "KARYAKAR"].includes(role)) return badRequest(res, "Invalid role.");
  const safeStatus = status === "INACTIVE" ? "INACTIVE" : "ACTIVE";
  const phoneVal = cleanText(phone || "", 40);
  const areaVal = cleanText(assignedArea || "", 200);
  let genderVal = null;
  if (gender != null && String(gender).trim() !== "") {
    genderVal = parseUserGender(gender);
    if (!genderVal) return badRequest(res, "gender must be MALE or FEMALE.");
  }
  if (typeof password !== "string" || password.length < 8) {
    return badRequest(res, "password is required (at least 8 characters).");
  }
  const passwordHash = hashUserPassword(password);

  try {
    const result = await db.query(
      `INSERT INTO users (full_name, email, role, status, phone, assigned_area, password_hash, gender)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, full_name, email, role, status, phone, assigned_area, gender, created_at`,
      [
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        role,
        safeStatus,
        phoneVal || null,
        areaVal || null,
        passwordHash,
        genderVal,
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create user." });
  }
});

app.patch("/api/users/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid user id.");
  const { fullName, email, role, status, phone, assignedArea, password, gender } = req.body || {};

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
    if (gender != null) {
      const g = String(gender).trim() === "" ? null : parseUserGender(gender);
      if (String(gender).trim() !== "" && !g) return badRequest(res, "gender must be MALE or FEMALE.");
      sets.push(`gender = $${i++}`);
      vals.push(g);
    }
    if (typeof password === "string" && password.length > 0) {
      if (password.length < 8) return badRequest(res, "Password must be at least 8 characters.");
      sets.push(`password_hash = $${i++}`);
      vals.push(hashUserPassword(password));
    }

    if (!sets.length) return badRequest(res, "No fields to update.");
    vals.push(id);
    const q = `UPDATE users SET ${sets.join(", ")} WHERE id = $${i} RETURNING id, full_name, email, role, status, phone, assigned_area, gender, created_at`;
    const result = await db.query(q, vals);
    return res.json(result.rows[0]);
  } catch (err) {
    console.error("Update user failed:", err.message || err);
    return res.status(500).json({ error: "Failed to update user." });
  }
});

// Dignitaries
app.get("/api/dignitaries", async (req, res) => {
  try {
    const approval = String(req.query.approvalStatus || req.query.approval || "")
      .trim()
      .toUpperCase();
    const params = [];
    let where = "";
    if (["PENDING", "APPROVED", "REJECTED"].includes(approval)) {
      params.push(approval);
      where = `WHERE COALESCE(UPPER(TRIM(d.approval_status)), 'APPROVED') = $1`;
    }
    const result = await db.query(
      `SELECT d.id, d.full_name, d.email, d.designation, d.organization, d.town, d.phone, d.category, d.karyakar_name,
              d.karyakar_name_secondary, d.karyakar_name_tertiary,
              d.salutation, d.post_nominals, d.dietary, d.interest_tags, d.protocol_notes, d.vip_category, d.contribution_notes, d.sub_sector, d.date_of_birth, d.created_at,
              COALESCE(NULLIF(UPPER(TRIM(d.approval_status)), ''), 'APPROVED') AS approval_status,
              COALESCE(NULLIF(UPPER(TRIM(d.status)), ''), 'ACTIVE') AS status,
              d.submitted_by_user_id, d.submitted_by_name, d.approved_by_user_id, d.approved_at, d.rejection_note,
              u.full_name AS approved_by_name
       FROM dignitaries d
       LEFT JOIN users u ON u.id = d.approved_by_user_id
       ${where}
       ORDER BY LOWER(TRIM(d.full_name)) ASC, d.id ASC`,
      params
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load dignitaries." });
  }
});

app.get("/api/dignitaries/pending-count", requireAdmin, async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT COUNT(*)::int AS count
       FROM dignitaries
       WHERE COALESCE(UPPER(TRIM(approval_status)), 'APPROVED') = 'PENDING'`
    );
    return res.json({ count: result.rows[0]?.count || 0 });
  } catch {
    return res.status(500).json({ error: "Failed to count pending dignitaries." });
  }
});

app.post("/api/dignitaries", async (req, res) => {
  const {
    fullName,
    email,
    designation,
    organization,
    town,
    phone,
    category,
    karyakarName,
    karyakarNameSecondary,
    karyakarNameTertiary,
    salutation,
    postNominals,
    dietary,
    interestTags,
    protocolNotes,
    vipCategory,
    contributionNotes,
    subSector,
    dateOfBirth,
    approvalStatus,
    submittedByUserId,
    submittedByName,
  } = req.body || {};
  if (!fullName || !email) return badRequest(res, "fullName and email are required.");
  if (!isEmail(email)) return badRequest(res, "Invalid email.");

  const phoneVal = cleanText(phone || "", 40);
  let cat = cleanText(category || "", 40);
  if (!cat) cat = "Government";
  const kar = cleanText(karyakarName || "", 120);
  const kar2 = cleanText(karyakarNameSecondary || "", 120);
  const kar3 = cleanText(karyakarNameTertiary || "", 120);
  const sal = cleanText(salutation || "", 40);
  const postN = cleanText(postNominals || "", 120);
  const diet = cleanText(dietary || "", 80);
  const tags = cleanText(interestTags || "", 500);
  const proto = cleanText(protocolNotes || "", 2000);
  const contrib = cleanText(contributionNotes || "", 2000);
  const townVal = cleanText(town || "", 120);
  const subSec = cleanText(subSector || "", 80);
  let dob = cleanText(dateOfBirth || "", 10);
  if (dob && !/^\d{4}-\d{2}-\d{2}$/.test(dob)) dob = "";
  let vip = cleanText(vipCategory || "", 10).toUpperCase().replace(/\s+/g, "");
  if (vip === "1" || vip === "V1") vip = "V1";
  else if (vip === "2" || vip === "V2") vip = "V2";
  else if (vip === "3" || vip === "V3") vip = "V3";
  else if (!["V1", "V2", "V3"].includes(vip)) vip = "";
  let approval = String(approvalStatus || "APPROVED").trim().toUpperCase();
  if (!["PENDING", "APPROVED", "REJECTED"].includes(approval)) approval = "APPROVED";
  let submitterId = submittedByUserId ? Number(submittedByUserId) : null;
  if (submitterId != null && (!Number.isInteger(submitterId) || submitterId <= 0)) submitterId = null;
  const submitterName = cleanText(submittedByName || "", 120) || null;

  try {
    const result = await db.query(
      `INSERT INTO dignitaries (
         full_name, email, designation, organization, town, phone, category, karyakar_name,
         karyakar_name_secondary, karyakar_name_tertiary,
         salutation, post_nominals, dietary, interest_tags, protocol_notes, vip_category, contribution_notes, sub_sector, date_of_birth,
         approval_status, submitted_by_user_id, submitted_by_name
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22) RETURNING *`,
      [
        cleanText(fullName, 120),
        cleanText(email, 180).toLowerCase(),
        cleanText(designation, 120),
        cleanText(organization, 160),
        townVal || null,
        phoneVal || null,
        cat,
        kar || null,
        kar2 || null,
        kar3 || null,
        sal || null,
        postN || null,
        diet || null,
        tags || null,
        proto || null,
        vip || null,
        contrib || null,
        subSec || null,
        dob || null,
        approval,
        submitterId,
        submitterName,
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to create dignitary." });
  }
});

app.patch("/api/dignitaries/:id/approval", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid dignitary id.");
  const approval = String(req.body?.approvalStatus || req.body?.approval || "")
    .trim()
    .toUpperCase();
  if (!["APPROVED", "REJECTED", "PENDING"].includes(approval)) {
    return badRequest(res, "approvalStatus must be APPROVED, REJECTED, or PENDING.");
  }
  let approvedBy = req.body?.approvedByUserId ? Number(req.body.approvedByUserId) : null;
  if (approvedBy != null && (!Number.isInteger(approvedBy) || approvedBy <= 0)) approvedBy = null;
  const note = cleanText(req.body?.rejectionNote || req.body?.note || "", 1000) || null;

  try {
    const result = await db.query(
      `UPDATE dignitaries SET
         approval_status = $1,
         approved_by_user_id = CASE WHEN $1 = 'PENDING' THEN NULL ELSE COALESCE($2, approved_by_user_id) END,
         approved_at = CASE WHEN $1 = 'PENDING' THEN NULL ELSE NOW() END,
         rejection_note = CASE WHEN $1 = 'REJECTED' THEN $3 ELSE NULL END
       WHERE id = $4
       RETURNING *`,
      [approval, approvedBy, note, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Dignitary not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to update approval." });
  }
});

function normalizeDignitaryStatus(raw) {
  const s = String(raw == null ? "" : raw).trim().toUpperCase();
  if (s === "INACTIVE" || s === "DISABLED" || s === "OFF" || s === "0" || s === "FALSE") return "INACTIVE";
  if (s === "ACTIVE" || s === "ENABLED" || s === "ON" || s === "1" || s === "TRUE") return "ACTIVE";
  return "";
}

app.patch("/api/dignitaries/:id/status", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid dignitary id.");
  const body = req.body && typeof req.body === "object" ? req.body : {};
  let st = normalizeDignitaryStatus(
    body.recordStatus ?? body.activeStatus ?? body.status ?? body.st ?? req.query?.value ?? req.query?.status
  );
  if (!st && "enabled" in body) st = body.enabled === false || body.enabled === "false" || body.enabled === 0 ? "INACTIVE" : "ACTIVE";
  if (!st) return badRequest(res, "status must be ACTIVE or INACTIVE.");
  try {
    const result = await db.query(
      `UPDATE dignitaries SET status = $1 WHERE id = $2 RETURNING *`,
      [st, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Dignitary not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to update dignitary status." });
  }
});

app.patch("/api/dignitaries/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid dignitary id.");
  const body = req.body || {};
  const sets = [];
  const vals = [];
  let i = 1;
  const map = {
    fullName: ["full_name", 120],
    email: ["email", 180],
    designation: ["designation", 120],
    organization: ["organization", 160],
    town: ["town", 120],
    phone: ["phone", 40],
    category: ["category", 40],
    karyakarName: ["karyakar_name", 120],
    karyakarNameSecondary: ["karyakar_name_secondary", 120],
    karyakarNameTertiary: ["karyakar_name_tertiary", 120],
    salutation: ["salutation", 40],
    postNominals: ["post_nominals", 120],
    dietary: ["dietary", 80],
    interestTags: ["interest_tags", 500],
    protocolNotes: ["protocol_notes", 2000],
    vipCategory: ["vip_category", 10],
    contributionNotes: ["contribution_notes", 2000],
    subSector: ["sub_sector", 80],
    dateOfBirth: ["date_of_birth", 10],
    recordStatus: ["status", 20],
  };
  for (const [key, [col, max]] of Object.entries(map)) {
    if (!(key in body)) continue;
    let v = cleanText(body[key] == null ? "" : String(body[key]), max);
    if (key === "email") {
      if (!isEmail(v)) return badRequest(res, "Invalid email.");
      v = v.toLowerCase();
    }
    if (key === "category" && !v) v = "Government";
    if (key === "dateOfBirth") {
      if (v && !/^\d{4}-\d{2}-\d{2}$/.test(v)) v = "";
    }
    if (key === "vipCategory") {
      v = String(v || "").toUpperCase().replace(/\s+/g, "");
      if (v === "1") v = "V1";
      if (v === "2") v = "V2";
      if (v === "3") v = "V3";
      if (!["V1", "V2", "V3"].includes(v)) v = "";
    }
    if (key === "recordStatus") {
      v = normalizeDignitaryStatus(v);
      if (!v) return badRequest(res, "status must be ACTIVE or INACTIVE.");
    }
    sets.push(`${col} = $${i++}`);
    vals.push(v || null);
  }
  const statusRaw = body.recordStatus ?? body.activeStatus ?? body.status ?? body.st;
  if (!sets.some((s) => s.startsWith("status =")) && statusRaw != null && String(statusRaw).trim() !== "") {
    const st = normalizeDignitaryStatus(statusRaw);
    if (!st) return badRequest(res, "status must be ACTIVE or INACTIVE.");
    sets.push(`status = $${i++}`);
    vals.push(st);
  }
  if (!sets.length) return badRequest(res, "No fields to update.");
  vals.push(id);
  try {
    const result = await db.query(
      `UPDATE dignitaries SET ${sets.join(", ")} WHERE id = $${i} RETURNING *`,
      vals
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Dignitary not found." });
    return res.json(result.rows[0]);
  } catch (err) {
    if (String(err.message).includes("duplicate key")) return badRequest(res, "Email already exists.");
    return res.status(500).json({ error: "Failed to update dignitary." });
  }
});

app.post("/api/dignitaries/import", async (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : null;
  if (!rows) return badRequest(res, "rows[] is required.");
  if (rows.length > 5000) return badRequest(res, "Too many rows. Max 5000 per import.");

  let importApproval = String(req.body?.approvalStatus || "APPROVED")
    .trim()
    .toUpperCase();
  if (!["PENDING", "APPROVED", "REJECTED"].includes(importApproval)) importApproval = "APPROVED";
  let submitterId = req.body?.submittedByUserId ? Number(req.body.submittedByUserId) : null;
  if (submitterId != null && (!Number.isInteger(submitterId) || submitterId <= 0)) submitterId = null;
  const submitterName = cleanText(req.body?.submittedByName || "", 120) || null;

  const stats = {
    total: rows.length,
    added: 0,
    skipped: 0,
    invalid: 0,
    duplicate: 0,
    generatedEmail: 0,
    generatedName: 0,
    failed: 0,
    pendingApproval: 0,
  };

  for (let i = 0; i < rows.length; i++) {
    const raw = rows[i] || {};
    let fullName = cleanText(raw.fullName || "", 120);
    const designation = cleanText(raw.designation || "", 120);
    const organization = cleanText(raw.organization || "", 160);
    const town = cleanText(raw.town || raw.city || "", 120);
    const rawEmail = cleanText(raw.email || "", 180).toLowerCase();
    const phone = cleanText(raw.phone || raw.whatsapp || "", 40);
    let category = cleanText(raw.category || "", 40);
    if (!category) category = "Government";
    let karyakarName = cleanText(raw.karyakarName || raw.karyakar || "", 120);
    if (!karyakarName && submitterName) karyakarName = submitterName;
    const karyakarNameSecondary = cleanText(
      raw.karyakarNameSecondary || raw.karyakarSecondary || raw.secondaryKaryakar || "",
      120
    );
    const karyakarNameTertiary = cleanText(
      raw.karyakarNameTertiary || raw.karyakarTertiary || raw.tertiaryKaryakar || "",
      120
    );
    const salutation = cleanText(raw.salutation || raw.title || "", 40);
    const postNominals = cleanText(raw.postNominals || raw.postnominals || raw.credentials || "", 120);
    const dietary = cleanText(raw.dietary || "", 80);
    const interestTags = cleanText(raw.interestTags || raw.tags || raw.interests || "", 500);
    const protocolNotes = cleanText(raw.protocolNotes || raw.notes || "", 2000);
    const contributionNotes = cleanText(
      raw.contributionNotes || raw.sansthaContribution || raw.contribution || "",
      2000
    );
    const subSector = cleanText(raw.subSector || raw.subsector || raw.sub_sector || "", 80);
    let dateOfBirth = cleanText(raw.dateOfBirth || raw.dob || raw.date_of_birth || "", 10);
    if (dateOfBirth && !/^\d{4}-\d{2}-\d{2}$/.test(dateOfBirth)) dateOfBirth = "";
    let vipCategory = cleanText(raw.vipCategory || raw.vip || "", 10).toUpperCase().replace(/\s+/g, "");
    if (vipCategory === "1") vipCategory = "V1";
    if (vipCategory === "2") vipCategory = "V2";
    if (vipCategory === "3") vipCategory = "V3";
    if (!["V1", "V2", "V3"].includes(vipCategory)) vipCategory = "";

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
             full_name, email, designation, organization, town, phone, category, karyakar_name,
             karyakar_name_secondary, karyakar_name_tertiary,
             salutation, post_nominals, dietary, interest_tags, protocol_notes, vip_category, contribution_notes, sub_sector, date_of_birth,
             approval_status, submitted_by_user_id, submitted_by_name
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
           ON CONFLICT (email) DO NOTHING RETURNING id`,
          [
            fullName,
            tryEmail,
            designation,
            organization,
            town || null,
            phone || null,
            category,
            karyakarName || null,
            karyakarNameSecondary || null,
            karyakarNameTertiary || null,
            salutation || null,
            postNominals || null,
            dietary || null,
            interestTags || null,
            protocolNotes || null,
            vipCategory || null,
            contributionNotes || null,
            subSector || null,
            dateOfBirth || null,
            importApproval,
            submitterId,
            submitterName,
          ]
        );
        if (result.rows[0]) {
          stats.added++;
          if (importApproval === "PENDING") stats.pendingApproval++;
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
      `SELECT id, title, event_date, event_time, venue, description, schedule, standard_message, status, attendance_enabled, created_at,
              (invitation_template IS NOT NULL AND LENGTH(TRIM(invitation_template)) > 2) AS has_invitation_template
       FROM events ORDER BY event_date DESC`
    );
    return res.json(result.rows.map(withEventSchedule));
  } catch (err) {
    console.error("Load events failed:", err.message || err);
    return res.status(500).json({ error: "Failed to load events." });
  }
});

app.post("/api/events", async (req, res) => {
  const { title, venue, description, standardMessage } = req.body || {};
  const status = parseEventStatus(req.body?.status, "PUBLISHED");
  const days = normalizeEventDays(req.body || {});
  const name = cleanText(title, 160);
  if (!name) {
    return badRequest(res, "title is required.");
  }
  if (status === "PUBLISHED") {
    if (!venue) {
      return badRequest(res, "title and venue are required.");
    }
    if (!days.length) {
      return badRequest(res, "Add at least one event day with a date.");
    }
  }
  try {
    const result = await db.query(
      `INSERT INTO events (title, event_date, event_time, venue, description, schedule, standard_message, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, title, event_date, event_time, venue, description, schedule, standard_message, status, attendance_enabled, invitation_template, created_at`,
      [
        name,
        days[0]?.date || "",
        eventTimeSummary(days),
        cleanText(venue, 180),
        typeof description === "string" ? cleanText(description, 4000) : "",
        JSON.stringify(days),
        typeof standardMessage === "string" ? cleanMultilineText(standardMessage, 4000) : "",
        status,
      ]
    );
    return res.status(201).json(withEventSchedule(result.rows[0]));
  } catch (err) {
    console.error("Create event failed:", err.message || err);
    return res.status(500).json({ error: "Failed to create event." });
  }
});

app.patch("/api/events/:id", async (req, res) => {
  const id = Number(req.params.id);
  const { title, venue, description, standardMessage } = req.body || {};
  const days = normalizeEventDays(req.body || {});
  if (!Number.isInteger(id) || id < 1) {
    return badRequest(res, "Invalid event id.");
  }
  const name = cleanText(title, 160);
  if (!name) {
    return badRequest(res, "title is required.");
  }
  try {
    const cur = await db.query(`SELECT status FROM events WHERE id = $1`, [id]);
    if (!cur.rows[0]) return res.status(404).json({ error: "Event not found." });
    const status = parseEventStatus(req.body?.status, cur.rows[0].status || "PUBLISHED");
    if (status === "PUBLISHED") {
      if (!venue) {
        return badRequest(res, "title and venue are required.");
      }
      if (!days.length) {
        return badRequest(res, "Add at least one event day with a date.");
      }
    }
    const result = await db.query(
      `UPDATE events SET title = $1, event_date = $2, event_time = $3, venue = $4, description = $5, schedule = $6, standard_message = $7, status = $8
       WHERE id = $9 RETURNING id, title, event_date, event_time, venue, description, schedule, standard_message, status, attendance_enabled, invitation_template, created_at`,
      [
        name,
        days[0]?.date || "",
        eventTimeSummary(days),
        cleanText(venue, 180),
        typeof description === "string" ? cleanText(description, 4000) : "",
        JSON.stringify(days),
        typeof standardMessage === "string" ? cleanMultilineText(standardMessage, 4000) : "",
        status,
        id,
      ]
    );
    if (!result.rowCount) {
      return res.status(404).json({ error: "Event not found." });
    }
    return res.json(withEventSchedule(result.rows[0]));
  } catch (err) {
    console.error("Update event failed:", err.message || err);
    return res.status(500).json({ error: "Failed to update event." });
  }
});

app.patch("/api/events/:id/attendance-enabled", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid event id.");
  const raw = req.body?.enabled ?? req.body?.attendanceEnabled ?? req.body?.attendance_enabled;
  const enabled = raw === true || raw === "true" || raw === 1 || raw === "1";
  try {
    const result = await db.query(
      `UPDATE events SET attendance_enabled = $1
       WHERE id = $2
       RETURNING id, title, event_date, event_time, venue, description, schedule, standard_message, status, attendance_enabled, invitation_template, created_at`,
      [enabled, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Event not found." });
    return res.json(withEventSchedule(result.rows[0]));
  } catch (err) {
    console.error("Update event attendance flag failed:", err.message || err);
    return res.status(500).json({ error: "Failed to update attendance setting." });
  }
});

app.delete("/api/events/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid event id.");
  try {
    // Clear dependent rows first (invitations restrict event delete; notifications use SET NULL).
    await db.query("DELETE FROM invitations WHERE event_id = $1", [id]);
    const result = await db.query("DELETE FROM events WHERE id = $1 RETURNING id", [id]);
    if (!result.rows[0]) return res.status(404).json({ error: "Event not found." });
    return res.json({ ok: true, deletedId: id });
  } catch (err) {
    console.error("Delete event failed:", err.message || err);
    return res.status(500).json({ error: "Failed to delete event." });
  }
});

app.get("/api/events/:id/invitation-template", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid event id.");
  try {
    const result = await db.query(
      "SELECT id, invitation_template FROM events WHERE id = $1",
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Event not found." });
    let template = null;
    const raw = result.rows[0].invitation_template;
    if (raw) {
      try {
        template = typeof raw === "string" ? JSON.parse(raw) : raw;
      } catch {
        template = null;
      }
    }
    return res.json({ eventId: result.rows[0].id, template });
  } catch {
    return res.status(500).json({ error: "Failed to load invitation template." });
  }
});

app.put("/api/events/:id/invitation-template", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid event id.");
  const template = req.body?.template ?? req.body;
  if (!template || typeof template !== "object" || Array.isArray(template)) {
    return badRequest(res, "template object is required.");
  }
  let payload;
  try {
    payload = JSON.stringify(template);
  } catch {
    return badRequest(res, "template must be JSON-serializable.");
  }
  if (payload.length > 10 * 1024 * 1024) {
    return badRequest(res, "template is too large (max 10MB).");
  }
  try {
    const result = await db.query(
      `UPDATE events SET invitation_template = $1 WHERE id = $2
       RETURNING id, title`,
      [payload, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Event not found." });
    return res.json({ ok: true, eventId: result.rows[0].id, title: result.rows[0].title });
  } catch {
    return res.status(500).json({ error: "Failed to save invitation template." });
  }
});

app.delete("/api/events/:id/invitation-template", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return badRequest(res, "Invalid event id.");
  try {
    const result = await db.query(
      `UPDATE events SET invitation_template = NULL WHERE id = $1 RETURNING id`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Event not found." });
    return res.json({ ok: true, eventId: id });
  } catch {
    return res.status(500).json({ error: "Failed to clear invitation template." });
  }
});

// Invitations
app.get("/api/invitations", async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT i.id, i.custom_message, i.status, i.sent_at, i.created_at,
             i.rsvp_status, i.rsvp_channels, i.admin_approval, i.attended, i.attended_at, i.rsvp_token,
             i.ladies_count, i.gents_count, i.tracker_notes, i.day_rsvp, i.day_attendance, i.day_counts,
             d.id AS dignitary_id, d.full_name AS dignitary_name, d.email AS dignitary_email,
             d.designation AS dignitary_designation, d.organization AS dignitary_organization,
             d.karyakar_name, d.karyakar_name_secondary, d.karyakar_name_tertiary,
             d.phone AS dignitary_phone, d.protocol_notes,
             e.id AS event_id, e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      ORDER BY i.id DESC
    `);
    return res.json(result.rows.map(withRsvpFields));
  } catch {
    return res.status(500).json({ error: "Failed to load invitations." });
  }
});

app.post("/api/invitations", async (req, res) => {
  const { dignitaryId, eventId, customMessage } = req.body || {};
  if (!dignitaryId || !eventId) return badRequest(res, "dignitaryId and eventId are required.");
  try {
    const dignitary = await db.query(
      `SELECT id,
              COALESCE(NULLIF(UPPER(TRIM(approval_status)), ''), 'APPROVED') AS approval_status,
              COALESCE(NULLIF(UPPER(TRIM(status)), ''), 'ACTIVE') AS status
       FROM dignitaries WHERE id = $1`,
      [dignitaryId]
    );
    const event = await db.query("SELECT id, standard_message FROM events WHERE id = $1", [eventId]);
    if (!dignitary.rows[0] || !event.rows[0]) return badRequest(res, "Invalid dignitaryId or eventId.");
    if (dignitary.rows[0].approval_status !== "APPROVED") {
      return badRequest(res, "Dignitary must be approved by admin before inviting.");
    }
    if (dignitary.rows[0].status === "INACTIVE") {
      return badRequest(res, "Dignitary is inactive. Enable them before inviting.");
    }

    const token = crypto.randomBytes(24).toString("base64url");
    const inviteMsg =
      cleanMultilineText(customMessage, 2000) ||
      cleanMultilineText(event.rows[0].standard_message || "", 2000);
    const result = await db.query(
      `INSERT INTO invitations (dignitary_id, event_id, custom_message, rsvp_token)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [dignitaryId, eventId, inviteMsg, token]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create invitation." });
  }
});

const RSVP_STATUSES = ["PENDING", "ACCEPTED", "DECLINED", "BY_PHONE", "BY_EMAIL", "BY_WHATSAPP", "IN_PERSON"];
const RSVP_CHANNEL_KEYS = ["BY_WHATSAPP", "BY_EMAIL", "IN_PERSON", "BY_PHONE"];

const RSVP_CHANNEL_TO_COMM = {
  BY_WHATSAPP: { type: "WHATSAPP", label: "WhatsApp" },
  BY_EMAIL: { type: "EMAIL", label: "Email" },
  IN_PERSON: { type: "VISIT", label: "in-person" },
  BY_PHONE: { type: "PHONE_CALL", label: "phone" },
};

function parseRsvpChannels(raw, rsvpStatus) {
  let channels = [];
  if (Array.isArray(raw)) {
    channels = raw;
  } else if (typeof raw === "string" && raw.trim()) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) channels = parsed;
    } catch {
      channels = [];
    }
  }
  channels = [
    ...new Set(
      channels
        .map((c) => String(c || "").trim().toUpperCase().replace(/\s+/g, "_"))
        .filter((c) => RSVP_CHANNEL_KEYS.includes(c))
    ),
  ];
  const st = String(rsvpStatus || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (!channels.length && RSVP_CHANNEL_KEYS.includes(st)) channels = [st];
  return channels;
}

function deriveRsvpStatus(channels, declined, previousStatus) {
  if (declined) return "DECLINED";
  if (channels.length === 1) return channels[0];
  if (channels.length > 1) return "ACCEPTED";
  const prev = String(previousStatus || "").toUpperCase();
  if (prev === "ACCEPTED") return "ACCEPTED";
  return "PENDING";
}

function parseDayAttendance(raw) {
  let o = raw;
  if (typeof raw === "string") {
    if (!raw.trim()) return {};
    try {
      o = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) return {};
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    if (v === false || v == null || v === "" || v === 0 || v === "0" || v === "false") continue;
    if (v === true || v === 1 || v === "1" || String(v).toUpperCase() === "TRUE") {
      out[String(k)] = "1";
      continue;
    }
    const d = new Date(v);
    out[String(k)] = Number.isNaN(d.getTime()) ? "1" : d.toISOString();
  }
  return out;
}

function seedDayAttendanceFromLegacy(row) {
  const dayAtt = parseDayAttendance(row?.day_attendance);
  if (Object.keys(dayAtt).length) return dayAtt;
  if (row?.attended) {
    const at = row.attended_at ? new Date(row.attended_at) : null;
    return { 0: at && !Number.isNaN(at.getTime()) ? at.toISOString() : "1" };
  }
  return {};
}

function rollupAttendance(dayAtt) {
  const keys = Object.keys(dayAtt || {});
  const times = keys
    .map((k) => {
      const d = new Date(dayAtt[k]);
      return Number.isNaN(d.getTime()) ? null : d.toISOString();
    })
    .filter(Boolean)
    .sort();
  return {
    attended: keys.length > 0,
    attended_at: times[0] || null,
  };
}

function parseDayCounts(raw) {
  let o = raw;
  if (typeof raw === "string") {
    if (!raw.trim()) return {};
    try {
      o = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) return {};
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    const idx = Number(k);
    if (!Number.isInteger(idx) || idx < 0 || idx > 31) continue;
    let ladies = 0;
    let gents = 0;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const ln = Number(v.ladies);
      const gn = Number(v.gents);
      if (Number.isInteger(ln) && ln >= 0 && ln <= 10) ladies = ln;
      if (Number.isInteger(gn) && gn >= 0 && gn <= 10) gents = gn;
    }
    if (ladies || gents) out[String(idx)] = { ladies, gents };
  }
  return out;
}

function seedDayCountsFromLegacy(row) {
  const parsed = parseDayCounts(row?.day_counts);
  if (Object.keys(parsed).length) return parsed;
  const ladies = Number(row?.ladies_count) || 0;
  const gents = Number(row?.gents_count) || 0;
  if (ladies || gents) return { 0: { ladies, gents } };
  return {};
}

function rollupDayCounts(dayCounts) {
  let ladies = 0;
  let gents = 0;
  for (const rec of Object.values(dayCounts || {})) {
    ladies += Number(rec?.ladies) || 0;
    gents += Number(rec?.gents) || 0;
  }
  return { ladies_count: ladies, gents_count: gents };
}

function withRsvpFields(row) {
  if (!row) return row;
  const dayAtt = seedDayAttendanceFromLegacy(row);
  const att = rollupAttendance(dayAtt);
  const dayCounts = seedDayCountsFromLegacy(row);
  const counts = rollupDayCounts(dayCounts);
  return {
    ...row,
    rsvp_channels: parseRsvpChannels(row.rsvp_channels, row.rsvp_status),
    day_rsvp: parseDayRsvp(row.day_rsvp),
    day_counts: dayCounts,
    ladies_count: Object.keys(dayCounts).length ? counts.ladies_count : Number(row.ladies_count) || 0,
    gents_count: Object.keys(dayCounts).length ? counts.gents_count : Number(row.gents_count) || 0,
    tracker_notes: row.tracker_notes || "",
    day_attendance: dayAtt,
    attended: att.attended,
    attended_at: att.attended_at || row.attended_at || null,
  };
}

function parseDayRsvp(raw) {
  let o = raw;
  if (typeof raw === "string") {
    if (!raw.trim()) return {};
    try {
      o = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!o || typeof o !== "object" || Array.isArray(o)) return {};
  const out = {};
  for (const [k, v] of Object.entries(o)) {
    const st = String(v || "").toUpperCase();
    if (st === "ACCEPTED" || st === "DECLINED") out[String(k)] = st;
  }
  return out;
}

function rollupRsvpFromDays(dayRsvp, fallback) {
  const vals = Object.values(dayRsvp || {});
  if (vals.includes("ACCEPTED")) return "ACCEPTED";
  if (vals.length && vals.every((v) => v === "DECLINED")) return "DECLINED";
  return fallback || "PENDING";
}

async function logRsvpChannelCommunication(invitationId, status, requestedUserId) {
  const channel = RSVP_CHANNEL_TO_COMM[status];
  if (!channel) return;
  const invite = await db.query(
    `SELECT i.id, i.dignitary_id, e.title AS event_title, d.karyakar_name
     FROM invitations i
     JOIN dignitaries d ON d.id = i.dignitary_id
     JOIN events e ON e.id = i.event_id
     WHERE i.id = $1`,
    [invitationId]
  );
  const inv = invite.rows[0];
  if (!inv) return;

  let userId = Number(requestedUserId);
  if (!Number.isInteger(userId) || userId <= 0) {
    const kar = await db.query(
      `SELECT id FROM users
       WHERE UPPER(TRIM(role)) = 'KARYAKAR'
         AND LOWER(TRIM(full_name)) = LOWER(TRIM($1))
       LIMIT 1`,
      [inv.karyakar_name || ""]
    );
    userId = kar.rows[0] ? Number(kar.rows[0].id) : 0;
  } else {
    const user = await db.query(`SELECT id FROM users WHERE id = $1`, [userId]);
    if (!user.rows[0]) userId = 0;
  }
  if (!userId) return;

  const notes = `RSVP recorded via ${channel.label} for ${inv.event_title}.`;
  await db.query(
    `INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at)
     VALUES ($1, $2, $3, $4, NOW())`,
    [inv.dignitary_id, userId, channel.type, notes]
  );
}

app.patch("/api/invitations/:id/rsvp", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid invitation id.");
  const channelRaw = String(req.body?.rsvpChannel || req.body?.channel || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  const hasChannelToggle = Boolean(channelRaw);

  try {
    const cur = await db.query(
      `SELECT id, rsvp_status, rsvp_channels FROM invitations WHERE id = $1`,
      [id]
    );
    if (!cur.rows[0]) return res.status(404).json({ error: "Invitation not found." });

    let channels = parseRsvpChannels(cur.rows[0].rsvp_channels, cur.rows[0].rsvp_status);
    let declined = String(cur.rows[0].rsvp_status || "").toUpperCase() === "DECLINED";
    let addedChannel = null;

    if (hasChannelToggle) {
      if (![...RSVP_CHANNEL_KEYS, "DECLINED"].includes(channelRaw)) {
        return badRequest(
          res,
          "rsvpChannel must be BY_WHATSAPP, BY_EMAIL, IN_PERSON, BY_PHONE, or DECLINED."
        );
      }
      const explicit = req.body?.channelChecked ?? req.body?.checked;
      const on = explicit == null ? true : explicit === true || explicit === "true" || explicit === 1;
      if (channelRaw === "DECLINED") {
        declined = on;
        if (on) channels = [];
      } else if (on) {
        declined = false;
        if (!channels.includes(channelRaw)) channels.push(channelRaw);
        addedChannel = channelRaw;
      } else {
        channels = channels.filter((c) => c !== channelRaw);
      }
    } else {
      const status = String(req.body?.rsvpStatus || req.body?.status || "")
        .trim()
        .toUpperCase()
        .replace(/\s+/g, "_");
      if (!RSVP_STATUSES.includes(status)) {
        return badRequest(
          res,
          "rsvpStatus must be PENDING, ACCEPTED, DECLINED, BY_PHONE, BY_EMAIL, BY_WHATSAPP, or IN_PERSON."
        );
      }
      if (status === "PENDING") {
        declined = false;
      } else if (status === "DECLINED") {
        declined = true;
      } else if (status === "ACCEPTED") {
        declined = false;
      } else if (RSVP_CHANNEL_KEYS.includes(status)) {
        declined = false;
        if (!channels.includes(status)) addedChannel = status;
        channels = [status];
      }
    }

    let nextStatus;
    if (!hasChannelToggle) {
      const status = String(req.body?.rsvpStatus || req.body?.status || "")
        .trim()
        .toUpperCase()
        .replace(/\s+/g, "_");
      if (status === "ACCEPTED" || status === "DECLINED" || status === "PENDING") {
        nextStatus = status;
      } else {
        nextStatus = deriveRsvpStatus(channels, declined, cur.rows[0].rsvp_status);
      }
    } else {
      const prev = String(cur.rows[0].rsvp_status || "").toUpperCase();
      if (declined) nextStatus = "DECLINED";
      else if (prev === "ACCEPTED") nextStatus = "ACCEPTED";
      else nextStatus = deriveRsvpStatus(channels, declined, cur.rows[0].rsvp_status);
    }
    const result = await db.query(
      `UPDATE invitations SET rsvp_status = $1, rsvp_channels = $2 WHERE id = $3
       RETURNING id, rsvp_status, rsvp_channels, admin_approval, attended, attended_at, status`,
      [nextStatus, JSON.stringify(channels), id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Invitation not found." });
    if (addedChannel) await logRsvpChannelCommunication(id, addedChannel, req.body?.userId);
    return res.json(withRsvpFields(result.rows[0]));
  } catch {
    return res.status(500).json({ error: "Failed to update RSVP." });
  }
});

app.patch("/api/invitations/:id/tracker", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid invitation id.");
  const body = req.body && typeof req.body === "object" ? req.body : {};
  try {
    const cur = await db.query(
      `SELECT id, rsvp_status, day_rsvp, ladies_count, gents_count, tracker_notes, day_counts FROM invitations WHERE id = $1`,
      [id]
    );
    if (!cur.rows[0]) return res.status(404).json({ error: "Invitation not found." });

    let dayRsvp = parseDayRsvp(cur.rows[0].day_rsvp);
    if (body.dayRsvp != null) dayRsvp = parseDayRsvp(body.dayRsvp);
    const rsvpStatusPatch =
      body.dayRsvpStatus != null
        ? body.dayRsvpStatus
        : body.status != null && body.ladiesCount == null && body.gentsCount == null
          ? body.status
          : null;
    if (body.dayIndex != null && body.dayIndex !== "" && rsvpStatusPatch != null) {
      const idx = Number(body.dayIndex);
      if (!Number.isInteger(idx) || idx < 0 || idx > 31) {
        return badRequest(res, "dayIndex must be an integer from 0 to 31.");
      }
      const st = String(rsvpStatusPatch || "")
        .trim()
        .toUpperCase();
      if (st === "PENDING" || st === "") delete dayRsvp[String(idx)];
      else if (st === "ACCEPTED" || st === "DECLINED") dayRsvp[String(idx)] = st;
      else return badRequest(res, "dayRsvpStatus must be ACCEPTED, DECLINED, or PENDING.");
    }

    const clampCount = (raw, fallback) => {
      if (raw == null || raw === "") return fallback;
      const n = Number(raw);
      if (!Number.isInteger(n) || n < 0 || n > 10) return null;
      return n;
    };
    let dayCounts = seedDayCountsFromLegacy(cur.rows[0]);
    if (body.dayCounts != null) dayCounts = parseDayCounts(body.dayCounts);
    if (body.ladiesCount != null || body.gentsCount != null) {
      let idx = 0;
      if (body.dayIndex != null && body.dayIndex !== "") {
        idx = Number(body.dayIndex);
        if (!Number.isInteger(idx) || idx < 0 || idx > 31) {
          return badRequest(res, "dayIndex must be an integer from 0 to 31.");
        }
      }
      const curDay = { ladies: 0, gents: 0, ...(dayCounts[String(idx)] || {}) };
      if (body.ladiesCount != null) {
        const n = clampCount(body.ladiesCount, 0);
        if (n == null) return badRequest(res, "ladiesCount must be 0–10.");
        curDay.ladies = n;
      }
      if (body.gentsCount != null) {
        const n = clampCount(body.gentsCount, 0);
        if (n == null) return badRequest(res, "gentsCount must be 0–10.");
        curDay.gents = n;
      }
      if (!curDay.ladies && !curDay.gents) delete dayCounts[String(idx)];
      else dayCounts[String(idx)] = { ladies: curDay.ladies || 0, gents: curDay.gents || 0 };
    }
    const counts = rollupDayCounts(dayCounts);
    const ladies = counts.ladies_count;
    const gents = counts.gents_count;

    let notes = cur.rows[0].tracker_notes || "";
    if (typeof body.trackerNotes === "string") notes = cleanText(body.trackerNotes, 2000);

    const nextStatus = Object.keys(dayRsvp).length
      ? rollupRsvpFromDays(dayRsvp, cur.rows[0].rsvp_status)
      : cur.rows[0].rsvp_status;

    const result = await db.query(
      `UPDATE invitations
       SET day_rsvp = $1, ladies_count = $2, gents_count = $3, tracker_notes = $4, rsvp_status = $5, day_counts = $6
       WHERE id = $7
       RETURNING id, rsvp_status, rsvp_channels, ladies_count, gents_count, tracker_notes, day_rsvp, day_counts`,
      [JSON.stringify(dayRsvp), ladies, gents, notes, nextStatus, JSON.stringify(dayCounts), id]
    );
    return res.json(withRsvpFields(result.rows[0]));
  } catch {
    return res.status(500).json({ error: "Failed to update tracker details." });
  }
});

app.patch("/api/invitations/:id/approval", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid invitation id.");
  const approval = String(req.body?.adminApproval || req.body?.approval || "")
    .trim()
    .toUpperCase();
  if (!["PENDING", "APPROVED", "REJECTED"].includes(approval)) {
    return badRequest(res, "adminApproval must be PENDING, APPROVED, or REJECTED.");
  }
  try {
    const result = await db.query(
      `UPDATE invitations SET admin_approval = $1 WHERE id = $2
       RETURNING id, rsvp_status, admin_approval, attended, attended_at, status`,
      [approval, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Invitation not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to update approval." });
  }
});

app.patch("/api/invitations/:id/attendance", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid invitation id.");
  const attended = req.body?.attended === true || req.body?.attended === "true" || req.body?.attended === 1;
  try {
    const cur = await db.query(
      `SELECT id, attended, attended_at, day_attendance FROM invitations WHERE id = $1`,
      [id]
    );
    if (!cur.rows[0]) return res.status(404).json({ error: "Invitation not found." });

    let dayAtt = seedDayAttendanceFromLegacy(cur.rows[0]);
    const hasDay = req.body?.dayIndex != null && req.body?.dayIndex !== "";
    if (hasDay) {
      const idx = Number(req.body.dayIndex);
      if (!Number.isInteger(idx) || idx < 0 || idx > 31) {
        return badRequest(res, "dayIndex must be an integer from 0 to 31.");
      }
      const key = String(idx);
      if (attended) {
        const existing = dayAtt[key] ? new Date(dayAtt[key]) : null;
        if (!existing || Number.isNaN(existing.getTime())) dayAtt[key] = new Date().toISOString();
      } else {
        delete dayAtt[key];
      }
    } else if (attended) {
      const existing = dayAtt["0"] ? new Date(dayAtt["0"]) : null;
      if (!existing || Number.isNaN(existing.getTime())) dayAtt["0"] = new Date().toISOString();
    } else {
      dayAtt = {};
    }

    const rollup = rollupAttendance(dayAtt);
    const result = await db.query(
      `UPDATE invitations
       SET day_attendance = $1, attended = $2, attended_at = $3
       WHERE id = $4
       RETURNING id, rsvp_status, admin_approval, attended, attended_at, status, day_attendance`,
      [JSON.stringify(dayAtt), rollup.attended, rollup.attended_at, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Invitation not found." });
    return res.json(withRsvpFields(result.rows[0]));
  } catch {
    return res.status(500).json({ error: "Failed to update attendance." });
  }
});

app.get("/api/events/:id/volunteer-attendance", async (req, res) => {
  const eventId = Number(req.params.id);
  if (!Number.isInteger(eventId) || eventId <= 0) return badRequest(res, "Invalid event id.");
  try {
    const event = await db.query(`SELECT id, title FROM events WHERE id = $1`, [eventId]);
    if (!event.rows[0]) return res.status(404).json({ error: "Event not found." });
    const result = await db.query(
      `SELECT u.id AS user_id, u.full_name, u.email, u.phone, u.assigned_area, u.status AS user_status,
              COALESCE(va.attended, FALSE) AS attended,
              va.attended_at,
              (
                SELECT COUNT(*)::int
                FROM invitations i
                JOIN dignitaries d ON d.id = i.dignitary_id
                WHERE i.event_id = $1
                  AND (
                    LOWER(TRIM(COALESCE(d.karyakar_name, ''))) = LOWER(TRIM(u.full_name))
                    OR LOWER(TRIM(COALESCE(d.karyakar_name_secondary, ''))) = LOWER(TRIM(u.full_name))
                    OR LOWER(TRIM(COALESCE(d.karyakar_name_tertiary, ''))) = LOWER(TRIM(u.full_name))
                  )
              ) AS guest_count
       FROM users u
       LEFT JOIN volunteer_attendance va
         ON va.user_id = u.id AND va.event_id = $1
       WHERE u.role = 'KARYAKAR'
       ORDER BY COALESCE(va.attended, FALSE) ASC, u.full_name ASC`,
      [eventId]
    );
    return res.json({
      eventId,
      eventTitle: event.rows[0].title,
      volunteers: result.rows,
    });
  } catch {
    return res.status(500).json({ error: "Failed to load volunteer attendance." });
  }
});

app.patch("/api/events/:id/volunteer-attendance/:userId", async (req, res) => {
  const eventId = Number(req.params.id);
  const userId = Number(req.params.userId);
  if (!Number.isInteger(eventId) || eventId <= 0) return badRequest(res, "Invalid event id.");
  if (!Number.isInteger(userId) || userId <= 0) return badRequest(res, "Invalid user id.");
  const attended = req.body?.attended === true || req.body?.attended === "true" || req.body?.attended === 1;
  const markedByRaw = Number(req.body?.markedBy);
  const markedBy = Number.isInteger(markedByRaw) && markedByRaw > 0 ? markedByRaw : null;
  try {
    const event = await db.query(`SELECT id FROM events WHERE id = $1`, [eventId]);
    if (!event.rows[0]) return res.status(404).json({ error: "Event not found." });
    const user = await db.query(
      `SELECT id, full_name, role, status FROM users WHERE id = $1 AND role = 'KARYAKAR'`,
      [userId]
    );
    if (!user.rows[0]) return res.status(404).json({ error: "Volunteer not found." });
    const result = await db.query(
      `INSERT INTO volunteer_attendance (event_id, user_id, attended, attended_at, marked_by, updated_at)
       VALUES ($1, $2, $3, CASE WHEN $3 THEN NOW() ELSE NULL END, $4, NOW())
       ON CONFLICT (event_id, user_id) DO UPDATE
         SET attended = EXCLUDED.attended,
             attended_at = CASE
               WHEN EXCLUDED.attended THEN COALESCE(volunteer_attendance.attended_at, NOW())
               ELSE NULL
             END,
             marked_by = EXCLUDED.marked_by,
             updated_at = NOW()
       RETURNING id, event_id, user_id, attended, attended_at, marked_by`,
      [eventId, userId, attended, markedBy]
    );
    return res.json({
      ...result.rows[0],
      full_name: user.rows[0].full_name,
    });
  } catch {
    return res.status(500).json({ error: "Failed to update volunteer attendance." });
  }
});

app.get("/api/events/:id/guests", async (req, res) => {
  const eventId = Number(req.params.id);
  if (!Number.isInteger(eventId) || eventId <= 0) return badRequest(res, "Invalid event id.");
  try {
    const result = await db.query(
      `SELECT i.id AS invitation_id, i.status, i.rsvp_status, i.rsvp_channels, i.admin_approval, i.attended, i.attended_at, i.day_attendance,
              d.id AS dignitary_id, d.full_name AS dignitary_name, d.email AS dignitary_email,
              d.phone AS dignitary_phone, d.protocol_notes,
              d.karyakar_name, d.karyakar_name_secondary, d.karyakar_name_tertiary,
              e.id AS event_id, e.title AS event_title
       FROM invitations i
       JOIN dignitaries d ON d.id = i.dignitary_id
       JOIN events e ON e.id = i.event_id
       WHERE i.event_id = $1
       ORDER BY d.full_name ASC`,
      [eventId]
    );
    return res.json(result.rows.map(withRsvpFields));
  } catch {
    return res.status(500).json({ error: "Failed to load guest list." });
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
      SELECT i.id, i.custom_message, d.full_name AS dignitary_name, d.salutation AS dignitary_salutation, d.designation, d.organization, d.email,
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
  const dignitaryDisplayName = invitationRender.formatDignitaryName(invite);
  const dateLine = invitationRender.formatDateDisplay(invite.event_date);
  const textBody = [
    `Dear ${dignitaryDisplayName},`,
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
    const emailSettings = await readEmailSettings();
    const pm = await postmark.sendEmail({
      to: invite.email,
      subject,
      htmlBody: html,
      textBody,
      tag: "invitation",
      attachments: attach,
      fromEmail: emailSettings.senderEmail,
      fromName: emailSettings.senderName,
      replyTo: emailSettings.replyTo,
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

app.post("/api/invitations/:id/send-whatsapp", invitationWhatsAppLimiter, async (req, res) => {
  const { userId, customMessage } = req.body || {};
  if (!userId) return badRequest(res, "userId is required.");
  if (!whatsapp.isConfigured()) {
    return res.status(503).json({
      error: "WhatsApp is not configured on the server. Set WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID.",
    });
  }
  const sender = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
  if (!sender.rows[0]) return badRequest(res, "Invalid userId.");

  const inviteResult = await db.query(
    `
      SELECT i.id, i.custom_message, d.id AS dignitary_id, d.full_name AS dignitary_name, d.salutation AS dignitary_salutation, d.phone,
             e.title AS event_title, e.event_date, e.event_time, e.venue
      FROM invitations i
      JOIN dignitaries d ON d.id = i.dignitary_id
      JOIN events e ON e.id = i.event_id
      WHERE i.id = $1
    `,
    [req.params.id]
  );
  const invite = inviteResult.rows[0];
  if (!invite) return res.status(404).json({ error: "Invitation not found." });

  const normalizedPhone = whatsapp.normalizePhoneNumber(invite.phone);
  if (!normalizedPhone) {
    return badRequest(
      res,
      "Dignitary WhatsApp number is missing or invalid. Save an international number (with country code) in the profile."
    );
  }

  const dignitaryDisplayName = invitationRender.formatDignitaryName(invite);
  const dateLine = invitationRender.formatDateDisplay(invite.event_date);
  const customText = typeof customMessage === "string" ? customMessage.trim() : "";
  const messageText =
    cleanText(customText, 2000) ||
    [
      `Jai Swaminarayan ${dignitaryDisplayName},`,
      "",
      invite.custom_message ? String(invite.custom_message).trim() : "You are cordially invited.",
      "",
      `Event: ${invite.event_title}`,
      `Date: ${dateLine}`,
      invite.event_time ? `Time: ${invite.event_time}` : "",
      `Venue: ${invite.venue}`,
      "",
      "With warm regards,",
      "BAPS Africa",
    ]
      .filter(Boolean)
      .join("\n");

  const sent = await whatsapp.sendText({
    to: normalizedPhone,
    text: messageText,
  });
  if (!sent.success) {
    return res.status(502).json({
      error: isProduction ? "WhatsApp delivery failed. Try again or contact support." : sent.error || "WhatsApp send failed.",
      waMeLink: sent.waMeLink || whatsapp.buildWaMeLink(normalizedPhone, messageText) || null,
    });
  }

  await db.query("UPDATE invitations SET status = 'SENT', sent_at = NOW() WHERE id = $1", [invite.id]);
  const commNote = `Invitation WhatsApp sent via Cloud API for ${invite.event_title}${sent.messageId ? ` (message id: ${sent.messageId})` : ""}`;
  await db.query(
    "INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES ($1, $2, $3, $4, NOW())",
    [invite.dignitary_id, userId, "WHATSAPP", commNote]
  );

  return res.json({
    ok: true,
    provider: "whatsapp-cloud-api",
    messageId: sent.messageId || null,
    to: normalizedPhone,
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
  let commType = String(type || "").trim().toUpperCase().replace(/[-\s]+/g, "_");
  if (commType === "IN_PERSON" || commType === "INPERSON") commType = "VISIT";
  if (!allowedTypes.includes(commType)) return badRequest(res, "Invalid communication type.");
  const dignitary = await db.query("SELECT id FROM dignitaries WHERE id = $1", [dignitaryId]);
  const user = await db.query("SELECT id FROM users WHERE id = $1", [userId]);
  if (!dignitary.rows[0] || !user.rows[0]) return badRequest(res, "Invalid dignitaryId or userId.");
  const dt = new Date(happenedAt);
  if (Number.isNaN(dt.getTime())) return badRequest(res, "Invalid happenedAt date.");

  try {
    const result = await db.query(
      "INSERT INTO communications (dignitary_id, user_id, type, notes, happened_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [dignitaryId, userId, commType, cleanText(notes, 3000), dt.toISOString()]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create communication." });
  }
});

// Donations
app.get("/api/donations", async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT d.id, d.dignitary_id, d.donor_name, d.amount, d.donation_date, d.receipt_no,
              d.project, d.note, d.status, d.created_by, d.created_at,
              dig.full_name AS dignitary_name
       FROM donations d
       LEFT JOIN dignitaries dig ON dig.id = d.dignitary_id
       ORDER BY d.id DESC`
    );
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load donations." });
  }
});

app.post("/api/donations", async (req, res) => {
  const { dignitaryId, donorName, amount, donationDate, receiptNo, project, note, createdBy } =
    req.body || {};
  const name = cleanText(donorName || "", 160);
  const amt = Number(amount);
  const date = cleanText(donationDate || "", 40);
  if (!name || !date || !Number.isFinite(amt) || amt <= 0) {
    return badRequest(res, "donorName, positive amount, and donationDate are required.");
  }
  let digId = dignitaryId ? Number(dignitaryId) : null;
  if (digId != null && (!Number.isInteger(digId) || digId <= 0)) digId = null;
  if (digId) {
    const dig = await db.query("SELECT id, full_name FROM dignitaries WHERE id = $1", [digId]);
    if (!dig.rows[0]) return badRequest(res, "Invalid dignitaryId.");
  }
  let creator = createdBy ? Number(createdBy) : null;
  if (creator != null && (!Number.isInteger(creator) || creator <= 0)) creator = null;
  try {
    const result = await db.query(
      `INSERT INTO donations (
         dignitary_id, donor_name, amount, donation_date, receipt_no, project, note, created_by
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [
        digId,
        name,
        amt,
        date,
        cleanText(receiptNo || "", 80) || null,
        cleanText(project || "General", 80) || "General",
        cleanText(note || "", 2000) || null,
        creator,
      ]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to record donation." });
  }
});

// Notifications (karyakar reminders)
app.get("/api/notifications", async (req, res) => {
  const userId = req.query.userId ? Number(req.query.userId) : null;
  try {
    let result;
    if (userId && Number.isInteger(userId) && userId > 0) {
      result = await db.query(
        `SELECT n.id, n.user_id, n.dignitary_id, n.event_id, n.invitation_id, n.message, n.type,
                n.read_at, n.created_by, n.created_at,
                u.full_name AS user_name,
                d.full_name AS dignitary_name,
                e.title AS event_title,
                cb.full_name AS created_by_name
         FROM notifications n
         JOIN users u ON u.id = n.user_id
         LEFT JOIN dignitaries d ON d.id = n.dignitary_id
         LEFT JOIN events e ON e.id = n.event_id
         LEFT JOIN users cb ON cb.id = n.created_by
         WHERE n.user_id = $1
         ORDER BY n.id DESC
         LIMIT 100`,
        [userId]
      );
    } else {
      result = await db.query(
        `SELECT n.id, n.user_id, n.dignitary_id, n.event_id, n.invitation_id, n.message, n.type,
                n.read_at, n.created_by, n.created_at,
                u.full_name AS user_name,
                d.full_name AS dignitary_name,
                e.title AS event_title,
                cb.full_name AS created_by_name
         FROM notifications n
         JOIN users u ON u.id = n.user_id
         LEFT JOIN dignitaries d ON d.id = n.dignitary_id
         LEFT JOIN events e ON e.id = n.event_id
         LEFT JOIN users cb ON cb.id = n.created_by
         ORDER BY n.id DESC
         LIMIT 100`
      );
    }
    return res.json(result.rows);
  } catch {
    return res.status(500).json({ error: "Failed to load notifications." });
  }
});

app.post("/api/notifications/reminder", async (req, res) => {
  const { userId, dignitaryId, eventId, invitationId, message, createdBy } = req.body || {};
  const targetUserId = Number(userId);
  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return badRequest(res, "userId (karyakar) is required.");
  }
  const msg = cleanText(message || "", 2000);
  if (!msg) return badRequest(res, "message is required.");

  const user = await db.query("SELECT id, full_name, role FROM users WHERE id = $1", [targetUserId]);
  if (!user.rows[0]) return badRequest(res, "Invalid userId.");

  let digId = dignitaryId ? Number(dignitaryId) : null;
  let evtId = eventId ? Number(eventId) : null;
  let invId = invitationId ? Number(invitationId) : null;
  if (digId != null && (!Number.isInteger(digId) || digId <= 0)) digId = null;
  if (evtId != null && (!Number.isInteger(evtId) || evtId <= 0)) evtId = null;
  if (invId != null && (!Number.isInteger(invId) || invId <= 0)) invId = null;

  if (digId) {
    const dig = await db.query("SELECT id FROM dignitaries WHERE id = $1", [digId]);
    if (!dig.rows[0]) return badRequest(res, "Invalid dignitaryId.");
  }
  if (evtId) {
    const evt = await db.query("SELECT id FROM events WHERE id = $1", [evtId]);
    if (!evt.rows[0]) return badRequest(res, "Invalid eventId.");
  }

  let creator = createdBy ? Number(createdBy) : null;
  if (creator != null && (!Number.isInteger(creator) || creator <= 0)) creator = null;

  try {
    const result = await db.query(
      `INSERT INTO notifications (
         user_id, dignitary_id, event_id, invitation_id, message, type, created_by
       ) VALUES ($1, $2, $3, $4, $5, 'REMINDER', $6) RETURNING *`,
      [targetUserId, digId, evtId, invId, msg, creator]
    );
    return res.status(201).json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to create reminder." });
  }
});

app.patch("/api/notifications/:id/read", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return badRequest(res, "Invalid notification id.");
  try {
    const result = await db.query(
      `UPDATE notifications SET read_at = COALESCE(read_at, NOW()) WHERE id = $1 RETURNING *`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Notification not found." });
    return res.json(result.rows[0]);
  } catch {
    return res.status(500).json({ error: "Failed to mark notification read." });
  }
});

app.get("/api/lookups", async (_req, res) => {
  try {
    return res.json(await readStoredLookups());
  } catch {
    return res.status(500).json({ error: "Failed to load lookups." });
  }
});

app.put("/api/lookups", requireAdmin, async (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const sectors = uniqLookupLabels(body.sectors, 40, 40);
  if (!sectors.length) return badRequest(res, "At least one sector is required.");
  const normalized = normalizeLookups(body);
  try {
    await db.query(
      `INSERT INTO app_lookups (key, value, updated_at) VALUES ('form_options', $1, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [JSON.stringify(normalized)]
    );
    return res.json(normalized);
  } catch {
    return res.status(500).json({ error: "Failed to save lookups." });
  }
});

app.post("/api/system/backup", requireAdmin, async (req, res) => {
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

if (!isVercel) {
  setInterval(() => {
    createEncryptedBackup()
      .then((details) => {
        if (details) console.log(`Backup created: ${path.basename(details.file)}`);
      })
      .catch(() => {
        console.error("Scheduled backup failed.");
      });
  }, 6 * 60 * 60 * 1000);
}

app.use((_req, res) => {
  res.status(404).json({ error: "Not found." });
});

app.use((err, _req, res, _next) => {
  if (String(err.message || "").includes("CORS blocked")) {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  return res.status(500).json({ error: "Internal server error." });
});

if (!isVercel) {
  ensureBooted()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`PRASAR server running at port ${PORT}`);
      });
    })
    .catch((err) => {
      console.error("Failed to initialize database schema:", err.message);
      process.exit(1);
    });
}

module.exports = app;
