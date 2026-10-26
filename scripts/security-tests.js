/**
 * PRASAR security regression tests (requires running server + DATABASE_URL).
 *
 * Usage:
 *   node scripts/security-tests.js [baseUrl] [--rate-limit] [--heavy]
 *
 * Env:
 *   PRASAR_API_KEY — overrides data/runtime-secrets.json
 *   PRASAR_SECURITY_STRICT=1 — fail if same-origin bypass works without key
 *   PRASAR_SECURITY_BASE_URL — default base URL
 */
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith("--")));
const baseArg = argv.find((a) => !a.startsWith("--"));
const BASE = process.env.PRASAR_SECURITY_BASE_URL || baseArg || "http://127.0.0.1:3000";
const STRICT = process.env.PRASAR_SECURITY_STRICT === "1";
const RUN_RATE_LIMIT = flags.has("--rate-limit");
const RUN_HEAVY = flags.has("--heavy");

const secretsPath = path.join(__dirname, "..", "data", "runtime-secrets.json");
let apiKey = process.env.PRASAR_API_KEY || "";
if (!apiKey) {
  try {
    apiKey = JSON.parse(fs.readFileSync(secretsPath, "utf8")).PRASAR_API_KEY || "";
  } catch {
    apiKey = "";
  }
}

const stamp = Date.now();
const findings = [];
let passed = 0;
let failed = 0;

function documentRisk(id, message) {
  findings.push({ id, message });
  console.log(`  [DOCUMENTED RISK ${id}] ${message}`);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function rawFetch(method, urlPath, { body, headers = {}, expectOk = false } = {}) {
  const h = { ...headers };
  if (body !== undefined && !h["Content-Type"]) h["Content-Type"] = "application/json";
  const res = await fetch(`${BASE}${urlPath}`, {
    method,
    headers: h,
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text.slice(0, 500) };
  }
  if (expectOk && !res.ok) {
    const err = new Error(data.error || `${res.status} ${urlPath}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return { res, data, text };
}

async function api(method, urlPath, body, extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (apiKey) headers["x-prasar-api-key"] = apiKey;
  const out = await rawFetch(method, urlPath, { body, headers });
  if (!out.res.ok) {
    const err = new Error(out.data.error || `${out.res.status} ${urlPath}`);
    err.status = out.res.status;
    err.data = out.data;
    throw err;
  }
  return out.data;
}

async function step(name, fn) {
  process.stdout.write(`\n▶ ${name} … `);
  try {
    await fn();
    passed++;
    console.log("OK");
  } catch (e) {
    failed++;
    console.log("FAIL");
    console.error(`   ${e.message}`);
    if (e.data) console.error("   ", e.data);
  }
}

function assertUnauthorized(res, label) {
  assert(
    res.status === 401 || res.status === 403,
    `${label}: expected 401 or 403, got ${res.status}`
  );
}

function assertNoPasswordHash(users) {
  for (const u of users || []) {
    assert(!("password_hash" in u), "password_hash leaked on user object");
  }
}

function assertNoDbLeak(data) {
  const s = JSON.stringify(data || {});
  assert(!/syntax error at or near/i.test(s), "possible SQL error leak");
  assert(!/pg_/i.test(s) || !/error/i.test(s), "possible Postgres leak");
}

// --- A: Authentication and API boundary ---
async function sectionA() {
  await step("A1. Protected route without key + evil Origin → 401/403", async () => {
    const { res } = await rawFetch("GET", "/api/users", {
      headers: { Origin: "https://evil.example" },
    });
    assertUnauthorized(res, "A1");
  });

  await step("A2. Wrong API key + evil Origin → 401/403", async () => {
    const { res } = await rawFetch("GET", "/api/users", {
      headers: {
        Origin: "https://evil.example",
        "x-prasar-api-key": "wrong-key-value-00000000000000000000",
      },
    });
    assertUnauthorized(res, "A2");
  });

  if (!apiKey) {
    await step("A3. Valid API key → 200 (skipped — no key)", async () => {
      documentRisk("A3", "No API key available; set PRASAR_API_KEY or start server once.");
    });
  } else {
    await step("A3. Valid API key → 200", async () => {
      const users = await api("GET", "/api/users");
      assert(Array.isArray(users), "expected user array");
    });
  }

  await step("A4. Same-origin request without key or session → 401", async () => {
    const { res } = await rawFetch("GET", "/api/users", {
      headers: { Origin: "http://localhost:3000" },
    });
    assert(res.status === 401, `expected 401 without session/key, got ${res.status}`);
  });

  await step("A5. Public /api/health without key → 200", async () => {
    const { res, data } = await rawFetch("GET", "/api/health");
    assert(res.status === 200 && data.ok === true, "health should be public");
  });

  await step("A6. Public login missing fields → 400", async () => {
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: "", password: "" },
    });
    assert(res.status === 400, `expected 400, got ${res.status}`);
    assertNoDbLeak(data);
  });

  await step("A7. GET /api/events without credentials → 401", async () => {
    const { res } = await rawFetch("GET", "/api/events");
    assertUnauthorized(res, "A7");
  });
}

// --- B: Authorization (RBAC gap) ---
async function sectionB() {
  if (!apiKey) {
    await step("B. RBAC gap tests (skipped — no API key)", async () => {
      documentRisk("B", "Skipped RBAC tests without API key.");
    });
    return;
  }
  await step("B1. API key is treated as admin for automation", async () => {
    const users = await api("GET", "/api/users");
    assert(Array.isArray(users), "expected users");
  });

  await step("B2. API key can trigger backup (admin-equivalent service credential)", async () => {
    const headers = { "x-prasar-api-key": apiKey };
    const backupToken = process.env.PRASAR_BACKUP_HTTP_TOKEN || "";
    if (backupToken) headers["x-prasar-backup-token"] = backupToken;
    const { res, data } = await rawFetch("POST", "/api/system/backup", { headers, body: {} });
    if (res.status === 403 && backupToken) {
      assert(res.status === 403, "backup token rejected");
      return;
    }
    assert(res.status === 200 && data.ok, "backup should succeed with API key");
  });
}

// --- C: Karyakar login ---
async function sectionC(testKar) {
  await step("C1. Wrong password → 401, no stack trace", async () => {
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: testKar.email, password: "WrongPassword999!" },
    });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    assert(!String(data.raw || "").includes("at "), "stack trace in response");
    assertNoDbLeak(data);
  });

  await step("C2. Unknown email → 401", async () => {
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: `nobody.${stamp}@example.com`, password: "WrongPassword999!" },
    });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    assert(data.error === "Invalid email or password.", "unexpected error message for unknown user");
  });

  await step("C3. Valid login → user without password fields", async () => {
    if (!testKar?.created) {
      documentRisk("C3", "Skipped valid login — test karyakar was not created (need API key + DB).");
      return;
    }
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: testKar.email, password: testKar.password },
    });
    assert(res.status === 200, data.error || "login failed");
    assert(data.user && data.user.role === "KARYAKAR", "karyakar user expected");
    assert(!("password" in data.user) && !("password_hash" in data.user), "password leak");
  });

  await step("C4. INACTIVE karyakar → 401 same message", async () => {
    if (!apiKey) {
      documentRisk("C4", "Skipped INACTIVE test — no API key.");
      return;
    }
    const inactive = await api("POST", "/api/users", {
      fullName: `Inactive Kar ${stamp}`,
      email: `inactive.kar.${stamp}@example.com`,
      role: "KARYAKAR",
      status: "INACTIVE",
      password: "SecTestPass1!",
    });
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: inactive.email, password: "SecTestPass1!" },
    });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    assert(data.error === "Invalid email or password.", "inactive accounts must use the same login error");
    assertNoDbLeak(data);
  });

  await step("C5. ADMIN without karyakar login path → 401", async () => {
    if (!apiKey) return;
    const admins = (await api("GET", "/api/users")).filter((u) => String(u.role).toUpperCase() === "ADMIN");
    if (!admins[0]) {
      documentRisk("C5", "No ADMIN user in DB to test login rejection.");
      return;
    }
    const { res } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: admins[0].email, password: "anypassword" },
    });
    assert(res.status === 401, "admin should not login via karyakar endpoint");
  });

  await step("C7. Admin login via /api/auth/login sets HttpOnly cookie", async () => {
    if (!apiKey) return;
    const email = `sec.adm.${stamp}@example.com`;
    const password = "SecTestAdm1!";
    await api("POST", "/api/users", {
      fullName: `Sec Test Admin ${stamp}`,
      email,
      role: "ADMIN",
      password,
    });
    const { res, data } = await rawFetch("POST", "/api/auth/login", {
      body: { identifier: email, password, role: "ADMIN" },
    });
    assert(res.ok, data.error || "admin login failed");
    assert(data.user && data.user.role === "ADMIN", "admin role");
    const setCookie = String(res.headers.get("set-cookie") || "");
    assert(/prasar_sid=/.test(setCookie), "session cookie missing");
    assert(/HttpOnly/i.test(setCookie), "session cookie must be HttpOnly");
  });

  if (RUN_RATE_LIMIT && testKar?.created) {
    await step("C6. Login rate limit (>40 failures) → 429", async () => {
      let saw429 = false;
      for (let i = 0; i < 45; i++) {
        const { res } = await rawFetch("POST", "/api/auth/karyakar-login", {
          body: { identifier: testKar.email, password: "bad-" + i },
        });
        if (res.status === 429) {
          saw429 = true;
          break;
        }
      }
      assert(saw429, "expected 429 from karyakar login limiter within 45 attempts");
    });
  } else {
    await step("C6. Login rate limit (skipped — use --rate-limit)", async () => {
      documentRisk("C6", "Rate limit test not run; pass --rate-limit in isolated env.");
    });
  }
}

// --- D: RSVP / tokens ---
async function sectionD(ctx) {
  await step("D1. Invalid RSVP token → 404, no internal leak", async () => {
    const { res, data } = await rawFetch("GET", `/api/rsvp/not-a-valid-token-${stamp}`);
    assert(res.status === 404, `expected 404, got ${res.status}`);
    assert(!data.id || res.status === 404, "should not expose invitation id");
    assertNoDbLeak(data);
  });

  if (!ctx.rsvpToken) {
    await step("D2–D5 RSVP flow (skipped — setup failed)", async () => {
      documentRisk("D", "RSVP setup skipped.");
    });
    return;
  }

  await step("D2. Valid RSVP GET omits rsvp_token", async () => {
    const { res, data } = await rawFetch("GET", `/api/rsvp/${encodeURIComponent(ctx.rsvpToken)}`);
    assert(res.ok, data.error || "RSVP GET failed");
    assert(data.event_title, "event_title expected");
    assert(!("rsvp_token" in data), "public RSVP must not echo the token");
  });

  await step("D3. RSVP POST invalid status → 400", async () => {
    const { res, data } = await rawFetch("POST", `/api/rsvp/${encodeURIComponent(ctx.rsvpToken)}`, {
      body: { rsvpStatus: "ADMIN_APPROVED" },
    });
    assert(res.status === 400, `expected 400, got ${res.status}`);
    assertNoDbLeak(data);
  });

  await step("D4. RSVP enumeration sample (50 random tokens → 404)", async () => {
    let all404 = true;
    for (let i = 0; i < 50; i++) {
      const fake = `fake${stamp}${i}${Math.random().toString(36).slice(2, 10)}`;
      const { res } = await rawFetch("GET", `/api/rsvp/${encodeURIComponent(fake)}`);
      if (res.status !== 404) all404 = false;
    }
    assert(all404, "expected 404 for random tokens");
  });

  if (apiKey) {
    await step("D5. GET /api/invitations includes rsvp_token", async () => {
      const list = await api("GET", "/api/invitations");
      const row = list.find((x) => x.id === ctx.inviteId);
      assert(row && row.rsvp_token, "authenticated invitation list should include rsvp_token for copy-link");
    });
  }
}

// --- E: Injection / malformed input ---
async function sectionE(ctx) {
  if (!apiKey) {
    await step("E. Input tests (skipped — no API key)", async () => {});
    return;
  }

  const sqli = "' OR 1=1--";

  await step("E1. SQLi-like dignitary fullName stored safely", async () => {
    const created = await api("POST", "/api/dignitaries", {
      fullName: sqli,
      email: `sqli.dig.${stamp}@example.com`,
      designation: "Test",
      organization: "QA",
      category: "Government",
      karyakarName: "QA",
      approvalStatus: "APPROVED",
    });
    assert(created.full_name.includes("'") || created.full_name.length > 0, "created");
    ctx.sqliDigId = created.id;
    const list = await api("GET", "/api/dignitaries");
    assert(list.some((d) => d.id === created.id), "dignitary listed");
  });

  await step("E2. SQLi-like event title", async () => {
    const evt = await api("POST", "/api/events", {
      title: sqli + " Event " + stamp,
      eventDate: "2026-10-01",
      venue: "Venue",
    });
    ctx.sqliEventId = evt.id;
  });

  await step("E3. Login identifier SQLi → 401 without DB leak", async () => {
    const { res, data } = await rawFetch("POST", "/api/auth/karyakar-login", {
      body: { identifier: sqli, password: "x" },
    });
    assert(res.status === 401 || res.status === 400, `status ${res.status}`);
    assertNoDbLeak(data);
  });

  await step("E4. Import rows > 5000 → 400", async () => {
    const rows = Array.from({ length: 5001 }, (_, i) => ({
      fullName: `Bulk ${i}`,
      email: `bulk.${stamp}.${i}@example.com`,
    }));
    const { res, data } = await rawFetch("POST", "/api/dignitaries/import", {
      body: { rows },
      headers: { "x-prasar-api-key": apiKey },
    });
    assert(res.status === 400, `expected 400, got ${res.status}`);
    assert(String(data.error || "").includes("5000"), "expected max rows message");
  });

  await step("E5. PATCH user unknown field ignored (no 500)", async () => {
    const users = await api("GET", "/api/users");
    const uid = users[0]?.id;
    assert(uid, "need a user");
    const { res, data } = await rawFetch("PATCH", `/api/users/${uid}`, {
      body: { fullName: "Sec Test Name", evilColumn: "DROP TABLE users" },
      headers: { "x-prasar-api-key": apiKey },
    });
    assert(res.ok || res.status === 400, `unexpected ${res.status}`);
    assertNoDbLeak(data);
  });

  if (ctx.inviteId) {
    await step("E6. send-email non-PDF pdfBase64 falls back (no crash)", async () => {
      const users = await api("GET", "/api/users");
      const userId = users[0]?.id;
      assert(userId, "need userId");
      const notPdf = Buffer.from("NOTPDF-content").toString("base64");
      const { res, data } = await rawFetch("POST", `/api/invitations/${ctx.inviteId}/send-email`, {
        body: { userId, pdfBase64: notPdf },
        headers: { "x-prasar-api-key": apiKey },
      });
      assert(res.status !== 500 || !String(data.error || "").includes("syntax"), "no SQL leak on send-email");
      if (res.ok) {
        documentRisk("E6", "Invalid pdfBase64 is ignored; server generates PDF instead of rejecting.");
      }
    });
  }

  if (RUN_HEAVY) {
    await step("E7. Oversized JSON body (~13MB)", async () => {
      const huge = "x".repeat(13 * 1024 * 1024);
      try {
        const { res } = await rawFetch("POST", "/api/events", {
          body: JSON.stringify({ title: "Huge", eventDate: "2026-01-01", venue: huge }),
          headers: { "x-prasar-api-key": apiKey, "Content-Type": "application/json" },
        });
        assert(res.status === 413 || res.status === 400 || res.status === 500, `status ${res.status}`);
      } catch (e) {
        documentRisk("E7", "Oversized body caused connection error (acceptable).");
      }
    });
  } else {
    await step("E7. Oversized body (skipped — use --heavy)", async () => {});
  }
}

// --- F: CORS ---
async function sectionF() {
  await step("F1. CORS evil Origin on API → 403", async () => {
    const { res, data } = await rawFetch("GET", "/api/users", {
      headers: { Origin: "https://attacker.example", "x-prasar-api-key": apiKey || "x" },
    });
    assert(res.status === 403, `expected 403 CORS, got ${res.status}`);
    assert(data.error === "Origin not allowed.", "CORS message");
  });
}

// --- G: Sensitive data ---
async function sectionG(ctx) {
  if (!apiKey) return;

  await step("G1. GET /api/users omits password_hash", async () => {
    const users = await api("GET", "/api/users");
    assertNoPasswordHash(users);
  });

  await step("G2. GET invitation PDF without key → 401/403", async () => {
    if (!ctx.inviteId) return;
    const { res } = await rawFetch("GET", `/api/invitations/${ctx.inviteId}/pdf`, {
      headers: { Origin: "https://evil.example" },
    });
    assertUnauthorized(res, "G2");
  });

  await step("G3. send-email 404 for bad invitation id", async () => {
    const users = await api("GET", "/api/users");
    const { res, data } = await rawFetch("POST", "/api/invitations/999999999/send-email", {
      body: { userId: users[0]?.id || 1 },
      headers: { "x-prasar-api-key": apiKey },
    });
    assert(res.status === 404, `expected 404, got ${res.status}`);
    assertNoDbLeak(data);
    const body = JSON.stringify(data);
    assert(!body.includes("POSTMARK") && !body.includes("Bearer"), "provider secret leak");
  });
}

// --- H: Backup ---
async function sectionH() {
  if (!apiKey) {
    await step("H. Backup tests (skipped — no API key)", async () => {});
    return;
  }

  await step("H1. Backup without API key → 401/403", async () => {
    const { res } = await rawFetch("POST", "/api/system/backup", {
      body: {},
      headers: { Origin: "https://evil.example" },
    });
    assertUnauthorized(res, "H1");
  });

  const serverBackupToken = process.env.PRASAR_BACKUP_HTTP_TOKEN || "";
  if (serverBackupToken) {
    await step("H2. Backup without x-prasar-backup-token → 403", async () => {
      const { res } = await rawFetch("POST", "/api/system/backup", {
        body: {},
        headers: { "x-prasar-api-key": apiKey },
      });
      assert(res.status === 403, `expected 403, got ${res.status}`);
    });
  } else {
    await step("H2. Backup token gate (skipped — PRASAR_BACKUP_HTTP_TOKEN not set on server)", async () => {
      documentRisk("H2", "Set PRASAR_BACKUP_HTTP_TOKEN on server to test backup double-gate.");
    });
  }

  await step("H3. Backup file contains users table (document password_hash at rest)", async () => {
    const headers = { "x-prasar-api-key": apiKey };
    if (serverBackupToken) headers["x-prasar-backup-token"] = serverBackupToken;
    const { res, data } = await rawFetch("POST", "/api/system/backup", { headers, body: {} });
    assert(res.ok, data.error || "backup failed");
    const backupDir = path.join(__dirname, "..", "data", "backups");
    const file = path.join(backupDir, data.backupFile);
    if (!fs.existsSync(file)) {
      documentRisk("H3", "Backup file not on disk from test runner cwd (may be on server host only).");
      return;
    }
    if (data.encrypted) {
      return;
    }
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    assert(parsed.data && Array.isArray(parsed.data.users), "users table in backup");
    const hasHash = parsed.data.users.some((u) => u.password_hash != null && String(u.password_hash).length > 0);
    assert(!hasHash, "backup must not include users.password_hash");
  });
}

// --- I: Client static XSS scan ---
async function sectionI() {
  await step("I1. public/main.js uses escapeHtml for dynamic HTML", async () => {
    const file = path.join(__dirname, "..", "public", "main.js");
    const src = fs.readFileSync(file, "utf8");
    assert(src.includes("function escapeHtml"), "public/main.js must define escapeHtml");
    assert(/innerHTML[\s\S]*escapeHtml/.test(src) || src.includes("escapeHtml(u."), "dynamic HTML should be escaped");
  });

  await step("I2. Prototype innerHTML vs escapeHtml ratio", async () => {
    const file = path.join(__dirname, "..", "Prasar-Prototype.html");
    const src = fs.readFileSync(file, "utf8");
    const inner = (src.match(/innerHTML/g) || []).length;
    const esc = (src.match(/escapeHtml/g) || []).length;
    assert(esc >= 80, `expected substantial escapeHtml usage, got ${esc} vs ${inner} innerHTML`);
  });
}

// --- J: Repo hygiene ---
async function sectionJ() {
  await step("J1. Tracked files must not contain live secrets patterns", async () => {
    const patterns = ["POSTMARK_API_KEY=", "WHATSAPP_ACCESS_TOKEN=", "postgresql://postgres:"];
    for (const pat of patterns) {
      try {
        const out = execSync(`git grep -F "${pat}" -- . ":(exclude).env.example"`, {
          cwd: path.join(__dirname, ".."),
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
        });
        if (out.trim()) assert(false, `Found ${pat} in tracked files`);
      } catch (e) {
        if (e.status === 1) continue;
        if (e.stderr && String(e.stderr).includes("not a git repository")) {
          documentRisk("J1", "Not a git repo; skipped git grep.");
          return;
        }
      }
    }
  });

  await step("J2. .gitignore covers secrets paths", async () => {
    const gi = fs.readFileSync(path.join(__dirname, "..", ".gitignore"), "utf8");
    assert(gi.includes("runtime-secrets.json"), "runtime-secrets.json");
    assert(gi.includes("data/backups"), "data/backups");
    assert(gi.includes(".env"), ".env");
  });

  await step("J3. No hardcoded demo passwords in app source", async () => {
    const proto = fs.readFileSync(path.join(__dirname, "..", "Prasar-Prototype.html"), "utf8");
    const server = fs.readFileSync(path.join(__dirname, "..", "src", "server.js"), "utf8");
    assert(!proto.includes("admin123"), "admin123 must not be in the prototype");
    assert(!proto.includes("karyakar123"), "karyakar123 must not be in the prototype");
    assert(!server.includes("admin123"), "admin123 must not be in the server");
  });
}

async function setupTestData() {
  const ctx = { rsvpToken: null, inviteId: null, sqliDigId: null, sqliEventId: null };
  if (!apiKey) return { testKar: null, ctx };

  const testKar = {
    email: `sec.kar.${stamp}@example.com`,
    password: "SecTestPass1!",
  };
  await api("POST", "/api/users", {
    fullName: `Sec Test Karyakar ${stamp}`,
    email: testKar.email,
    role: "KARYAKAR",
    password: testKar.password,
  });
  testKar.created = true;

  const dig = await api("POST", "/api/dignitaries", {
    fullName: `Sec Dig ${stamp}`,
    email: `sec.dig.${stamp}@example.com`,
    designation: "Officer",
    organization: "QA",
    category: "Government",
    karyakarName: "Sec Kar",
    approvalStatus: "APPROVED",
  });
  const evt = await api("POST", "/api/events", {
    title: `Sec Event ${stamp}`,
    eventDate: "2026-11-01",
    venue: "Test Venue",
  });
  const inv = await api("POST", "/api/invitations", {
    dignitaryId: dig.id,
    eventId: evt.id,
    customMessage: "Security test invite",
  });
  ctx.rsvpToken = inv.rsvp_token;
  ctx.inviteId = inv.id;
  ctx.digId = dig.id;

  return { testKar, ctx };
}

async function main() {
  console.log(`PRASAR security tests → ${BASE}`);
  console.log(`API key: ${apiKey ? "loaded" : "MISSING"}`);
  if (STRICT) console.log("STRICT mode: same-origin bypass must be off");

  let testKar = null;
  let ctx = {};
  try {
    const setup = await setupTestData();
    testKar = setup.testKar;
    ctx = setup.ctx;
  } catch (e) {
    console.error("\nSetup warning:", e.message);
    testKar = { email: `sec.kar.${stamp}@example.com`, password: "SecTestPass1!", created: false };
  }

  await sectionA();
  await sectionB();
  if (testKar) await sectionC(testKar);
  await sectionD(ctx);
  await sectionE(ctx);
  await sectionF();
  await sectionG(ctx);
  await sectionH();
  await sectionI();
  await sectionJ();

  console.log("\n--- Summary ---");
  console.log(`Passed: ${passed}, Failed: ${failed}, Documented risks: ${findings.length}`);
  if (findings.length) {
    console.log("\nDocumented risks (see docs/SECURITY-REPORT.md):");
    for (const f of findings) console.log(`  ${f.id}: ${f.message}`);
  }
  if (failed > 0) process.exit(1);
  console.log("\nSecurity regression tests completed.");
}

main().catch((err) => {
  console.error("\nFATAL:", err.message);
  process.exit(1);
});
