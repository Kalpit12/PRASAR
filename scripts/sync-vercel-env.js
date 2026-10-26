"use strict";
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });
const crypto = require("crypto");
const { spawnSync } = require("child_process");

if (!process.env.PRASAR_API_KEY) {
  process.env.PRASAR_API_KEY = crypto.randomBytes(48).toString("base64url");
}
if (!process.env.PRASAR_BACKUP_KEY) {
  process.env.PRASAR_BACKUP_KEY = crypto.randomBytes(48).toString("base64url");
}
if (!process.env.TRUST_PROXY) process.env.TRUST_PROXY = "1";

const names = [
  "DATABASE_URL",
  "PRASAR_BOOTSTRAP_ADMIN_EMAIL",
  "PRASAR_BOOTSTRAP_ADMIN_PASSWORD",
  "PRASAR_BOOTSTRAP_VOLUNTEER_EMAIL",
  "PRASAR_BOOTSTRAP_VOLUNTEER_PASSWORD",
  "PRASAR_API_KEY",
  "PRASAR_BACKUP_KEY",
  "TRUST_PROXY",
  "POSTMARK_API_KEY",
  "POSTMARK_SENDER_EMAIL",
  "POSTMARK_SENDER_NAME",
  "POSTMARK_REPLY_TO",
  "POSTMARK_MESSAGE_STREAM",
  "WHATSAPP_ACCESS_TOKEN",
  "WHATSAPP_PHONE_NUMBER_ID",
  "PUBLIC_APP_URL",
  "ALLOWED_ORIGINS",
];

let failed = 0;
for (const name of names) {
  const value = process.env[name];
  if (!value || !String(value).trim()) {
    console.log("skip", name);
    continue;
  }
  const result = spawnSync(
    "npx",
    ["vercel", "env", "add", name, "production,preview,development", "--sensitive", "--force", "--yes"],
    {
      input: String(value),
      encoding: "utf8",
      shell: true,
      cwd: require("path").join(__dirname, ".."),
    }
  );
  if (result.status !== 0) {
    failed += 1;
    console.error("fail", name);
    const err = String(result.stderr || result.stdout || "").trim();
    if (err) console.error(err.slice(0, 300));
  } else {
    console.log("set", name);
  }
}

if (!process.env.DATABASE_URL) {
  console.error("missing DATABASE_URL in .env — login will not work until it is set on Vercel.");
  process.exitCode = 1;
}
if (!process.env.PRASAR_BOOTSTRAP_ADMIN_EMAIL || !process.env.PRASAR_BOOTSTRAP_ADMIN_PASSWORD) {
  console.error("missing bootstrap admin credentials in .env — set them on Vercel to sign in.");
  process.exitCode = 1;
}
if (failed) process.exitCode = 1;
