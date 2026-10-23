const crypto = require("crypto");

const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };

function hashUserPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 64, SCRYPT_OPTS);
  return `v1$${salt.toString("base64")}$${hash.toString("base64")}`;
}

function nameTokens(fullName) {
  const cleaned = String(fullName || "")
    .replace(/\([^)]*\)/g, " ")
    .replace(/\//g, " ")
    .trim();
  return cleaned
    .split(/\s+/)
    .map((part) => part.replace(/[^a-zA-Z0-9]/g, ""))
    .filter((part) => part.length >= 2);
}

function passwordCore(fullName) {
  const tokens = nameTokens(fullName);
  if (!tokens.length) return "User";
  if (tokens.length === 1) return tokens[0];
  return `${tokens[0]}${tokens[tokens.length - 1]}`;
}

function buildPassword(fullName, email, role, used) {
  const core = passwordCore(fullName);
  const digest = crypto.createHash("sha256").update(`${email}|${fullName}|${role}`).digest("hex");
  for (let attempt = 0; attempt < 500; attempt++) {
    const chunk = digest.slice((attempt * 3) % 28, ((attempt * 3) % 28) + 4);
    const n = parseInt(chunk, 16) % 10000;
    const password = `${core}${String(n).padStart(4, "0")}`;
    if (password.length >= 8 && !used.has(password)) {
      used.add(password);
      return password;
    }
  }
  throw new Error(`Could not build a unique password for ${fullName}`);
}

module.exports = { hashUserPassword, buildPassword, passwordCore };
