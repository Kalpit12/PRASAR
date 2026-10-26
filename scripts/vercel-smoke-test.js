"use strict";
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const BASE = process.env.PRASAR_TEST_URL || "https://prasar.vercel.app";
const email = process.env.PRASAR_BOOTSTRAP_ADMIN_EMAIL;
const password = process.env.PRASAR_BOOTSTRAP_ADMIN_PASSWORD;

async function main() {
  const results = [];

  const home = await fetch(BASE + "/", { redirect: "manual" });
  const homeText = await home.text();
  results.push({
    name: "GET /",
    status: home.status,
    hasLogin: homeText.includes("loginScreen") && homeText.includes("Enter PRASAR"),
    titleOk: homeText.includes("PRASAR"),
  });

  const health = await fetch(BASE + "/api/health");
  results.push({ name: "GET /api/health", status: health.status, body: await health.json().catch(() => null) });

  const rsvp = await fetch(BASE + "/rsvp.html");
  results.push({ name: "GET /rsvp.html", status: rsvp.status, ok: (await rsvp.text()).toLowerCase().includes("rsvp") });

  const unauthMe = await fetch(BASE + "/api/auth/me");
  const unauthMeBody = await unauthMe.json().catch(() => ({}));
  results.push({
    name: "GET /api/auth/me unauth",
    status: unauthMe.status,
    userIsNull: unauthMeBody.user == null,
  });

  const loginRes = await fetch(BASE + "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: email, password, role: "ADMIN" }),
  });
  const loginBody = await loginRes.json().catch(() => ({}));
  const setCookie = loginRes.headers.get("set-cookie") || "";
  const hasSessionCookie = /prasar_sid=/i.test(setCookie);
  results.push({
    name: "POST /api/auth/login",
    status: loginRes.status,
    ok: Boolean(loginBody && loginBody.ok),
    role: loginBody && loginBody.user && loginBody.user.role,
    hasSessionCookie,
  });

  const cookie = (setCookie.split(";")[0] || "").trim();
  const me = await fetch(BASE + "/api/auth/me", { headers: cookie ? { cookie } : {} });
  const meBody = await me.json().catch(() => ({}));
  results.push({
    name: "GET /api/auth/me",
    status: me.status,
    role: meBody && meBody.user && meBody.user.role,
  });

  const users = await fetch(BASE + "/api/users", { headers: cookie ? { cookie } : {} });
  const usersBody = await users.json().catch(() => null);
  results.push({
    name: "GET /api/users auth",
    status: users.status,
    count: Array.isArray(usersBody) ? usersBody.length : null,
  });

  const events = await fetch(BASE + "/api/events", { headers: cookie ? { cookie } : {} });
  const eventsBody = await events.json().catch(() => null);
  results.push({
    name: "GET /api/events",
    status: events.status,
    count: Array.isArray(eventsBody) ? eventsBody.length : null,
  });

  const lookups = await fetch(BASE + "/api/lookups", { headers: cookie ? { cookie } : {} });
  results.push({ name: "GET /api/lookups", status: lookups.status });

  console.log(JSON.stringify(results, null, 2));
}

main().catch((err) => {
  console.error("TEST_FAIL", err.message);
  process.exit(1);
});
