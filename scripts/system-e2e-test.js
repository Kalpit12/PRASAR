/**
 * Full-system wipe + end-to-end test for PRASAR.
 * Requires running server + DATABASE_URL. Does not print API keys.
 *
 * Usage: node scripts/system-e2e-test.js [baseUrl]
 */
const fs = require("fs");
const path = require("path");
const db = require("../src/db");

const BASE = process.argv[2] || "http://127.0.0.1:3000";
const secretsPath = path.join(__dirname, "..", "data", "runtime-secrets.json");
let apiKey = "";
try {
  apiKey = JSON.parse(fs.readFileSync(secretsPath, "utf8")).PRASAR_API_KEY || "";
} catch {
  apiKey = "";
}

const ADMIN_PASSWORD = "PrasarAdmin2026!";
const VOL_PASSWORD = "PrasarVol2026!";
const results = [];
const created = {
  admin: null,
  volunteers: [],
  dignitaries: [],
  event: null,
  adminInvites: [],
  volunteerInvites: [],
};

function record(name, ok, detail) {
  results.push({ name, ok, detail: detail || "" });
  const mark = ok ? "OK" : "FAIL";
  console.log(`  [${mark}] ${name}${detail ? ` — ${detail}` : ""}`);
}

async function req(method, urlPath, body, opts = {}) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey && !opts.noKey) headers["x-prasar-api-key"] = apiKey;
  const res = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text.slice(0, 400) };
  }
  if (!res.ok && !opts.allowFail) {
    const err = new Error(data.error || `${res.status} ${urlPath}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return { status: res.status, data, ok: res.ok };
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function step(name, fn) {
  process.stdout.write(`\n▶ ${name}\n`);
  await fn();
}

async function snapshotCounts() {
  const tables = [
    "users",
    "dignitaries",
    "events",
    "invitations",
    "communications",
    "donations",
    "notifications",
    "volunteer_attendance",
  ];
  const counts = {};
  for (const t of tables) {
    try {
      const r = await db.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
      counts[t] = r.rows[0].n;
    } catch {
      counts[t] = "n/a";
    }
  }
  return counts;
}

const VOLUNTEERS = [
  { fullName: "Ravi Patel", email: "ravi.patel@prasar.test", phone: "+254711000001", assignedArea: "Nairobi Central" },
  { fullName: "Meera Shah", email: "meera.shah@prasar.test", phone: "+254711000002", assignedArea: "Westlands" },
  { fullName: "Amit Desai", email: "amit.desai@prasar.test", phone: "+254711000003", assignedArea: "Mombasa" },
  { fullName: "Priya Kotecha", email: "priya.kotecha@prasar.test", phone: "+254711000004", assignedArea: "Kisumu" },
  { fullName: "Nikhil Joshi", email: "nikhil.joshi@prasar.test", phone: "+254711000005", assignedArea: "Nakuru" },
  { fullName: "Kavita Mehta", email: "kavita.mehta@prasar.test", phone: "+254711000006", assignedArea: "Eldoret" },
  { fullName: "Sanjay Trivedi", email: "sanjay.trivedi@prasar.test", phone: "+254711000007", assignedArea: "Thika" },
  { fullName: "Anjali Popat", email: "anjali.popat@prasar.test", phone: "+254711000008", assignedArea: "Nyeri" },
  { fullName: "Dhruv Bhatt", email: "dhruv.bhatt@prasar.test", phone: "+254711000009", assignedArea: "Machakos" },
  { fullName: "Neha Gadhia", email: "neha.gadhia@prasar.test", phone: "+254711000010", assignedArea: "Kilifi" },
];

const DIGNITARIES = [
  { fullName: "Amina Hassan", salutation: "Hon.", designation: "County Executive, Health", organization: "Nairobi County Government", category: "Government", subSector: "County Government", vipCategory: "V1", dietary: "None", town: "Nairobi", email: "amina.hassan@example.com" },
  { fullName: "David Mwangi", salutation: "Dr.", designation: "Vice Chancellor", organization: "University of Nairobi", category: "Academic", subSector: "University", vipCategory: "V1", dietary: "Strict Veg", town: "Nairobi", email: "david.mwangi@example.com" },
  { fullName: "Fatima Ali", salutation: "Ms.", designation: "Country Director", organization: "Aga Khan Foundation", category: "NGO", subSector: "International NGO", vipCategory: "V2", dietary: "None", town: "Mombasa", email: "fatima.ali@example.com" },
  { fullName: "James Otieno", salutation: "Mr.", designation: "Managing Director", organization: "Kenya Commercial Bank", category: "Corporate", subSector: "Banking & Finance", vipCategory: "V2", dietary: "None", town: "Nairobi", email: "james.otieno@example.com" },
  { fullName: "Grace Wanjiku", salutation: "Prof.", designation: "Dean of Medicine", organization: "Kenyatta University", category: "Academic", subSector: "University", vipCategory: "V2", dietary: "Vegan", town: "Kiambu", email: "grace.wanjiku@example.com" },
  { fullName: "Ibrahim Noor", salutation: "Sheikh", designation: "Interfaith Council Chair", organization: "Supreme Council of Kenya Muslims", category: "Religious", subSector: "Muslim", vipCategory: "V1", dietary: "None", town: "Mombasa", email: "ibrahim.noor@example.com" },
  { fullName: "Linda Cherono", salutation: "Hon.", designation: "Member of Parliament", organization: "National Assembly of Kenya", category: "Government", subSector: "Legislature", vipCategory: "V1", dietary: "Gluten-Free", town: "Eldoret", email: "linda.cherono@example.com" },
  { fullName: "Peter Kamau", salutation: "Mr.", designation: "Editor-in-Chief", organization: "Nation Media Group", category: "Corporate", subSector: "Media & Communications", vipCategory: "V3", dietary: "None", town: "Nairobi", email: "peter.kamau@example.com" },
  { fullName: "Sarah Njeri", salutation: "Dr.", designation: "Director of Public Health", organization: "Ministry of Health", category: "Government", subSector: "National Government", vipCategory: "V2", dietary: "Strict Veg", town: "Nakuru", email: "sarah.njeri@example.com" },
  { fullName: "Michael Omondi", salutation: "Mr.", designation: "Programme Lead", organization: "UN Habitat", category: "NGO", subSector: "UN / Multilateral", vipCategory: "V2", dietary: "None", town: "Nairobi", email: "michael.omondi@example.com" },
];

async function maybeSendEmail(inviteId, userId, label) {
  const sent = await req("POST", `/api/invitations/${inviteId}/send-email`, { userId }, { allowFail: true });
  if (sent.ok) {
    record(`${label} email send`, true, `provider=${sent.data.provider || "unknown"}`);
    return true;
  }
  record(
    `${label} email send`,
    false,
    `${sent.status}: ${sent.data.error || "send failed"} (invitation still created)`
  );
  return false;
}

async function main() {
  console.log(`PRASAR full-system test against ${BASE}`);
  console.log("API key loaded:", Boolean(apiKey));

  const health = await req("GET", "/api/health", null, { noKey: true, allowFail: true });
  assert(health.ok, "Server health check failed. Start with npm run dev.");
  record("Server health", true, "ok");

  await step("0. Snapshot existing data", async () => {
    const before = await snapshotCounts();
    console.log("  Before wipe:", JSON.stringify(before));
    record("Snapshot counts", true, JSON.stringify(before));
  });

  await step("1. Wipe all operational demo data", async () => {
    await db.init();
    await db.query(`
      TRUNCATE TABLE
        notifications,
        volunteer_attendance,
        communications,
        donations,
        invitations,
        dignitaries,
        events,
        users,
        sessions
      RESTART IDENTITY CASCADE
    `);
    const after = await snapshotCounts();
    const leftover = Object.entries(after).filter(([, n]) => Number(n) > 0);
    assert(leftover.length === 0, `Wipe incomplete: ${JSON.stringify(after)}`);
    record("Wipe users/dignitaries/events/invites/comms/donations/attendance", true, JSON.stringify(after));
  });

  await step("2. Create admin + 10 PR volunteers", async () => {
    const adminRes = await req("POST", "/api/users", {
      fullName: "Admin User",
      email: "admin@prasar.test",
      role: "ADMIN",
      status: "ACTIVE",
      phone: "+254700000000",
      assignedArea: "HQ",
      password: ADMIN_PASSWORD,
    });
    created.admin = adminRes.data;
    record("Create admin user", true, `id=${created.admin.id}`);

    for (const v of VOLUNTEERS) {
      const r = await req("POST", "/api/users", {
        ...v,
        role: "KARYAKAR",
        status: "ACTIVE",
        password: VOL_PASSWORD,
      });
      created.volunteers.push(r.data);
    }
    const users = (await req("GET", "/api/users")).data;
    const vols = users.filter((u) => String(u.role).toUpperCase() === "KARYAKAR");
    assert(vols.length === 10, `expected 10 volunteers, got ${vols.length}`);
    record("Create 10 PR volunteers", true, vols.map((u) => u.full_name).join(", "));
  });

  await step("3. Volunteer dashboard login", async () => {
    const first = created.volunteers[0];
    const last = created.volunteers[9];
    for (const vol of [first, last]) {
      const login = await req(
        "POST",
        "/api/auth/karyakar-login",
        { identifier: vol.email, password: VOL_PASSWORD },
        { noKey: true }
      );
      assert(login.data.user && login.data.user.role === "KARYAKAR", "login role mismatch");
      assert(login.data.user.fullName === vol.full_name, "login name mismatch");
      record(`Volunteer login (${vol.full_name})`, true, vol.email);
    }
    const bad = await req(
      "POST",
      "/api/auth/karyakar-login",
      { identifier: first.email, password: "wrong-password" },
      { noKey: true, allowFail: true }
    );
    assert(bad.status === 401, `expected 401, got ${bad.status}`);
    record("Volunteer login rejects bad password", true);
  });

  await step("4. Admin creates event", async () => {
    const evt = await req("POST", "/api/events", {
      title: "BAPS Africa Diwali Celebration 2026",
      venue: "BAPS Shri Swaminarayan Mandir, Nairobi",
      description: "Annual Diwali celebration with dignitary reception, aarti, and cultural programme.",
      standardMessage:
        "Jai Swaminarayan. You are cordially invited to join BAPS Africa for our Diwali Celebration. We would be honoured by your presence.",
      days: [
        { date: "2026-10-20", startTime: "17:30", endTime: "21:30" },
        { date: "2026-10-21", startTime: "09:00", endTime: "12:00" },
      ],
    });
    created.event = evt.data;
    assert(created.event.id, "event id missing");
    assert(created.event.title.includes("Diwali"), "event title mismatch");
    const list = (await req("GET", "/api/events")).data;
    assert(list.length === 1, `expected 1 event, got ${list.length}`);
    record("Create event", true, `${created.event.title} (id=${created.event.id})`);
  });

  await step("5. Add 10 dignitaries and assign to volunteers", async () => {
    for (let i = 0; i < DIGNITARIES.length; i++) {
      const d = DIGNITARIES[i];
      const primary = created.volunteers[i].full_name;
      const secondary = created.volunteers[(i + 1) % 10].full_name;
      const r = await req("POST", "/api/dignitaries", {
        ...d,
        phone: `+2547220000${String(i + 1).padStart(2, "0")}`,
        karyakarName: primary,
        karyakarNameSecondary: secondary,
        protocolNotes: `Assigned to ${primary} for Diwali 2026 outreach.`,
        contributionNotes: "Community partner for BAPS Africa programmes.",
        approvalStatus: "APPROVED",
      });
      created.dignitaries.push(r.data);
    }
    const list = (await req("GET", "/api/dignitaries")).data;
    assert(list.length === 10, `expected 10 dignitaries, got ${list.length}`);
    const assigned = list.filter((d) => d.karyakar_name);
    assert(assigned.length === 10, "not all dignitaries assigned");
    record("Create + assign 10 dignitaries", true, list.map((d) => `${d.full_name}→${d.karyakar_name}`).join("; "));
  });

  await step("6. Admin sends invitations for first 5 dignitaries", async () => {
    let sendOk = 0;
    for (let i = 0; i < 5; i++) {
      const dig = created.dignitaries[i];
      const inv = await req("POST", "/api/invitations", {
        dignitaryId: dig.id,
        eventId: created.event.id,
        customMessage: `Dear ${dig.salutation} ${dig.full_name}, BAPS Africa warmly invites you to our Diwali Celebration 2026.`,
      });
      created.adminInvites.push(inv.data);
      assert(inv.data.rsvp_token, "rsvp_token missing");
      const preview = await req("GET", `/api/invitations/${inv.data.id}/preview`);
      assert(preview.data.event_title, "preview missing event");
      const pdf = await fetch(`${BASE}/api/invitations/${inv.data.id}/pdf`, {
        headers: apiKey ? { "x-prasar-api-key": apiKey } : {},
      });
      assert(pdf.ok, `PDF failed for invite ${inv.data.id}`);
      const ct = pdf.headers.get("content-type") || "";
      assert(ct.includes("pdf"), `unexpected PDF content-type ${ct}`);
      const sent = await maybeSendEmail(inv.data.id, created.admin.id, `Admin invite ${dig.full_name}`);
      if (sent) sendOk++;
    }
    record("Admin created 5 invitations", true, `ids=${created.adminInvites.map((i) => i.id).join(",")}; emails sent=${sendOk}/5`);
  });

  await step("7. Volunteers send invitations for remaining 5 dignitaries", async () => {
    let sendOk = 0;
    for (let i = 5; i < 10; i++) {
      const dig = created.dignitaries[i];
      const vol = created.volunteers[i];
      const inv = await req("POST", "/api/invitations", {
        dignitaryId: dig.id,
        eventId: created.event.id,
        customMessage: `Jai Swaminarayan. On behalf of BAPS Africa, ${vol.full_name} invites you to Diwali Celebration 2026.`,
      });
      created.volunteerInvites.push(inv.data);
      const sent = await maybeSendEmail(inv.data.id, vol.id, `Volunteer invite ${dig.full_name} via ${vol.full_name}`);
      if (sent) sendOk++;
    }
    const allInv = (await req("GET", "/api/invitations")).data;
    assert(allInv.length === 10, `expected 10 invitations, got ${allInv.length}`);
    record("Volunteer-created invitations", true, `5 created; emails sent=${sendOk}/5; total invites=${allInv.length}`);
  });

  await step("8. Volunteer-scoped assignment check", async () => {
    const allDigs = (await req("GET", "/api/dignitaries")).data;
    const allInv = (await req("GET", "/api/invitations")).data;
    for (let i = 0; i < 10; i++) {
      const vol = created.volunteers[i];
      const name = String(vol.full_name).trim().toLowerCase();
      const scoped = allDigs.filter((d) => {
        const kars = [d.karyakar_name, d.karyakar_name_secondary, d.karyakar_name_tertiary].map((x) =>
          String(x || "").trim().toLowerCase()
        );
        return kars.includes(name);
      });
      assert(scoped.length >= 1, `${vol.full_name} has no assigned dignitaries`);
      const digIds = new Set(scoped.map((d) => Number(d.id)));
      const scopedInv = allInv.filter((inv) => digIds.has(Number(inv.dignitary_id)));
      assert(scopedInv.length >= 1, `${vol.full_name} has no invitations for assigned guests`);
    }
    record("Volunteer dashboard assignment scope", true, "each of 10 volunteers has assigned dignitary + invitation");
  });

  await step("9. RSVP (public link + admin patch)", async () => {
    const allInv = (await req("GET", "/api/invitations")).data;
    const byDig = Object.fromEntries(allInv.map((i) => [Number(i.dignitary_id), i]));
    const plan = [
      { idx: 0, status: "ACCEPTED", how: "public" },
      { idx: 1, status: "DECLINED", how: "public" },
      { idx: 2, status: "BY_PHONE", how: "admin" },
      { idx: 3, status: "BY_EMAIL", how: "admin" },
      { idx: 4, status: "BY_WHATSAPP", how: "admin" },
      { idx: 5, status: "IN_PERSON", how: "admin" },
      { idx: 6, status: "ACCEPTED", how: "public" },
      { idx: 7, status: "PENDING", how: "skip" },
    ];
    for (const p of plan) {
      const dig = created.dignitaries[p.idx];
      const inv = byDig[Number(dig.id)];
      if (p.how === "skip") {
        record(`RSVP left PENDING (${dig.full_name})`, true);
        continue;
      }
      if (p.how === "public") {
        const get = await fetch(`${BASE}/api/rsvp/${encodeURIComponent(inv.rsvp_token)}`);
        const pub = await get.json();
        assert(get.ok, pub.error || "public RSVP GET failed");
        const page = await fetch(`${BASE}/rsvp?token=${encodeURIComponent(inv.rsvp_token)}`);
        assert(page.ok, "RSVP page not served");
        const post = await fetch(`${BASE}/api/rsvp/${encodeURIComponent(inv.rsvp_token)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rsvpStatus: p.status }),
        });
        const body = await post.json();
        assert(post.ok, body.error || "public RSVP POST failed");
        assert(body.rsvp_status === p.status, `expected ${p.status}`);
        record(`Public RSVP ${p.status} (${dig.full_name})`, true);
      } else {
        const patched = await req("PATCH", `/api/invitations/${inv.id}/rsvp`, { rsvpStatus: p.status });
        assert(patched.data.rsvp_status === p.status, `expected ${p.status}`);
        record(`Volunteer/admin RSVP ${p.status} (${dig.full_name})`, true);
      }
    }
  });

  await step("10. Admin approval of dignitary RSVPs", async () => {
    const allInv = (await req("GET", "/api/invitations")).data;
    const accepted = allInv.filter((i) => ["ACCEPTED", "BY_PHONE", "BY_EMAIL", "BY_WHATSAPP", "IN_PERSON"].includes(i.rsvp_status));
    let n = 0;
    for (const inv of accepted) {
      const r = await req("PATCH", `/api/invitations/${inv.id}/approval`, { adminApproval: "APPROVED" });
      assert(r.data.admin_approval === "APPROVED", "approval failed");
      n++;
    }
    const declined = allInv.find((i) => i.rsvp_status === "DECLINED");
    if (declined) {
      await req("PATCH", `/api/invitations/${declined.id}/approval`, { adminApproval: "REJECTED" });
    }
    record("Admin RSVP approvals", true, `${n} approved, ${declined ? 1 : 0} rejected`);
  });

  await step("11. Guest attendance", async () => {
    const guests = (await req("GET", `/api/events/${created.event.id}/guests`)).data;
    assert(Array.isArray(guests) && guests.length === 10, `guest list expected 10, got ${guests.length}`);
    const toMark = guests.filter((g) => ["ACCEPTED", "BY_PHONE", "BY_EMAIL", "BY_WHATSAPP", "IN_PERSON"].includes(g.rsvp_status)).slice(0, 6);
    for (const g of toMark) {
      const r = await req("PATCH", `/api/invitations/${g.invitation_id}/attendance`, { attended: true });
      assert(r.data.attended === true, "attendance mark failed");
      assert(r.data.attended_at, "attended_at missing");
    }
    const after = (await req("GET", `/api/events/${created.event.id}/guests`)).data;
    const present = after.filter((g) => g.attended).length;
    assert(present === toMark.length, `expected ${toMark.length} present, got ${present}`);
    record("Guest attendance", true, `${present}/10 marked present`);
  });

  await step("12. Volunteer attendance (admin collects)", async () => {
    const va = (await req("GET", `/api/events/${created.event.id}/volunteer-attendance`)).data;
    assert(Array.isArray(va.volunteers) && va.volunteers.length === 10, `expected 10 volunteers on attendance list, got ${va.volunteers?.length}`);
    const withGuests = va.volunteers.filter((v) => Number(v.guest_count) > 0);
    assert(withGuests.length === 10, `expected guest_count on all volunteers, got ${withGuests.length}`);
    const markIds = va.volunteers.slice(0, 7).map((v) => v.user_id);
    for (const userId of markIds) {
      const r = await req("PATCH", `/api/events/${created.event.id}/volunteer-attendance/${userId}`, {
        attended: true,
        markedBy: created.admin.id,
      });
      assert(r.data.attended === true, "volunteer attendance failed");
    }
    const after = (await req("GET", `/api/events/${created.event.id}/volunteer-attendance`)).data;
    const present = after.volunteers.filter((v) => v.attended).length;
    assert(present === 7, `expected 7 present volunteers, got ${present}`);
    record("Volunteer attendance", true, `${present}/10 PR volunteers marked present`);
  });

  await step("13. Volunteer communications + reminder + donation", async () => {
    const vol = created.volunteers[0];
    const dig = created.dignitaries[0];
    const comm = await req("POST", "/api/communications", {
      dignitaryId: dig.id,
      userId: vol.id,
      type: "PHONE_CALL",
      notes: "Confirmed travel plans for Diwali reception. Guest will arrive at 17:15.",
      happenedAt: new Date().toISOString(),
    });
    assert(comm.data.id, "communication not created");
    const visit = await req("POST", "/api/communications", {
      dignitaryId: created.dignitaries[5].id,
      userId: created.volunteers[5].id,
      type: "VISIT",
      notes: "Hand-delivered printed invitation at office.",
      happenedAt: new Date().toISOString(),
    });
    assert(visit.data.id, "visit communication not created");

    const inv = created.adminInvites[0];
    const notif = await req("POST", "/api/notifications/reminder", {
      userId: vol.id,
      dignitaryId: dig.id,
      eventId: created.event.id,
      invitationId: inv.id,
      message: "Please call Hon. Amina Hassan to confirm seating and protocol.",
      createdBy: created.admin.id,
    });
    const listed = (await req("GET", `/api/notifications?userId=${vol.id}`)).data;
    assert(listed.some((x) => x.id === notif.data.id), "reminder not listed for volunteer");

    const don = await req("POST", "/api/donations", {
      dignitaryId: created.dignitaries[3].id,
      donorName: created.dignitaries[3].full_name,
      amount: 50000,
      donationDate: "2026-08-13",
      receiptNo: "PRASAR-E2E-001",
      project: "Akshardham",
      note: "Contribution towards Diwali outreach and mandir programmes.",
      createdBy: created.admin.id,
    });
    assert(don.data.id, "donation missing");
    record("Comms + reminder + donation", true, `comm=${comm.data.id}, reminder=${notif.data.id}, donation=${don.data.id}`);
  });

  await step("14. Reports / analytics data", async () => {
    const digs = (await req("GET", "/api/dignitaries")).data;
    const inv = (await req("GET", "/api/invitations")).data;
    const comms = (await req("GET", "/api/communications")).data;
    const dons = (await req("GET", "/api/donations")).data;
    const guests = (await req("GET", `/api/events/${created.event.id}/guests`)).data;
    const vols = (await req("GET", `/api/events/${created.event.id}/volunteer-attendance`)).data.volunteers;

    const invited = inv.length;
    const rsvpConfirmed = inv.filter((i) =>
      ["ACCEPTED", "BY_PHONE", "BY_EMAIL", "BY_WHATSAPP", "IN_PERSON"].includes(i.rsvp_status)
    ).length;
    const declined = inv.filter((i) => i.rsvp_status === "DECLINED").length;
    const pending = inv.filter((i) => i.rsvp_status === "PENDING").length;
    const attended = guests.filter((g) => g.attended).length;
    const attRate = invited ? Math.round((attended / invited) * 100) : 0;
    const volPresent = vols.filter((v) => v.attended).length;

    const karPerf = created.volunteers.map((u) => {
      const assigned = digs.filter((d) => {
        const kars = [d.karyakar_name, d.karyakar_name_secondary, d.karyakar_name_tertiary].map((x) =>
          String(x || "").trim().toLowerCase()
        );
        return kars.includes(String(u.full_name).trim().toLowerCase());
      }).length;
      return { name: u.full_name, assigned };
    });

    console.log("  Reports snapshot:");
    console.log(`    Dignitaries: ${digs.length}`);
    console.log(`    Invited: ${invited}  RSVP confirmed: ${rsvpConfirmed}  Declined: ${declined}  Pending: ${pending}`);
    console.log(`    Guest attendance: ${attended}/${invited} (${attRate}%)`);
    console.log(`    Volunteer attendance: ${volPresent}/10`);
    console.log(`    Communications: ${comms.length}`);
    console.log(`    Donations: ${dons.length} (KES ${dons.reduce((s, d) => s + Number(d.amount || 0), 0)})`);
    console.log("    Karyakar assigned counts:", karPerf.map((k) => `${k.name}:${k.assigned}`).join(", "));

    assert(digs.length === 10, "reports: dignitary count");
    assert(invited === 10, "reports: invite count");
    assert(rsvpConfirmed >= 6, "reports: RSVP confirmed too low");
    assert(attended >= 6, "reports: attendance too low");
    assert(volPresent === 7, "reports: volunteer present count");
    assert(comms.length >= 2, "reports: communications");
    assert(dons.length === 1, "reports: donations");
    record("Reports overview", true, `digs=10 invited=10 rsvp=${rsvpConfirmed} attended=${attended} volPresent=${volPresent} comms=${comms.length}`);
  });

  const failed = results.filter((r) => !r.ok);
  console.log("\n======== SYSTEM TEST SUMMARY ========");
  console.log(`Passed: ${results.filter((r) => r.ok).length}  Failed: ${failed.length}`);
  if (failed.length) {
    failed.forEach((f) => console.log(`  FAIL: ${f.name} — ${f.detail}`));
  }
  console.log("\nLogin for dashboards:");
  console.log(`  Admin: email admin@prasar.test / password ${ADMIN_PASSWORD}`);
  console.log(`  PR Volunteer: any of the 10 emails below / password ${VOL_PASSWORD}`);
  created.volunteers.forEach((v) => console.log(`    - ${v.full_name} <${v.email}> (${v.assigned_area})`));
  console.log(`\nEvent: ${created.event.title} (id=${created.event.id})`);
  console.log("Dignitary assignments:");
  created.dignitaries.forEach((d, i) => {
    console.log(`    - ${d.salutation || ""} ${d.full_name} → ${created.volunteers[i].full_name}`);
  });

  if (failed.some((f) => !String(f.name).includes("email send"))) {
    process.exit(1);
  }
  if (failed.length) {
    console.log("\nCompleted with non-blocking email-send failures (invitations still exist).");
  } else {
    console.log("\nAll system tests passed.");
  }
}

main()
  .catch((err) => {
    console.error("\nFAILED:", err.message);
    if (err.data) console.error(err.data);
    process.exit(1);
  })
  .finally(async () => {
    try {
      if (db.pool) await db.pool.end();
    } catch {
      /* ignore */
    }
    process.exitCode = process.exitCode || 0;
    setTimeout(() => process.exit(process.exitCode), 250);
  });
