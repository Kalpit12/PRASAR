/**
 * Feature smoke tests for PRASAR (requires running server + DATABASE_URL).
 * Usage: node scripts/test-features.js [baseUrl]
 */
const fs = require("fs");
const path = require("path");

const BASE = process.argv[2] || "http://127.0.0.1:3000";
const secretsPath = path.join(__dirname, "..", "data", "runtime-secrets.json");
let apiKey = "";
try {
  apiKey = JSON.parse(fs.readFileSync(secretsPath, "utf8")).PRASAR_API_KEY || "";
} catch {
  apiKey = "";
}

async function req(method, urlPath, body) {
  const headers = { "Content-Type": "application/json" };
  if (apiKey) headers["x-prasar-api-key"] = apiKey;
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
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(data.error || `${res.status} ${urlPath}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function step(name, fn) {
  process.stdout.write(`\n▶ ${name} … `);
  await fn();
  console.log("OK");
}

async function main() {
  console.log(`Testing against ${BASE}`);
  const stamp = Date.now();
  let digId;
  let eventId;
  let inviteId;
  let rsvpToken;
  let userId;
  let donationId;
  let notifId;

  await step("1. Secondary & tertiary karyakar fields", async () => {
    const users = await req("GET", "/api/users");
    const kar = (users || []).find((u) => String(u.role).toUpperCase() === "KARYAKAR") || users[0];
    assert(kar, "Need at least one user for karyakar name");
    const created = await req("POST", "/api/dignitaries", {
      fullName: `Test Dig ${stamp}`,
      email: `test.dig.${stamp}@example.com`,
      designation: "Test Officer",
      organization: "PRASAR QA",
      phone: "+254700000001",
      category: "Government",
      karyakarName: kar.full_name,
      karyakarNameSecondary: "Secondary Kar",
      karyakarNameTertiary: "Tertiary Kar",
      salutation: "Hon.",
    });
    digId = created.id;
    assert(created.karyakar_name_secondary === "Secondary Kar", "secondary missing");
    assert(created.karyakar_name_tertiary === "Tertiary Kar", "tertiary missing");
    const list = await req("GET", "/api/dignitaries");
    const found = list.find((d) => d.id === digId);
    assert(found && found.karyakar_name_secondary === "Secondary Kar", "GET secondary missing");
  });

  await step("1b. Karyakar dig pending approval + import pending", async () => {
    const pendingDig = await req("POST", "/api/dignitaries", {
      fullName: `Pending Dig ${stamp}`,
      email: `pending.dig.${stamp}@example.com`,
      designation: "Pending Officer",
      organization: "PRASAR QA",
      category: "Government",
      karyakarName: "QA Karyakar",
      approvalStatus: "PENDING",
      submittedByName: "QA Karyakar",
    });
    assert(pendingDig.approval_status === "PENDING", "create should be PENDING");
    const pendingList = await req("GET", "/api/dignitaries?approvalStatus=PENDING");
    assert(
      pendingList.some((d) => d.id === pendingDig.id),
      "pending dig not in Pending Approval list"
    );
    const inviteBlocked = await fetch(`${BASE}/api/invitations`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(apiKey ? { "x-prasar-api-key": apiKey } : {}),
      },
      body: JSON.stringify({
        dignitaryId: pendingDig.id,
        eventId: 1,
        customMessage: "should fail",
      }),
    });
    // May fail for missing event OR unapproved dig — create temp event if needed later; check approval message when dig exists
    const blockedBody = await inviteBlocked.json().catch(() => ({}));
    if (inviteBlocked.status === 400) {
      assert(
        String(blockedBody.error || "").toLowerCase().includes("approved") ||
          String(blockedBody.error || "").toLowerCase().includes("invalid"),
        "unexpected invite error for pending dig"
      );
    }
    const approved = await req("PATCH", `/api/dignitaries/${pendingDig.id}/approval`, {
      approvalStatus: "APPROVED",
    });
    assert(approved.approval_status === "APPROVED", "approve failed");
    const imp = await req("POST", "/api/dignitaries/import", {
      approvalStatus: "PENDING",
      submittedByName: "QA Karyakar",
      rows: [
        {
          fullName: `Import Pending ${stamp}`,
          email: `import.pending.${stamp}@example.com`,
          designation: "Imported",
          organization: "QA",
          category: "Government",
          karyakarName: "QA Karyakar",
        },
      ],
    });
    assert(imp.stats && imp.stats.added >= 1, "import pending did not add");
    assert(imp.stats.pendingApproval >= 1, "import should count pendingApproval");
  });

  await step("2. Create event + invitation for RSVP/approval/attendance", async () => {
    const evt = await req("POST", "/api/events", {
      title: `QA Event ${stamp}`,
      eventDate: "2026-09-01",
      eventTime: "10:00 AM",
      venue: "Nairobi Mandir",
      description: "Feature test event",
    });
    eventId = evt.id;
    const inv = await req("POST", "/api/invitations", {
      dignitaryId: digId,
      eventId,
      customMessage: "Please join us",
    });
    inviteId = inv.id;
    rsvpToken = inv.rsvp_token;
    assert(rsvpToken, "rsvp_token not generated");
  });

  await step("3. RSVP confirmation (public token + admin patch)", async () => {
    const publicGet = await fetch(`${BASE}/api/rsvp/${encodeURIComponent(rsvpToken)}`);
    const pub = await publicGet.json();
    assert(publicGet.ok, pub.error || "public RSVP GET failed");
    assert(pub.event_title, "event title missing on RSVP");

    const publicPost = await fetch(`${BASE}/api/rsvp/${encodeURIComponent(rsvpToken)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rsvpStatus: "ACCEPTED" }),
    });
    const accepted = await publicPost.json();
    assert(publicPost.ok, accepted.error || "public RSVP POST failed");
    assert(accepted.rsvp_status === "ACCEPTED", "RSVP not ACCEPTED");

    const patched = await req("PATCH", `/api/invitations/${inviteId}/rsvp`, {
      rsvpStatus: "DECLINED",
    });
    assert(patched.rsvp_status === "DECLINED", "admin RSVP patch failed");
    const byPhone = await req("PATCH", `/api/invitations/${inviteId}/rsvp`, {
      rsvpStatus: "BY_PHONE",
    });
    assert(byPhone.rsvp_status === "BY_PHONE", "BY_PHONE RSVP failed");
    const byEmail = await req("PATCH", `/api/invitations/${inviteId}/rsvp`, {
      rsvpStatus: "BY_EMAIL",
    });
    assert(byEmail.rsvp_status === "BY_EMAIL", "BY_EMAIL RSVP failed");
    const inPerson = await req("PATCH", `/api/invitations/${inviteId}/rsvp`, {
      rsvpStatus: "IN_PERSON",
    });
    assert(inPerson.rsvp_status === "IN_PERSON", "IN_PERSON RSVP failed");
    const byWhatsapp = await req("PATCH", `/api/invitations/${inviteId}/rsvp`, {
      rsvpStatus: "BY_WHATSAPP",
    });
    assert(byWhatsapp.rsvp_status === "BY_WHATSAPP", "BY_WHATSAPP RSVP failed");
    await req("PATCH", `/api/invitations/${inviteId}/rsvp`, { rsvpStatus: "ACCEPTED" });
  });

  await step("4. Admin approval of dignitary attendance", async () => {
    const approved = await req("PATCH", `/api/invitations/${inviteId}/approval`, {
      adminApproval: "APPROVED",
    });
    assert(approved.admin_approval === "APPROVED", "approval failed");
    const rejected = await req("PATCH", `/api/invitations/${inviteId}/approval`, {
      adminApproval: "REJECTED",
    });
    assert(rejected.admin_approval === "REJECTED", "reject failed");
    await req("PATCH", `/api/invitations/${inviteId}/approval`, { adminApproval: "APPROVED" });
  });

  await step("5. Manual attendance + guest list", async () => {
    const guests = await req("GET", `/api/events/${eventId}/guests`);
    assert(Array.isArray(guests) && guests.some((g) => g.invitation_id === inviteId), "guest list missing invite");
    const attended = await req("PATCH", `/api/invitations/${inviteId}/attendance`, {
      attended: true,
    });
    assert(attended.attended === true, "attendance mark failed");
    assert(attended.attended_at, "attended_at missing");
    const cleared = await req("PATCH", `/api/invitations/${inviteId}/attendance`, {
      attended: false,
    });
    assert(cleared.attended === false, "attendance clear failed");
    await req("PATCH", `/api/invitations/${inviteId}/attendance`, { attended: true });
  });

  await step("6. Donation note for Sanstha contributions", async () => {
    const don = await req("POST", "/api/donations", {
      dignitaryId: digId,
      donorName: `Test Dig ${stamp}`,
      amount: 250.5,
      donationDate: "2026-08-08",
      receiptNo: `R-${stamp}`,
      project: "Education",
      note: "Contribution to the Sanstha for youth seva",
    });
    donationId = don.id;
    assert(don.note && don.note.includes("Sanstha"), "donation note missing");
    const list = await req("GET", "/api/donations");
    assert(list.some((d) => d.id === donationId && d.note.includes("Sanstha")), "donation list note missing");
  });

  await step("7. Karyakar reminder notifications", async () => {
    const users = await req("GET", "/api/users");
    userId = users[0]?.id;
    assert(userId, "no users for reminder target");
    const n = await req("POST", "/api/notifications/reminder", {
      userId,
      dignitaryId: digId,
      eventId,
      invitationId: inviteId,
      message: "Please remind the guest about the upcoming event",
      createdBy: userId,
    });
    notifId = n.id;
    assert(n.type === "REMINDER", "reminder type wrong");
    const list = await req("GET", `/api/notifications?userId=${userId}`);
    assert(list.some((x) => x.id === notifId), "reminder not listed");
    const read = await req("PATCH", `/api/notifications/${notifId}/read`, {});
    assert(read.read_at, "read_at not set");
  });

  await step("8. Public RSVP page is served", async () => {
    const res = await fetch(`${BASE}/rsvp?token=${encodeURIComponent(rsvpToken)}`);
    assert(res.ok, "rsvp page not served");
    const html = await res.text();
    assert(html.includes("Event RSVP"), "rsvp html unexpected");
  });

  console.log("\nAll feature tests passed.");
  console.log({ digId, eventId, inviteId, donationId, notifId });
}

main().catch((err) => {
  console.error("\nFAILED:", err.message);
  if (err.data) console.error(err.data);
  process.exit(1);
});
