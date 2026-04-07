const tabs = document.querySelectorAll(".tab");
const pages = document.querySelectorAll(".page");
try {
  localStorage.removeItem("prasarApiKey");
} catch (_e) {}
let apiKey = sessionStorage.getItem("prasarApiKey") || "";

function ensureApiKey() {
  if (apiKey) return true;
  const value = window.prompt("Enter PRASAR API key:");
  if (!value) return false;
  apiKey = value.trim();
  sessionStorage.setItem("prasarApiKey", apiKey);
  return Boolean(apiKey);
}

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    pages.forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`page-${tab.dataset.page}`).classList.add("active");
  });
});

async function api(url, options = {}) {
  if (!ensureApiKey()) throw new Error("API key is required.");
  const headers = {
    "Content-Type": "application/json",
    "x-prasar-api-key": apiKey,
    ...(options.headers || {}),
  };
  const response = await fetch(url, {
    headers,
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    sessionStorage.removeItem("prasarApiKey");
    apiKey = "";
    throw new Error("Unauthorized. API key reset, please enter again.");
  }
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

async function openInvitationPdf(id) {
  if (!ensureApiKey()) return;
  try {
    const response = await fetch(`/api/invitations/${id}/pdf`, {
      headers: { "x-prasar-api-key": apiKey },
    });
    if (response.status === 401) {
      sessionStorage.removeItem("prasarApiKey");
      apiKey = "";
      throw new Error("Unauthorized. API key reset, please enter again.");
    }
    if (!response.ok) throw new Error("Failed to load PDF");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const w = window.open(url, "_blank");
    if (!w) throw new Error("Pop-up blocked.");
    setTimeout(() => URL.revokeObjectURL(url), 120000);
  } catch (e) {
    alert(e.message);
  }
}

async function loadUsers() {
  const users = await api("/api/users");
  document.getElementById("usersBody").innerHTML = users
    .map(
      (u) =>
        `<tr><td>${u.id}</td><td>${u.full_name}</td><td>${u.email}</td><td>${u.role}</td><td>${u.status}</td><td>${u.created_at}</td></tr>`
    )
    .join("");
  document.getElementById("cUser").innerHTML = users
    .map((u) => `<option value="${u.id}">${u.full_name} (${u.role})</option>`)
    .join("");
}

async function loadDignitaries() {
  const dignitaries = await api("/api/dignitaries");
  const options = dignitaries
    .map((d) => `<option value="${d.id}">${d.full_name} (${d.email})</option>`)
    .join("");
  document.getElementById("iDignitary").innerHTML = options;
  document.getElementById("cDignitary").innerHTML = options;
}

async function loadEvents() {
  const events = await api("/api/events");
  document.getElementById("iEvent").innerHTML = events
    .map((e) => `<option value="${e.id}">${e.title} (${e.event_date})</option>`)
    .join("");
}

async function loadInvitations() {
  const invitations = await api("/api/invitations");
  document.getElementById("invBody").innerHTML = invitations
    .map(
      (i) =>
        `<tr>
          <td>${i.id}</td>
          <td>${i.dignitary_name}</td>
          <td>${i.event_title}</td>
          <td>${i.status}</td>
          <td>
            <button onclick="previewInvitation(${i.id})">Preview</button>
            <button onclick="sendEmail(${i.id})">Send Email</button>
            <button onclick="openInvitationPdf(${i.id})">Open PDF</button>
          </td>
        </tr>`
    )
    .join("");
}

async function loadCommunications() {
  const rows = await api("/api/communications");
  document.getElementById("comBody").innerHTML = rows
    .map(
      (r) =>
        `<tr><td>${r.happened_at}</td><td>${r.dignitary_name}</td><td>${r.user_name}</td><td>${r.type}</td><td>${r.notes}</td></tr>`
    )
    .join("");
}

async function createUser() {
  try {
    await api("/api/users", {
      method: "POST",
      body: JSON.stringify({
        fullName: document.getElementById("uName").value,
        email: document.getElementById("uEmail").value,
        role: document.getElementById("uRole").value,
        status: document.getElementById("uStatus").value,
      }),
    });
    await loadUsers();
    alert("User created.");
  } catch (e) {
    alert(e.message);
  }
}

async function createDignitary() {
  try {
    await api("/api/dignitaries", {
      method: "POST",
      body: JSON.stringify({
        fullName: document.getElementById("dName").value,
        email: document.getElementById("dEmail").value,
        designation: document.getElementById("dDes").value,
        organization: document.getElementById("dOrg").value,
      }),
    });
    await loadDignitaries();
    alert("Dignitary created.");
  } catch (e) {
    alert(e.message);
  }
}

async function createEvent() {
  try {
    await api("/api/events", {
      method: "POST",
      body: JSON.stringify({
        title: document.getElementById("eTitle").value,
        eventDate: document.getElementById("eDate").value,
        venue: document.getElementById("eVenue").value,
      }),
    });
    await loadEvents();
    alert("Event created.");
  } catch (e) {
    alert(e.message);
  }
}

async function createInvitation() {
  try {
    await api("/api/invitations", {
      method: "POST",
      body: JSON.stringify({
        dignitaryId: Number(document.getElementById("iDignitary").value),
        eventId: Number(document.getElementById("iEvent").value),
        customMessage: document.getElementById("iMsg").value,
      }),
    });
    await loadInvitations();
    alert("Invitation created.");
  } catch (e) {
    alert(e.message);
  }
}

async function previewInvitation(id) {
  try {
    const invite = await api(`/api/invitations/${id}/preview`);
    document.getElementById("previewBox").textContent =
      `To: ${invite.dignitary_name}\n` +
      `Email: ${invite.email}\n` +
      `Designation: ${invite.designation || "-"}\n` +
      `Organization: ${invite.organization || "-"}\n\n` +
      `Event: ${invite.event_title}\n` +
      `Date: ${invite.event_date}\n` +
      `Venue: ${invite.venue}\n\n` +
      `Message:\n${invite.custom_message || "You are cordially invited."}`;
  } catch (e) {
    alert(e.message);
  }
}

async function sendEmail(id) {
  try {
    const users = await api("/api/users");
    const sender = users.find((u) => u.role === "ADMIN") || users[0];
    if (!sender) {
      alert("Create at least one user first to attribute communication.");
      return;
    }
    const result = await api(`/api/invitations/${id}/send-email`, {
      method: "POST",
      body: JSON.stringify({ userId: sender.id }),
    });
    await Promise.all([loadInvitations(), loadCommunications()]);
    alert(`Email generated locally: ${result.outboxFile}`);
  } catch (e) {
    alert(e.message);
  }
}

async function createCommunication() {
  try {
    const localDate = document.getElementById("cAt").value;
    if (!localDate) {
      alert("Please select date and time.");
      return;
    }
    await api("/api/communications", {
      method: "POST",
      body: JSON.stringify({
        dignitaryId: Number(document.getElementById("cDignitary").value),
        userId: Number(document.getElementById("cUser").value),
        type: document.getElementById("cType").value,
        notes: document.getElementById("cNotes").value,
        happenedAt: new Date(localDate).toISOString(),
      }),
    });
    await loadCommunications();
    alert("Communication saved.");
  } catch (e) {
    alert(e.message);
  }
}

async function boot() {
  try {
    if (!ensureApiKey()) return;
    await Promise.all([loadUsers(), loadDignitaries(), loadEvents(), loadInvitations(), loadCommunications()]);
  } catch (e) {
    alert(`Startup error: ${e.message}`);
  }
}

boot();
