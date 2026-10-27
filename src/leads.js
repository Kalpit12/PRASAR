const SKIPPED_LEADS = new Set(["", "tbc", "unassigned", "na", "n a", "-"]);

/** Same person written more than one way in the BAPS appointed lead column. */
const PERSON_ALIASES = {
  "dr r k patel": "DR. R.K Patel",
  "ashish bhavsar": "Ashishbhai Bhavsar",
  "ashishbhai bhavsar": "Ashishbhai Bhavsar",
  "yogibhai": "Yogibhai",
  "yogibhai sahib": "Yogibhai",
  "kiranbhai": "Kiranbhai Patel",
  "manishbhai": "Manishbhai vadla",
};

function compactKey(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function personKey(value) {
  return compactKey(String(value || "").replace(/\([^)]*\)/g, " "));
}

function isSkippedLead(value) {
  return SKIPPED_LEADS.has(compactKey(value));
}

function volunteerEmail(fullName) {
  const slug = compactKey(fullName).replace(/ /g, ".");
  return `${slug || "volunteer"}@volunteer.prasar.local`;
}

function canonicalLead(variants) {
  return [...variants.entries()].sort((a, b) => b[1] - a[1] || a[0].length - b[0].length)[0][0];
}

function canonicalPerson(name) {
  const cleaned = String(name || "").replace(/\s+/g, " ").trim();
  if (!cleaned || isSkippedLead(cleaned)) return "";
  return PERSON_ALIASES[personKey(cleaned)] || cleaned;
}

/** Split a lead cell such as "DR. R.K Patel / Anjuben" into one name per person. */
function peopleFromLead(lead) {
  const seen = new Set();
  const people = [];
  for (const part of String(lead || "").split("/")) {
    const name = canonicalPerson(part);
    const key = personKey(name);
    if (!name || !key || seen.has(key)) continue;
    seen.add(key);
    people.push(name);
    if (people.length === 3) break;
  }
  return people;
}

/** One volunteer account per person, including each person named in a shared lead cell. */
function planGuestImport(rows) {
  const counts = new Map();
  const prepared = [];
  for (const raw of rows || []) {
    const lead = String(raw.karyakarName || raw.karyakar || "")
      .trim()
      .replace(/\s+/g, " ");
    const people = isSkippedLead(lead) ? [] : peopleFromLead(lead);
    prepared.push({ raw, people });
    for (const name of people) {
      const key = personKey(name);
      if (!counts.has(key)) counts.set(key, new Map());
      const variants = counts.get(key);
      variants.set(name, (variants.get(name) || 0) + 1);
    }
  }

  const canonical = new Map();
  for (const [key, variants] of counts) canonical.set(key, canonicalLead(variants));
  // "Kiranbhai" is the same person as "Kiranbhai Patel" when only one fuller name exists.
  for (const short of [...canonical.keys()]) {
    const longer = [...canonical.keys()].filter((key) => key.startsWith(`${short} `));
    if (longer.length === 1) canonical.set(short, canonical.get(longer[0]));
  }

  const volunteers = [];
  const seenVolunteer = new Set();
  for (const fullName of canonical.values()) {
    const key = personKey(fullName);
    if (seenVolunteer.has(key)) continue;
    seenVolunteer.add(key);
    volunteers.push({ key, fullName, email: volunteerEmail(fullName) });
  }

  const guests = prepared.map(({ raw, people }) => {
    const names = people.map((name) => canonical.get(personKey(name)) || name);
    return {
      ...raw,
      karyakarName: names[0] || "",
      karyakarNameSecondary: names[1] || "",
      karyakarNameTertiary: names[2] || "",
    };
  });

  return { guests, volunteers };
}

function leadMatchesVolunteer(leadText, volunteerName, secondary, tertiary) {
  const volunteerKey = personKey(volunteerName);
  if (!volunteerKey || isSkippedLead(volunteerName)) return false;
  const assigned = [leadText, secondary, tertiary].flatMap((value) => peopleFromLead(value));
  return assigned.some((name) => personKey(name) === volunteerKey);
}

module.exports = {
  compactKey,
  personKey,
  isSkippedLead,
  canonicalPerson,
  volunteerEmail,
  peopleFromLead,
  planGuestImport,
  leadMatchesVolunteer,
};
