/**
 * Give each BAPS appointed person one karyakar account.
 * Shared cells such as "DR. R.K Patel / Anjuben" stay on the guest,
 * with one name in each karyakar column, so both people can see that guest.
 *
 * Usage: DATABASE_URL=... node scripts/split-volunteer-accounts.js
 *        DATABASE_URL=... APPLY=1 node scripts/split-volunteer-accounts.js
 */
const { Pool } = require("pg");
const leads = require("../src/leads");

function sourceLead(row) {
  return [row.karyakar_name, row.karyakar_name_secondary, row.karyakar_name_tertiary]
    .map((value) => String(value || "").trim())
    .filter(Boolean)
    .join(" / ");
}

function countFor(guests, name) {
  const key = leads.personKey(name);
  return guests.filter((guest) =>
    [guest.karyakarName, guest.karyakarNameSecondary, guest.karyakarNameTertiary].some(
      (value) => leads.personKey(value) === key
    )
  ).length;
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
  const apply = process.env.APPLY === "1";
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 1 });
  const client = await pool.connect();
  try {
    const dignitaries = await client.query(
      "SELECT id, karyakar_name, karyakar_name_secondary, karyakar_name_tertiary FROM dignitaries ORDER BY id"
    );
    const users = await client.query(
      "SELECT id, full_name, email FROM users WHERE UPPER(TRIM(role)) = 'KARYAKAR' ORDER BY id"
    );
    const plan = leads.planGuestImport(
      dignitaries.rows.map((row) => ({ id: row.id, karyakarName: sourceLead(row) }))
    );
    const volunteerKeys = new Set(plan.volunteers.map((volunteer) => volunteer.key));
    const byKey = new Map();
    for (const user of users.rows) {
      const key = leads.personKey(user.full_name);
      if (!volunteerKeys.has(key)) continue;
      const prev = byKey.get(key);
      const prevIsSheet = prev && String(prev.email || "").endsWith("@volunteer.prasar.local");
      const userIsSheet = String(user.email || "").endsWith("@volunteer.prasar.local");
      const prevIsSlash = prev && String(prev.full_name).includes("/");
      const userIsSlash = String(user.full_name).includes("/");
      if (!prev || (prevIsSlash && !userIsSlash) || (prevIsSheet && !userIsSheet && !userIsSlash)) byKey.set(key, user);
    }
    const keptIds = new Set([...byKey.values()].map((user) => String(user.id)));
    const retired = users.rows.filter(
      (user) => String(user.email || "").endsWith("@volunteer.prasar.local") && !keptIds.has(String(user.id))
    );
    const created = plan.volunteers.filter((volunteer) => !byKey.has(volunteer.key));
    const renamed = plan.volunteers.filter((volunteer) => {
      const found = byKey.get(volunteer.key);
      if (!found) return false;
      const nextEmail = String(found.email || "").endsWith("@volunteer.prasar.local") ? volunteer.email : found.email;
      return found.full_name !== volunteer.fullName || found.email !== nextEmail;
    });

    const watched = [
      "Shamikbhai Patel",
      "DR. R.K Patel",
      "Anjuben",
      "Prakashbhai",
      "Yogibhai",
      "Sejal Aunty",
      "Ashishbhai Bhavsar",
      "Dipti Bhavsar",
      "Mahila Mandal",
      "Mukeshbhai Patel (Media)",
      "Test Volunteer",
    ];
    console.log(JSON.stringify({
      apply,
      guests: plan.guests.length,
      volunteers: plan.volunteers.length,
      slashAccounts: plan.volunteers.filter((volunteer) => volunteer.fullName.includes("/")).map((volunteer) => volunteer.fullName),
      created: created.map((volunteer) => ({ name: volunteer.fullName, email: volunteer.email })),
      renamed: renamed.map((volunteer) => {
        const found = byKey.get(volunteer.key);
        const nextEmail = String(found.email || "").endsWith("@volunteer.prasar.local") ? volunteer.email : found.email;
        return { from: found.full_name, emailFrom: found.email, to: volunteer.fullName, emailTo: nextEmail };
      }),
      removed: retired.map((user) => ({ name: user.full_name, email: user.email })),
      keptOutsideSheet: users.rows
        .filter((user) => !String(user.email || "").endsWith("@volunteer.prasar.local"))
        .map((user) => ({ name: user.full_name, email: user.email })),
      guestsByPerson: Object.fromEntries(watched.map((name) => [name, countFor(plan.guests, name)])),
    }, null, 2));

    if (!apply) return;

    const hashRow = await client.query(
      `SELECT password_hash FROM users
       WHERE email LIKE '%@volunteer.prasar.local' AND password_hash IS NOT NULL
       LIMIT 1`
    );
    if (!hashRow.rows[0]) throw new Error("No existing volunteer password is available to copy.");

    await client.query("BEGIN");
    const keptById = new Map();
    for (const volunteer of plan.volunteers) {
      const found = byKey.get(volunteer.key);
      if (found) {
        const nextEmail = String(found.email || "").endsWith("@volunteer.prasar.local") ? volunteer.email : found.email;
        if (found.full_name !== volunteer.fullName || found.email !== nextEmail) {
          await client.query("UPDATE users SET full_name = $1, email = $2 WHERE id = $3", [
            volunteer.fullName,
            nextEmail,
            found.id,
          ]);
        }
        keptById.set(volunteer.key, found.id);
        continue;
      }
      const inserted = await client.query(
        `INSERT INTO users (full_name, email, role, status, password_hash)
         VALUES ($1, $2, 'KARYAKAR', 'ACTIVE', $3)
         ON CONFLICT (email) DO NOTHING
         RETURNING id`,
        [volunteer.fullName, volunteer.email, hashRow.rows[0].password_hash]
      );
      if (!inserted.rows[0]) throw new Error(`Could not create account for ${volunteer.fullName}`);
      keptById.set(volunteer.key, inserted.rows[0].id);
    }

    const fks = await client.query(
      `SELECT tc.table_name, kcu.column_name
       FROM information_schema.table_constraints tc
       JOIN information_schema.key_column_usage kcu
         ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
       JOIN information_schema.constraint_column_usage ccu
         ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
       WHERE tc.constraint_type = 'FOREIGN KEY'
         AND tc.table_schema = 'public'
         AND ccu.table_name = 'users'`
    );
    for (const old of retired) {
      const people = leads.peopleFromLead(old.full_name);
      const targetId = people.map((person) => keptById.get(leads.personKey(person))).find(Boolean) || [...keptById.values()][0];
      for (const fk of fks.rows) {
        if (!/^[a-z_]+$/.test(fk.table_name) || !/^[a-z_]+$/.test(fk.column_name)) continue;
        await client.query(`UPDATE ${fk.table_name} SET ${fk.column_name} = $1 WHERE ${fk.column_name} = $2`, [
          targetId,
          old.id,
        ]);
      }
      await client.query("DELETE FROM users WHERE id = $1", [old.id]);
    }

    for (const guest of plan.guests) {
      await client.query(
        `UPDATE dignitaries
         SET karyakar_name = NULLIF($1, ''),
             karyakar_name_secondary = NULLIF($2, ''),
             karyakar_name_tertiary = NULLIF($3, '')
         WHERE id = $4`,
        [guest.karyakarName, guest.karyakarNameSecondary, guest.karyakarNameTertiary, guest.id]
      );
    }
    await client.query("COMMIT");

    const check = await client.query(
      `SELECT
         (SELECT COUNT(*)::int FROM users WHERE UPPER(TRIM(role)) = 'KARYAKAR' AND email LIKE '%@volunteer.prasar.local') AS accounts,
         (SELECT COUNT(*)::int FROM users WHERE UPPER(TRIM(role)) = 'KARYAKAR' AND email LIKE '%@volunteer.prasar.local' AND full_name LIKE '%/%') AS slash_accounts,
         (SELECT COUNT(*)::int FROM dignitaries WHERE karyakar_name_secondary IS NOT NULL AND karyakar_name_secondary <> '') AS shared_guests`
    );
    console.log(JSON.stringify({ applied: true, ...check.rows[0] }));
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch { /* no transaction open */ }
    throw err;
  } finally {
    client.release();
    pool.end().catch(() => {});
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
