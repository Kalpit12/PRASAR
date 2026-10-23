/** Remove all dignitary rows and dependent invitation/communication records. */
async function clearAllGuestData(db) {
  await db.query("DELETE FROM communications");
  await db.query("DELETE FROM invitations");
  await db.query("DELETE FROM dignitaries");
}

module.exports = { clearAllGuestData };
