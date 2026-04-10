# PRASAR Local App

Local-first implementation of:
- Admin user management (including karyakars)
- Invitations (PDF preview + local email generation)
- Communications timeline

## Run locally

1. Install dependencies:
   - `npm install`
2. Start server:
   - `npm start`
3. On first run, keys are auto-generated and saved to:
   - `data/runtime-secrets.json`
4. The terminal prints the API key for copy/paste.
5. Open:
   - `http://localhost:3000`
6. Enter the API key in the browser prompt.

## Storage

- SQLite database: `data/prasar.db`
- Local generated emails (no Postmark): `data/outbox/*.eml`
- Backups: `data/backups/*` (encrypted if `PRASAR_BACKUP_KEY` is set)

## Notes

- Starts with **no demo data**.
- Create users, dignitaries, and events from the UI first.
- **Postmark (optional):** set `POSTMARK_API_KEY`, `POSTMARK_SENDER_EMAIL` (verified sender in Postmark), and `POSTMARK_SENDER_NAME` to send invitation email for real. Same pattern as AksharJobs. If unset, sends are saved as `.eml` in `data/outbox/`.
- API routes require `x-prasar-api-key` when `PRASAR_API_KEY` is set.
- You can still override keys with env vars:
  - `PRASAR_API_KEY`
  - `PRASAR_BACKUP_KEY`
- A scheduled backup runs every 6 hours.
- You can trigger a manual backup with `POST /api/system/backup`.
