-- PRASAR PostgreSQL schema (idempotent). Applied on server start from src/db.js.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('ADMIN', 'KARYAKAR')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
  assigned_area TEXT,
  phone TEXT,
  password_hash TEXT,
  gender TEXT CHECK (gender IS NULL OR gender IN ('MALE', 'FEMALE')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  event_date TEXT NOT NULL,
  event_time TEXT,
  venue TEXT NOT NULL,
  description TEXT,
  invitation_template TEXT,
  schedule TEXT,
  standard_message TEXT,
  status TEXT NOT NULL DEFAULT 'PUBLISHED' CHECK (status IN ('DRAFT', 'PUBLISHED')),
  attendance_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dignitaries (
  id BIGSERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  designation TEXT,
  organization TEXT,
  phone TEXT,
  category TEXT DEFAULT 'Government',
  karyakar_name TEXT,
  karyakar_name_secondary TEXT,
  karyakar_name_tertiary TEXT,
  salutation TEXT,
  post_nominals TEXT,
  dietary TEXT,
  interest_tags TEXT,
  protocol_notes TEXT,
  vip_category TEXT,
  contribution_notes TEXT,
  sub_sector TEXT,
  date_of_birth TEXT,
  town TEXT,
  approval_status TEXT DEFAULT 'APPROVED',
  submitted_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  submitted_by_name TEXT,
  approved_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ,
  rejection_note TEXT,
  status TEXT DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invitations (
  id BIGSERIAL PRIMARY KEY,
  dignitary_id BIGINT NOT NULL REFERENCES dignitaries(id) ON DELETE RESTRICT,
  event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
  custom_message TEXT,
  status TEXT NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SENT')),
  sent_at TIMESTAMPTZ,
  rsvp_status TEXT DEFAULT 'PENDING',
  rsvp_channels TEXT DEFAULT '[]',
  admin_approval TEXT DEFAULT 'PENDING',
  attended BOOLEAN NOT NULL DEFAULT FALSE,
  attended_at TIMESTAMPTZ,
  rsvp_token TEXT,
  ladies_count INTEGER NOT NULL DEFAULT 0,
  gents_count INTEGER NOT NULL DEFAULT 0,
  tracker_notes TEXT,
  day_rsvp TEXT DEFAULT '{}',
  day_attendance TEXT DEFAULT '{}',
  day_counts TEXT DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS communications (
  id BIGSERIAL PRIMARY KEY,
  dignitary_id BIGINT NOT NULL REFERENCES dignitaries(id) ON DELETE RESTRICT,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN ('PHONE_CALL', 'WHATSAPP', 'EMAIL', 'VISIT', 'PDF_SENT', 'GIFT')),
  notes TEXT NOT NULL,
  happened_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS donations (
  id BIGSERIAL PRIMARY KEY,
  dignitary_id BIGINT REFERENCES dignitaries(id) ON DELETE SET NULL,
  donor_name TEXT NOT NULL,
  amount NUMERIC(12, 2) NOT NULL,
  donation_date TEXT NOT NULL,
  receipt_no TEXT,
  project TEXT,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'RECORDED',
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  dignitary_id BIGINT REFERENCES dignitaries(id) ON DELETE SET NULL,
  event_id BIGINT REFERENCES events(id) ON DELETE SET NULL,
  invitation_id BIGINT REFERENCES invitations(id) ON DELETE SET NULL,
  message TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'REMINDER',
  read_at TIMESTAMPTZ,
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_lookups (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS volunteer_attendance (
  id BIGSERIAL PRIMARY KEY,
  event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attended BOOLEAN NOT NULL DEFAULT FALSE,
  attended_at TIMESTAMPTZ,
  marked_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (event_id, user_id)
);

-- Columns for databases created before the full CREATE TABLE definitions above.
ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_area TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT;

ALTER TABLE events ADD COLUMN IF NOT EXISTS event_time TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS invitation_template TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS schedule TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS standard_message TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'PUBLISHED';
ALTER TABLE events ADD COLUMN IF NOT EXISTS attendance_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS category TEXT DEFAULT 'Government';
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS karyakar_name TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS karyakar_name_secondary TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS karyakar_name_tertiary TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS salutation TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS post_nominals TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS dietary TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS interest_tags TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS protocol_notes TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS vip_category TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS contribution_notes TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS sub_sector TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS date_of_birth TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS town TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'APPROVED';
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS submitted_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS submitted_by_name TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS approved_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS rejection_note TEXT;
ALTER TABLE dignitaries ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'ACTIVE';

ALTER TABLE invitations ADD COLUMN IF NOT EXISTS rsvp_status TEXT DEFAULT 'PENDING';
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS rsvp_channels TEXT DEFAULT '[]';
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS admin_approval TEXT DEFAULT 'PENDING';
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS attended BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS attended_at TIMESTAMPTZ;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS rsvp_token TEXT;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS ladies_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS gents_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS tracker_notes TEXT;
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS day_rsvp TEXT DEFAULT '{}';
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS day_attendance TEXT DEFAULT '{}';
ALTER TABLE invitations ADD COLUMN IF NOT EXISTS day_counts TEXT DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_users_role_status ON users (role, status);
CREATE INDEX IF NOT EXISTS idx_dignitaries_karyakar_name ON dignitaries (karyakar_name);
CREATE INDEX IF NOT EXISTS idx_dignitaries_submitted_by_user_id ON dignitaries (submitted_by_user_id);
CREATE INDEX IF NOT EXISTS idx_dignitaries_approved_by_user_id ON dignitaries (approved_by_user_id);
CREATE INDEX IF NOT EXISTS idx_dignitaries_approval_status ON dignitaries (approval_status);
CREATE INDEX IF NOT EXISTS idx_invitations_dignitary_id ON invitations (dignitary_id);
CREATE INDEX IF NOT EXISTS idx_invitations_event_id ON invitations (event_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_rsvp_token ON invitations (rsvp_token)
  WHERE rsvp_token IS NOT NULL AND btrim(rsvp_token) <> '';
CREATE INDEX IF NOT EXISTS idx_communications_dignitary_id ON communications (dignitary_id);
CREATE INDEX IF NOT EXISTS idx_communications_user_id ON communications (user_id);
CREATE INDEX IF NOT EXISTS idx_communications_happened_at ON communications (happened_at DESC);
CREATE INDEX IF NOT EXISTS idx_donations_dignitary_id ON donations (dignitary_id);
CREATE INDEX IF NOT EXISTS idx_donations_created_by ON donations (created_by);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications (user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_dignitary_id ON notifications (dignitary_id);
CREATE INDEX IF NOT EXISTS idx_notifications_event_id ON notifications (event_id);
CREATE INDEX IF NOT EXISTS idx_notifications_invitation_id ON notifications (invitation_id);
CREATE INDEX IF NOT EXISTS idx_notifications_created_by ON notifications (created_by);
CREATE INDEX IF NOT EXISTS idx_volunteer_attendance_user_id ON volunteer_attendance (user_id);
CREATE INDEX IF NOT EXISTS idx_volunteer_attendance_marked_by ON volunteer_attendance (marked_by);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
