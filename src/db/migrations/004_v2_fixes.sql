-- Migration 004: v2.0.0 fixes — missing columns, tables, and constraints
-- Run: psql $DATABASE_URL -f src/db/migrations/004_v2_fixes.sql

BEGIN;

-- FIX: args_length was referenced but never added to audit_log in migration 002
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS args_length         INTEGER,
  ADD COLUMN IF NOT EXISTS integration_method  TEXT,
  ADD COLUMN IF NOT EXISTS source_ip           INET,
  ADD COLUMN IF NOT EXISTS source_country      TEXT;

-- FIX: OAuth state table for CSRF-safe OAuth callbacks (was missing)
CREATE TABLE IF NOT EXISTS oauth_states (
  state       TEXT PRIMARY KEY,
  provider    TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_states_exp ON oauth_states(expires_at);

-- FIX: user_sessions table (referenced in auth/routes.ts but never defined)
CREATE TABLE IF NOT EXISTS user_sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  TEXT NOT NULL UNIQUE,
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  email       TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON user_sessions(expires_at);

-- FIX: admin_users table (referenced in auth/routes.ts but never defined)
CREATE TABLE IF NOT EXISTS admin_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  active        BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- FIX: tenant_users table (referenced in auth/routes.ts but never defined)
CREATE TABLE IF NOT EXISTS tenant_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  email         TEXT NOT NULL,
  password_hash TEXT NOT NULL DEFAULT '',
  active        BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_tenant_users_email ON tenant_users(email);

-- FIX: email_queue (new email system)
CREATE TABLE IF NOT EXISTS email_queue (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  to_email    TEXT NOT NULL,
  template    TEXT NOT NULL,
  payload     JSONB NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL DEFAULT 'pending',
  attempts    INTEGER DEFAULT 0,
  sent_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status, created_at);

-- NEW: SOC 2 reports table
CREATE TABLE IF NOT EXISTS soc2_reports (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  report_id    TEXT NOT NULL UNIQUE,
  period_start TIMESTAMPTZ NOT NULL,
  period_end   TIMESTAMPTZ NOT NULL,
  report_json  JSONB NOT NULL,
  generated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soc2_reports_tenant ON soc2_reports(tenant_id, generated_at DESC);

-- FIX: db:migrate package.json script only ran 001. Add view that lists what to run.
-- (package.json updated separately to run all 4 migrations)

-- Seed admin user (password must be set via UPDATE after bcrypt hash)
INSERT INTO admin_users (email, password_hash, active)
VALUES (COALESCE(current_setting('app.admin_email', true), 'admin@example.com'), '$placeholder_change_me', true)
ON CONFLICT (email) DO NOTHING;

-- Cleanup expired OAuth states every hour via pg_cron (if available)
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_cron') THEN
    PERFORM cron.schedule('cleanup-oauth-states', '0 * * * *', 'DELETE FROM oauth_states WHERE expires_at < NOW()');
    PERFORM cron.schedule('cleanup-sessions', '0 2 * * *', 'DELETE FROM user_sessions WHERE expires_at < NOW()');
    PERFORM cron.schedule('rotate-audit-logs', '0 3 * * 0', 'SELECT rotate_audit_logs()');
  END IF;
END $$;

COMMIT;
