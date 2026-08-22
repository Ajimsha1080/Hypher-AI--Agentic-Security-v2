-- Migration 004: v2.0.0 gap fixes and enterprise features
-- Run after 001, 002, 003
-- psql $DATABASE_URL -f src/db/migrations/004_v2_enterprise.sql

BEGIN;

-- ── FIX: args_length column missing from audit_log (anomaly detector needs it) ──
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS args_length   INTEGER,
  ADD COLUMN IF NOT EXISTS source_ip     INET,
  ADD COLUMN IF NOT EXISTS source_country TEXT;

-- ── FIX: tenant_id required on audit_log for isolation ───────────────
-- (was optional, now enforced by app layer — column already exists from migration 002)

-- ── FIX: user_sessions table for auth/routes.ts ───────────────────────
CREATE TABLE IF NOT EXISTS user_sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  TEXT NOT NULL UNIQUE,
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  email       TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON user_sessions(expires_at);

-- ── FIX: admin_users table ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  active        BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── FIX: tenant_users table for customer login ─────────────────────────
CREATE TABLE IF NOT EXISTS tenant_users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  active        BOOLEAN DEFAULT TRUE,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tenant_users_email ON tenant_users(email) WHERE active=true;

-- ── FIX: agent_oidc_mappings needs tenant_id FK ───────────────────────
ALTER TABLE agent_oidc_mappings
  ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);

-- ── FIX: usage_overage missing billed column ─────────────────────────
ALTER TABLE usage_overage
  ADD COLUMN IF NOT EXISTS billed    BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS billed_at TIMESTAMPTZ;

-- ── FIX: registry_servers needs unique constraint on name ─────────────
CREATE UNIQUE INDEX IF NOT EXISTS idx_registry_name ON registry_servers(name);

-- ── NEW: SIEM configuration per tenant ───────────────────────────────
CREATE TABLE IF NOT EXISTS siem_configs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id),
  provider          TEXT NOT NULL CHECK (provider IN ('splunk','datadog','elastic','generic')),
  endpoint          TEXT NOT NULL,
  api_key_encrypted TEXT NOT NULL,
  index_name        TEXT,
  source            TEXT,
  tags              JSONB DEFAULT '[]',
  batch_size        INTEGER DEFAULT 100,
  active            BOOLEAN DEFAULT TRUE,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  updated_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, provider)
);

-- ── NEW: Password reset tokens ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash  TEXT PRIMARY KEY,
  email       TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
  used        BOOLEAN DEFAULT FALSE
);

-- ── NEW: Terraform state table (for Terraform provider) ───────────────
CREATE TABLE IF NOT EXISTS terraform_state (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  state_json  JSONB NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, resource_type, resource_id)
);

-- ── NEW: SOC2 compliance export log ───────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance_exports (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  export_type   TEXT NOT NULL DEFAULT 'soc2',
  date_from     TIMESTAMPTZ NOT NULL,
  date_to       TIMESTAMPTZ NOT NULL,
  row_count     INTEGER,
  file_hash     TEXT,
  generated_by  TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── NEW: API key rotation log ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_key_rotations (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  agent_id    TEXT,
  rotated_by  TEXT,
  reason      TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── NEW: Webhook delivery log (for debugging) ─────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  channel       TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  status_code   INTEGER,
  success       BOOLEAN DEFAULT FALSE,
  duration_ms   INTEGER,
  error_message TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id, created_at DESC);

-- ── NEW: Feature flags — enterprise plan gate ─────────────────────────
-- Already exists from migration 003, but add new flags
INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT t.id, f.flag_name, f.enabled
FROM tenants t
CROSS JOIN (VALUES
  ('siem_forwarding',     false),
  ('soc2_export',         false),
  ('terraform_provider',  false),
  ('realtime_dashboard',  false),
  ('python_sdk',          false),
  ('multi_region',        false)
) AS f(flag_name, enabled)
ON CONFLICT (tenant_id, flag_name) DO NOTHING;

-- Enable enterprise features for enterprise plan tenants
UPDATE tenant_feature_flags tff
SET enabled = true
FROM tenants t
WHERE tff.tenant_id = t.id
  AND t.plan = 'enterprise'
  AND tff.flag_name IN ('siem_forwarding','soc2_export','terraform_provider','realtime_dashboard');

-- ── Performance indexes ────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_audit_source_ip    ON audit_log(source_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_args_length  ON audit_log(args_length) WHERE args_length > 4096;
CREATE INDEX IF NOT EXISTS idx_siem_tenant        ON siem_configs(tenant_id) WHERE active=true;

-- ── Cleanup: expire old user sessions ─────────────────────────────────
CREATE OR REPLACE FUNCTION cleanup_expired_sessions() RETURNS void AS $$
BEGIN
  DELETE FROM user_sessions WHERE expires_at < NOW();
  DELETE FROM password_reset_tokens WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMIT;
