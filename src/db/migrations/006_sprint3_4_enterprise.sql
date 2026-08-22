-- Migration 006: Sprint 3+4 Enterprise Features
-- Adds tables for: multi-admin, IP allowlists, SSO group mapping,
-- SLA metrics, SCIM, data retention, branding, feature flags
-- Run: psql $DATABASE_URL -f src/db/migrations/006_sprint3_4_enterprise.sql

BEGIN;

-- ── TENANT FEATURE FLAGS ───────────────────────────────────────────────
-- Used to enable/disable features per tenant (hitl, HIPAA mode, etc.)
CREATE TABLE IF NOT EXISTS tenant_feature_flags (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  flag_name   TEXT NOT NULL,
  enabled     BOOLEAN DEFAULT FALSE,
  metadata    JSONB DEFAULT '{}',
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, flag_name)
);
CREATE INDEX IF NOT EXISTS idx_flags_tenant ON tenant_feature_flags(tenant_id, flag_name);

-- Default flags for all existing tenants
INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT id, 'hitl_approvals', plan = 'enterprise' FROM tenants
ON CONFLICT DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT id, 'dlp_hipaa_mode', FALSE FROM tenants
ON CONFLICT DO NOTHING;

INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT id, 'hash_chain_audit', plan = 'enterprise' FROM tenants
ON CONFLICT DO NOTHING;

-- ── ADD MISSING COLUMNS TO TENANTS ────────────────────────────────────
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS metadata    JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS branding    JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;

-- ── ADMIN MEMBERS (multi-admin roles) ────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_members (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id),
  email             TEXT NOT NULL,
  role              TEXT NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('super_admin','security_analyst','billing_admin','viewer')),
  invited_by        TEXT,
  invite_token_hash TEXT,
  active            BOOLEAN DEFAULT TRUE,
  last_login        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_admin_members_tenant ON admin_members(tenant_id, active);

-- ── IP ALLOWLISTS (per-tenant CIDR access control) ────────────────────
CREATE TABLE IF NOT EXISTS tenant_ip_allowlists (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  cidr        INET NOT NULL,
  description TEXT,
  active      BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_ip_allowlist_tenant ON tenant_ip_allowlists(tenant_id) WHERE active=TRUE;

-- ── SSO GROUP → RBAC MAPPINGS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sso_group_mappings (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  provider      TEXT NOT NULL,
  group_name    TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  policy_action TEXT DEFAULT 'allow',
  tools         TEXT[] DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, provider, group_name, agent_id)
);

-- ── SLA METRICS ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sla_metrics (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID REFERENCES tenants(id),
  metric_type   TEXT NOT NULL CHECK (metric_type IN ('uptime','p50_ms','p95_ms','p99_ms','error_rate')),
  value         FLOAT NOT NULL,
  "window"      TEXT NOT NULL DEFAULT '1h',
  recorded_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sla_tenant_time ON sla_metrics(tenant_id, metric_type, recorded_at DESC);

-- ── SCIM PROVISIONING CONFIG ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_configs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL UNIQUE REFERENCES tenants(id),
  provider          TEXT NOT NULL,
  scim_endpoint     TEXT,
  bearer_token_hash TEXT NOT NULL,
  last_sync         TIMESTAMPTZ,
  sync_status       TEXT DEFAULT 'pending',
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ── DATA RETENTION POLICIES ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS retention_policies (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL UNIQUE REFERENCES tenants(id),
  audit_log_days    INTEGER DEFAULT 90,
  dlp_events_days   INTEGER DEFAULT 30,
  hitl_days         INTEGER DEFAULT 60,
  shadow_days       INTEGER DEFAULT 30,
  custom_rule       JSONB DEFAULT '{}',
  updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ── IMMUTABLE HASH-CHAINED AUDIT LOG ─────────────────────────────────
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.immutable_log (
  seq         BIGSERIAL PRIMARY KEY,
  tenant_id   UUID,
  agent_id    TEXT NOT NULL,
  tool_name   TEXT NOT NULL,
  decision    TEXT NOT NULL,
  reason      TEXT,
  prev_hash   TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
  row_hash    TEXT NOT NULL,
  args_hash   TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE OR REPLACE RULE no_update_audit AS ON UPDATE TO audit.immutable_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE no_delete_audit AS ON DELETE TO audit.immutable_log DO INSTEAD NOTHING;

CREATE INDEX IF NOT EXISTS idx_immutable_seq    ON audit.immutable_log(seq DESC);
CREATE INDEX IF NOT EXISTS idx_immutable_tenant ON audit.immutable_log(tenant_id, created_at DESC);

-- ── SIEM CONFIG STORAGE ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS siem_configs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  provider    TEXT NOT NULL CHECK (provider IN ('splunk','datadog','elastic','generic')),
  endpoint    TEXT NOT NULL,
  api_key_enc TEXT NOT NULL,
  active      BOOLEAN DEFAULT TRUE,
  last_flush  TIMESTAMPTZ,
  events_sent BIGINT DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, provider)
);

-- ── ALERT RULES (if not already created by migration 002) ────────────
CREATE TABLE IF NOT EXISTS alert_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id),
  name            TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  threshold       INTEGER,
  window_minutes  INTEGER DEFAULT 60,
  severity        TEXT DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
  webhook_url     TEXT,
  slack_webhook   TEXT,
  email           TEXT,
  active          BOOLEAN DEFAULT TRUE,
  last_triggered  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant ON alert_rules(tenant_id, active);

-- ── ADD source_ip & integration_method TO AUDIT LOG (if missing) ─────
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS source_ip          INET,
  ADD COLUMN IF NOT EXISTS integration_method TEXT,
  ADD COLUMN IF NOT EXISTS dlp_triggered      BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS hitl_required      BOOLEAN DEFAULT FALSE;

COMMIT;
