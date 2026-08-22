-- MCP Security Gateway — Audit Schema
-- Separate schema file for audit infrastructure.
-- Run: psql $DATABASE_URL -f src/audit/schema.sql

BEGIN;

-- ── IMMUTABLE AUDIT LOG WITH HASH CHAINING ────────────────────────────
-- Each row stores a SHA-256 hash of (prev_hash || current data) for
-- tamper-evident log chaining (SOC 2 CC7.2 compliance).

-- Create audit schema namespace
CREATE SCHEMA IF NOT EXISTS audit;

-- Hash-chained immutable log table
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

-- Prevent UPDATE and DELETE on audit log (tamper protection)
CREATE OR REPLACE RULE no_update_audit AS ON UPDATE TO audit.immutable_log DO INSTEAD NOTHING;
CREATE OR REPLACE RULE no_delete_audit AS ON DELETE TO audit.immutable_log DO INSTEAD NOTHING;

-- Index for hash chain verification
CREATE INDEX IF NOT EXISTS idx_immutable_seq ON audit.immutable_log(seq DESC);
CREATE INDEX IF NOT EXISTS idx_immutable_tenant ON audit.immutable_log(tenant_id, created_at DESC);

-- ── AUDIT LOG INTEGRITY CHECK FUNCTION ───────────────────────────────
CREATE OR REPLACE FUNCTION audit.verify_chain(
  p_tenant_id UUID DEFAULT NULL,
  p_limit INTEGER DEFAULT 1000
) RETURNS TABLE(broken_at BIGINT, expected_hash TEXT, actual_hash TEXT) AS $$
DECLARE
  prev TEXT := '0000000000000000000000000000000000000000000000000000000000000000';
  r RECORD;
BEGIN
  FOR r IN
    SELECT seq, prev_hash, row_hash
    FROM audit.immutable_log
    WHERE (p_tenant_id IS NULL OR tenant_id = p_tenant_id)
    ORDER BY seq ASC
    LIMIT p_limit
  LOOP
    IF r.prev_hash != prev THEN
      RETURN QUERY SELECT r.seq, prev, r.prev_hash;
    END IF;
    prev := r.row_hash;
  END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ── SIEM CONFIG STORAGE ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS siem_configs (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  provider    TEXT NOT NULL CHECK (provider IN ('splunk','datadog','elastic','generic')),
  endpoint    TEXT NOT NULL,
  api_key_enc TEXT NOT NULL,
  active      BOOLEAN DEFAULT TRUE,
  last_flush  TIMESTAMPTZ,
  events_sent BIGINT DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, provider)
);

-- ── ALERT RULES ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
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

-- ── IP ALLOWLISTS (Sprint 3 enterprise feature) ───────────────────────
CREATE TABLE IF NOT EXISTS tenant_ip_allowlists (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  cidr        INET NOT NULL,
  description TEXT,
  active      BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_ip_allowlist_tenant ON tenant_ip_allowlists(tenant_id) WHERE active=TRUE;

-- ── ADMIN ROLES (Sprint 3: multi-admin) ──────────────────────────────
CREATE TABLE IF NOT EXISTS admin_members (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  email       TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('super_admin','billing_admin','security_analyst','viewer')),
  invited_by  TEXT,
  active      BOOLEAN DEFAULT TRUE,
  last_login  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_admin_members_tenant ON admin_members(tenant_id, active);

-- ── SSO GROUP → RBAC MAPPINGS (Sprint 3) ──────────────────────────────
CREATE TABLE IF NOT EXISTS sso_group_mappings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  provider    TEXT NOT NULL,
  group_name  TEXT NOT NULL,
  agent_id    TEXT NOT NULL,
  policy_action TEXT DEFAULT 'allow',
  tools       TEXT[] DEFAULT '{}',
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, provider, group_name, agent_id)
);

-- ── DATA RETENTION POLICIES (Sprint 3) ───────────────────────────────
CREATE TABLE IF NOT EXISTS retention_policies (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL UNIQUE,
  audit_log_days  INTEGER DEFAULT 90,
  dlp_events_days INTEGER DEFAULT 30,
  hitl_days       INTEGER DEFAULT 60,
  shadow_days     INTEGER DEFAULT 30,
  custom_rule     JSONB DEFAULT '{}',
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ── SLA METRICS (Sprint 3) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sla_metrics (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID,
  metric_type   TEXT NOT NULL CHECK (metric_type IN ('uptime','p50_ms','p95_ms','p99_ms','error_rate')),
  value         FLOAT NOT NULL,
  "window"      TEXT NOT NULL DEFAULT '1h',
  recorded_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sla_tenant_time ON sla_metrics(tenant_id, metric_type, recorded_at DESC);

-- ── SCIM PROVISIONING (Sprint 4) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS scim_configs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL UNIQUE,
  provider      TEXT NOT NULL,
  scim_endpoint TEXT,
  bearer_token_hash TEXT,
  last_sync     TIMESTAMPTZ,
  sync_status   TEXT DEFAULT 'pending',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

COMMIT;
