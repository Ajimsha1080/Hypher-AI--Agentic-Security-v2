-- Migration 003: Admin panel, billing, and analytics tables
-- Run: psql $DATABASE_URL -f src/db/migrations/003_admin_billing_analytics.sql

BEGIN;

-- ── ADMIN ACTIONS LOG ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_actions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action      TEXT NOT NULL,
  target_id   TEXT,
  reason      TEXT,
  performed_by TEXT DEFAULT 'admin',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── TENANT SUSPENSION ─────────────────────────────────────────────────
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS stripe_customer_id      TEXT,
  ADD COLUMN IF NOT EXISTS stripe_subscription_id  TEXT,
  ADD COLUMN IF NOT EXISTS subscription_status     TEXT DEFAULT 'trialing',
  ADD COLUMN IF NOT EXISTS suspension_reason       TEXT,
  ADD COLUMN IF NOT EXISTS trial_ends_at           TIMESTAMPTZ DEFAULT NOW() + INTERVAL '14 days';

CREATE INDEX IF NOT EXISTS idx_tenants_stripe ON tenants(stripe_customer_id);

-- ── BILLING INVOICES ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS billing_invoices (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id),
  stripe_invoice_id TEXT UNIQUE,
  amount_usd        NUMERIC(10,2),
  status            TEXT DEFAULT 'pending',
  paid_at           TIMESTAMPTZ,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON billing_invoices(tenant_id, paid_at DESC);

-- ── USAGE ANALYTICS COLUMNS ───────────────────────────────────────────
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS integration_method TEXT,
  ADD COLUMN IF NOT EXISTS sdk_version        TEXT,
  ADD COLUMN IF NOT EXISTS source_ip          INET,
  ADD COLUMN IF NOT EXISTS source_country     TEXT;

-- ── AGENT SESSIONS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_sessions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  agent_id     TEXT NOT NULL,
  session_start TIMESTAMPTZ DEFAULT NOW(),
  session_end  TIMESTAMPTZ,
  total_calls  INTEGER DEFAULT 0,
  total_denied INTEGER DEFAULT 0,
  integration_method TEXT,
  sdk_version  TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_agent ON agent_sessions(tenant_id, agent_id, session_start DESC);

-- ── PRODUCT ONBOARDING CHECKLIST ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS onboarding_progress (
  tenant_id   UUID PRIMARY KEY REFERENCES tenants(id),
  step_created_agent    BOOLEAN DEFAULT FALSE,
  step_first_tool_call  BOOLEAN DEFAULT FALSE,
  step_configured_alert BOOLEAN DEFAULT FALSE,
  step_added_oidc       BOOLEAN DEFAULT FALSE,
  step_viewed_dashboard BOOLEAN DEFAULT FALSE,
  completed_at          TIMESTAMPTZ,
  updated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- ── FEATURE FLAGS PER TENANT ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_feature_flags (
  tenant_id  UUID NOT NULL REFERENCES tenants(id),
  flag_name  TEXT NOT NULL,
  enabled    BOOLEAN DEFAULT FALSE,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (tenant_id, flag_name)
);

-- Default flags for new tenants (insert via trigger)
CREATE OR REPLACE FUNCTION create_default_tenant_data() RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO onboarding_progress (tenant_id) VALUES (NEW.id);
  INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled) VALUES
    (NEW.id, 'anomaly_detection', NEW.plan != 'starter'),
    (NEW.id, 'federated_threats', NEW.plan = 'enterprise'),
    (NEW.id, 'sandbox_isolation', NEW.plan = 'enterprise'),
    (NEW.id, 'advanced_analytics', NEW.plan != 'starter');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS on_tenant_created ON tenants;
CREATE TRIGGER on_tenant_created AFTER INSERT ON tenants
  FOR EACH ROW EXECUTE FUNCTION create_default_tenant_data();

-- ── ONBOARDING PROGRESS UPDATER ───────────────────────────────────────
CREATE OR REPLACE FUNCTION update_onboarding_on_audit() RETURNS TRIGGER AS $$
BEGIN
  -- Mark first_tool_call when first ALLOW happens
  IF NEW.decision = 'ALLOW' THEN
    UPDATE onboarding_progress
    SET step_first_tool_call = TRUE, updated_at = NOW()
    WHERE tenant_id = NEW.tenant_id AND step_first_tool_call = FALSE;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS on_audit_entry ON audit_log;
CREATE TRIGGER on_audit_entry AFTER INSERT ON audit_log
  FOR EACH ROW EXECUTE FUNCTION update_onboarding_on_audit();

COMMIT;
