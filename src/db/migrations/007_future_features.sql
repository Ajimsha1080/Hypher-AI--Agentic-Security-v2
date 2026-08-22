-- Migration 007: Future features tables
-- policy_versions, webhook_deliveries, agent_budgets, policy_templates, key expiry
-- Run: psql $DATABASE_URL -f src/db/migrations/007_future_features.sql

BEGIN;

-- ── POLICY VERSION HISTORY ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_versions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  agent_id      TEXT NOT NULL,
  version       INTEGER NOT NULL DEFAULT 1,
  changed_by    TEXT,
  change_reason TEXT,
  snapshot_json JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant ON policy_versions(tenant_id, agent_id, version DESC);

-- ── WEBHOOK DELIVERY LOG ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id),
  rule_name        TEXT,
  event_type       TEXT,
  destination_type TEXT CHECK (destination_type IN ('slack','pagerduty','webhook','email')),
  destination_url  TEXT,
  payload_json     JSONB,
  http_status      INTEGER,
  response_ms      INTEGER,
  retry_count      INTEGER DEFAULT 0,
  delivered        BOOLEAN DEFAULT FALSE,
  error_message    TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS rule_name TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS destination_type TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS destination_url TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS payload_json JSONB;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS http_status INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS response_ms INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS retry_count INTEGER DEFAULT 0;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS delivered BOOLEAN DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_tenant ON webhook_deliveries(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_failed ON webhook_deliveries(tenant_id, delivered) WHERE delivered=FALSE;

-- ── AGENT BUDGETS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_budgets (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            UUID NOT NULL REFERENCES tenants(id),
  agent_id             TEXT NOT NULL,
  monthly_call_limit   INTEGER NOT NULL,
  action_on_exceed     TEXT DEFAULT 'throttle' CHECK (action_on_exceed IN ('throttle','require_hitl','block')),
  current_month_calls  INTEGER DEFAULT 0,
  created_at           TIMESTAMPTZ DEFAULT NOW(),
  updated_at           TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_budgets_tenant ON agent_budgets(tenant_id, agent_id);

-- ── POLICY TEMPLATES (community library) ─────────────────────────────
CREATE TABLE IF NOT EXISTS policy_templates (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID REFERENCES tenants(id),
  name        TEXT NOT NULL,
  description TEXT,
  tools       TEXT[] DEFAULT '{}',
  arg_rules   JSONB DEFAULT '[]',
  features    JSONB DEFAULT '{}',
  tags        TEXT[] DEFAULT '{}',
  public      BOOLEAN DEFAULT FALSE,
  installs    INTEGER DEFAULT 0,
  created_by  TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policy_templates_public ON policy_templates(public, installs DESC) WHERE public=TRUE;

-- ── AGENT TOKEN EXPIRY (key rotation grace period) ────────────────────
ALTER TABLE agent_tokens
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_tokens_expiry ON agent_tokens(expires_at) WHERE expires_at IS NOT NULL;

-- ── OTEL CONFIG in tenants metadata (JSON field, no schema change needed) ──
-- tenant.metadata->>'otel' stores: { endpoint, headers, enabled }

-- ── PROMETHEUS METRICS TOKEN ─────────────────────────────────────────
-- Stored as env var METRICS_TOKEN, no table needed

-- ── TOOL ARG RULES — add tenant_id unique constraint if missing ───────
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE table_name='tool_arg_rules' AND constraint_name='tool_arg_rules_tool_name_arg_key_tenant_id_key'
  ) THEN
    -- Add partial unique constraint for tenant-specific rules
    CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_arg_rules_tenant
      ON tool_arg_rules(tool_name, arg_key, tenant_id) WHERE tenant_id IS NOT NULL;
  END IF;
END $$;

COMMIT;
