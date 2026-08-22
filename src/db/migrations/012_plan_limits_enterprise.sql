-- Enterprise plan limits, tenant contract overrides, and limit-block audit.

BEGIN;

CREATE TABLE IF NOT EXISTS plan_limits (
  plan TEXT PRIMARY KEY,
  max_alert_channels INTEGER NOT NULL,
  max_alert_rules INTEGER NOT NULL,
  max_agents INTEGER NOT NULL,
  max_integrations INTEGER NOT NULL,
  max_audit_export_days INTEGER NOT NULL,
  max_analytics_export_days INTEGER NOT NULL,
  max_retention_days INTEGER NOT NULL,
  max_team_members INTEGER NOT NULL,
  max_ml_profiles INTEGER NOT NULL,
  max_hitl_policies INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_limit_overrides (
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  feature_key TEXT NOT NULL,
  limit_value INTEGER NOT NULL CHECK (limit_value >= 0),
  updated_by TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (tenant_id, feature_key)
);

CREATE TABLE IF NOT EXISTS plan_limit_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  plan TEXT,
  feature_key TEXT NOT NULL,
  used INTEGER NOT NULL,
  limit_value INTEGER NOT NULL,
  allowed BOOLEAN NOT NULL DEFAULT FALSE,
  action TEXT NOT NULL,
  message TEXT,
  actor_email TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plan_limit_audit_tenant ON plan_limit_audit(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_plan_limit_audit_feature ON plan_limit_audit(feature_key, created_at DESC);

CREATE TABLE IF NOT EXISTS admin_action_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  actor_email TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_action_tenant_time ON admin_action_log(tenant_id, created_at DESC);

INSERT INTO plan_limits (
  plan, max_alert_channels, max_alert_rules, max_agents, max_integrations,
  max_audit_export_days, max_analytics_export_days, max_retention_days,
  max_team_members, max_ml_profiles, max_hitl_policies, updated_at
) VALUES
  ('starter', 2, 5, 5, 1, 0, 7, 7, 2, 1, 1, NOW()),
  ('growth', 10, 25, 25, 5, 30, 30, 30, 10, 25, 10, NOW()),
  ('enterprise', 1000, 1000, 200, 100, 365, 365, 365, 200, 200, 100, NOW())
ON CONFLICT (plan) DO NOTHING;

COMMIT;
