-- Migration 005: Immediate features — DLP, Shadow MCP, HITL, Managed Cloud
-- Run: psql $DATABASE_URL -f src/db/migrations/005_immediate_features.sql

BEGIN;

-- ── DLP EVENTS ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dlp_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id),
  agent_id        TEXT NOT NULL,
  tool_name       TEXT NOT NULL,
  direction       TEXT NOT NULL CHECK (direction IN ('request', 'response')),
  pii_types       JSONB NOT NULL DEFAULT '[]',  -- array of detected types
  detection_count INTEGER NOT NULL DEFAULT 0,
  blocked         BOOLEAN DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dlp_tenant_time ON dlp_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dlp_blocked ON dlp_events(tenant_id, blocked) WHERE blocked = true;

-- ── SHADOW MCP FINDINGS ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shadow_mcp_findings (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  agent_id    TEXT,
  source_ip   INET,
  method      TEXT NOT NULL,
  risk_score  INTEGER NOT NULL DEFAULT 0,
  risk_level  TEXT NOT NULL DEFAULT 'medium' CHECK (risk_level IN ('low','medium','high','critical')),
  reason      TEXT NOT NULL,
  tools_used  JSONB DEFAULT '[]',
  approved    BOOLEAN DEFAULT FALSE,
  approved_by TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, agent_id, method)
);
CREATE INDEX IF NOT EXISTS idx_shadow_tenant ON shadow_mcp_findings(tenant_id, risk_level, created_at DESC);

-- ── HITL APPROVALS ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hitl_approvals (
  approval_id   TEXT PRIMARY KEY,
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  agent_id      TEXT NOT NULL,
  tool_name     TEXT NOT NULL,
  args_json     JSONB,
  risk_level    TEXT NOT NULL,
  risk_reason   TEXT NOT NULL,
  decision      TEXT NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approved','denied','timeout')),
  decided_at    TIMESTAMPTZ,
  decided_by    TEXT,
  decision_note TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '15 minutes'
);
CREATE INDEX IF NOT EXISTS idx_hitl_tenant_pending ON hitl_approvals(tenant_id, decision, created_at DESC);

-- ── MANAGED CLOUD TENANTS (hosted tier) ───────────────────────────────
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS deployment_type TEXT DEFAULT 'self_hosted'
    CHECK (deployment_type IN ('self_hosted', 'managed_cloud', 'enterprise_vpc')),
  ADD COLUMN IF NOT EXISTS cloud_subdomain TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS cloud_provisioned_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS cloud_db_url TEXT,
  ADD COLUMN IF NOT EXISTS cloud_redis_url TEXT;

-- ── RESPONSE FILTER LOG ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_filter_log (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  agent_id      TEXT NOT NULL,
  tool_name     TEXT NOT NULL,
  pii_types_found JSONB DEFAULT '[]',
  masking_count INTEGER DEFAULT 0,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_response_filter ON response_filter_log(tenant_id, created_at DESC);

-- ── SECRET DETECTION EVENTS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS secret_detection_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  agent_id    TEXT NOT NULL,
  tool_name   TEXT NOT NULL,
  secret_type TEXT NOT NULL,  -- 'aws_key', 'github_token', etc.
  direction   TEXT NOT NULL CHECK (direction IN ('request', 'response')),
  blocked     BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secrets_tenant ON secret_detection_events(tenant_id, created_at DESC);

-- ── HITL RULES (per tenant customisation) ─────────────────────────────
CREATE TABLE IF NOT EXISTS hitl_rules (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  tool_name   TEXT NOT NULL,
  risk_level  TEXT NOT NULL CHECK (risk_level IN ('auto_approve','flag_and_allow','require_approval','auto_deny')),
  condition   TEXT,  -- optional JSON condition for arg matching
  active      BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, tool_name)
);

-- ── FEATURE FLAGS for new features ────────────────────────────────────
INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT t.id, f.flag_name, f.enabled
FROM tenants t
CROSS JOIN (VALUES
  ('dlp_scanning',         true),   -- all plans
  ('response_filtering',   true),   -- all plans
  ('secret_detection',     true),   -- all plans
  ('shadow_discovery',     false),  -- growth+
  ('hitl_approvals',       false),  -- enterprise
  ('hipaa_mode',           false),  -- enterprise add-on
  ('managed_cloud',        false),  -- cloud plan
  ('realtime_dashboard',   false)   -- enterprise
) AS f(flag_name, enabled)
ON CONFLICT (tenant_id, flag_name) DO NOTHING;

-- Enable shadow + hitl for growth+
UPDATE tenant_feature_flags tff
SET enabled = true
FROM tenants t
WHERE tff.tenant_id = t.id
  AND t.plan IN ('growth', 'enterprise')
  AND tff.flag_name = 'shadow_discovery';

UPDATE tenant_feature_flags tff
SET enabled = true
FROM tenants t
WHERE tff.tenant_id = t.id
  AND t.plan = 'enterprise'
  AND tff.flag_name IN ('hitl_approvals', 'hipaa_mode', 'realtime_dashboard');

-- ── AUDIT LOG: add DLP columns ─────────────────────────────────────────
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS dlp_triggered  BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS dlp_types      JSONB,
  ADD COLUMN IF NOT EXISTS hitl_required  BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS hitl_id        TEXT;

COMMIT;
