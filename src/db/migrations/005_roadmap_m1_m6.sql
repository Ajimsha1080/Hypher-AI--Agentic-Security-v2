-- Migration 005: M1–M6 roadmap additions
-- A2A protocol tables, multi-region, SOC2 automation
-- Run: psql $DATABASE_URL -f src/db/migrations/005_roadmap_m1_m6.sql

BEGIN;

-- ── MULTI-REGION (M2-3) ──────────────────────────────────────────────
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS preferred_region TEXT DEFAULT 'us-east'
    CHECK (preferred_region IN ('us-east','eu-west','apac')),
  ADD COLUMN IF NOT EXISTS data_residency   TEXT DEFAULT 'us-east-1';

CREATE INDEX IF NOT EXISTS idx_tenants_region ON tenants(preferred_region);

-- ── A2A PROTOCOL (M4) ────────────────────────────────────────────────

-- Registered peer agents (agents this tenant trusts A2A calls from)
CREATE TABLE IF NOT EXISTS a2a_peers (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id),
  agent_url         TEXT NOT NULL,
  display_name      TEXT,
  jwks_uri          TEXT,
  peer_capabilities JSONB DEFAULT '[]',
  active            BOOLEAN DEFAULT TRUE,
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, agent_url)
);
CREATE INDEX IF NOT EXISTS idx_a2a_peers_tenant ON a2a_peers(tenant_id) WHERE active=true;

-- Per-peer method allowlists
CREATE TABLE IF NOT EXISTS a2a_policies (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id),
  peer_agent_url   TEXT NOT NULL,
  allowed_methods  JSONB NOT NULL DEFAULT '["*"]',
  active           BOOLEAN DEFAULT TRUE,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, peer_agent_url)
);

-- A2A audit log (immutable, same retention as regular audit_log)
CREATE TABLE IF NOT EXISTS a2a_audit_log (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id),
  request_id       TEXT NOT NULL,
  from_agent_url   TEXT NOT NULL,
  from_agent_id    TEXT,
  to_agent_id      TEXT NOT NULL,
  method           TEXT NOT NULL,
  decision         TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  reason           TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_a2a_audit_tenant ON a2a_audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_a2a_audit_peer   ON a2a_audit_log(from_agent_url, created_at DESC);

-- ── SOC2 AUTOMATION TABLES (M3-4) ────────────────────────────────────

-- Track evidence collection runs per control
CREATE TABLE IF NOT EXISTS soc2_evidence_runs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  control_id   TEXT NOT NULL,
  period_start TIMESTAMPTZ NOT NULL,
  period_end   TIMESTAMPTZ NOT NULL,
  row_count    INTEGER,
  sha256       TEXT,
  pushed_to    TEXT,  -- 'vanta' | 'drata' | null
  pushed_at    TIMESTAMPTZ,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_soc2_runs_tenant ON soc2_evidence_runs(tenant_id, created_at DESC);

-- ── BENCHMARK RESULTS (M2) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS benchmark_results (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_at         TIMESTAMPTZ DEFAULT NOW(),
  total_requests INTEGER,
  concurrency    INTEGER,
  p50_ms         NUMERIC(10,3),
  p95_ms         NUMERIC(10,3),
  p99_ms         NUMERIC(10,3),
  p999_ms        NUMERIC(10,3),
  mean_ms        NUMERIC(10,3),
  throughput_rps INTEGER,
  passed_sla     BOOLEAN,
  environment    TEXT,
  notes          TEXT
);

-- ── FEATURE FLAGS for new features ───────────────────────────────────
INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
SELECT t.id, f.flag_name, f.enabled
FROM tenants t
CROSS JOIN (VALUES
  ('a2a_protocol',       false),
  ('multi_region',       false),
  ('soc2_automation',    false),
  ('benchmark_access',   false)
) AS f(flag_name, enabled)
ON CONFLICT (tenant_id, flag_name) DO NOTHING;

-- Enable for enterprise tenants
UPDATE tenant_feature_flags tff
SET enabled = true
FROM tenants t
WHERE tff.tenant_id = t.id
  AND t.plan = 'enterprise'
  AND tff.flag_name IN ('a2a_protocol', 'multi_region', 'soc2_automation');

-- ── A2A audit rotation ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION rotate_a2a_logs() RETURNS void AS $$
BEGIN
  DELETE FROM a2a_audit_log WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

COMMIT;
