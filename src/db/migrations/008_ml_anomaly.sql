-- Migration 008: ML Anomaly Engine tables
-- Per-agent ML behaviour profiles, anomaly events, human feedback loop
-- Run: psql $DATABASE_URL -f src/db/migrations/008_ml_anomaly.sql

BEGIN;

-- ── PER-AGENT ML PROFILES ────────────────────────────────────────────
-- Stores the full ML profile as JSONB (tool distributions, Markov chain,
-- hourly probability, velocity percentiles, tool novelty counts)
CREATE TABLE IF NOT EXISTS agent_ml_profiles (
  agent_id      TEXT NOT NULL,
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  profile_json  JSONB NOT NULL,
  built_at      TIMESTAMPTZ DEFAULT NOW(),
  sample_size   INTEGER DEFAULT 0,
  PRIMARY KEY (agent_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_ml_profiles_tenant ON agent_ml_profiles(tenant_id, built_at DESC);

-- ── ANOMALY EVENTS LOG ────────────────────────────────────────────────
-- Every flagged/blocked anomaly event stored for history + ML feedback
CREATE TABLE IF NOT EXISTS anomaly_events (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id),
  agent_id         TEXT NOT NULL,
  tool_name        TEXT NOT NULL,
  score            INTEGER NOT NULL,
  confidence       TEXT CHECK (confidence IN ('low','medium','high')),
  action           TEXT NOT NULL CHECK (action IN ('allow','flag','block')),
  reasons_json     JSONB DEFAULT '[]',
  profile_age      TEXT,
  arg_length       INTEGER,
  call_hour        INTEGER,
  prev_tool        TEXT,
  human_feedback   BOOLEAN,          -- TRUE=correct, FALSE=false positive
  feedback_note    TEXT,
  feedback_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_tenant ON anomaly_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_agent  ON anomaly_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_score  ON anomaly_events(tenant_id, score DESC) WHERE score >= 35;

-- ── ANOMALY FEEDBACK LOG ──────────────────────────────────────────────
-- Track false positives per agent to adjust profile sensitivity
CREATE TABLE IF NOT EXISTS anomaly_feedback_log (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL REFERENCES tenants(id),
  event_id          UUID REFERENCES anomaly_events(id),
  was_false_positive BOOLEAN NOT NULL,
  note              TEXT,
  created_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_anomaly_feedback_tenant ON anomaly_feedback_log(tenant_id, created_at DESC);

-- ── EXTEND agent_baselines FOR BACKWARD COMPAT ───────────────────────
-- Keep the old z-score table as fallback while ML profiles are building
-- Old table: agent_baselines (already exists from migration 002)
-- New table: agent_ml_profiles (above)
-- The ML engine checks agent_ml_profiles first, falls back to z-score

-- Add transition_count to existing baselines for reference
ALTER TABLE agent_baselines
  ADD COLUMN IF NOT EXISTS ml_ready BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS ml_profile_size INTEGER DEFAULT 0;

-- ── ADD prev_tool COLUMN TO AUDIT_LOG FOR MARKOV CHAIN ───────────────
-- The Markov chain needs to know which tool preceded the current one.
-- We compute this in-query with LAG() so no column change needed,
-- but adding a materialized column speeds up profile building significantly.
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS prev_tool TEXT;

-- Backfill prev_tool for existing data (run once, may take a minute on large datasets)
-- UPDATE audit_log al
-- SET prev_tool = (
--   SELECT tool_name FROM audit_log al2
--   WHERE al2.agent_id = al.agent_id
--     AND al2.tenant_id = al.tenant_id
--     AND al2.created_at < al.created_at
--   ORDER BY al2.created_at DESC
--   LIMIT 1
-- )
-- WHERE prev_tool IS NULL;
-- Note: commented out — run manually on production as it's a heavy update.

-- Index for fast Markov chain queries
CREATE INDEX IF NOT EXISTS idx_audit_agent_time_tool ON audit_log(agent_id, tenant_id, created_at DESC, tool_name);

COMMIT;
