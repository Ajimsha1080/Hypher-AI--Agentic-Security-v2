-- MCP Security Gateway — Base Schema
-- This is the initial schema. Migrations 001-005 build on top of this.
-- Run: psql $DATABASE_URL -f src/db/schema.sql

BEGIN;

-- ── POLICIES (core RBAC) ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policies (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    TEXT NOT NULL,
  tool_name   TEXT NOT NULL,
  allowed_tools TEXT[],
  action      TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow','deny')),
  priority    INTEGER NOT NULL DEFAULT 100,
  active      BOOLEAN DEFAULT TRUE,
  description TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_policies_agent ON policies(agent_id, active);
CREATE INDEX IF NOT EXISTS idx_policies_tool ON policies(tool_name, active);
CREATE INDEX IF NOT EXISTS idx_policies_allowed_tools ON policies USING GIN (allowed_tools);

-- Seed: default deny-all policy (fail-closed baseline)
INSERT INTO policies (agent_id, tool_name, action, priority, description)
VALUES ('*', '*', 'deny', 0, 'Default deny-all — override with explicit allow policies')
ON CONFLICT DO NOTHING;

-- ── AGENT TOKENS ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_tokens (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    TEXT NOT NULL UNIQUE,
  token_hash  TEXT NOT NULL,
  description TEXT,
  active      BOOLEAN DEFAULT TRUE,
  last_seen   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON agent_tokens(token_hash) WHERE active=TRUE;
CREATE INDEX IF NOT EXISTS idx_tokens_agent ON agent_tokens(agent_id) WHERE active=TRUE;

-- ── AUDIT LOG ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id         TEXT NOT NULL,
  tool_name        TEXT NOT NULL,
  decision         TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY')),
  reason           TEXT,
  request_hash     TEXT,
  args_length      INTEGER DEFAULT 0,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- ── MCP SERVER REGISTRY ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mcp_servers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL UNIQUE,
  url           TEXT NOT NULL,
  description   TEXT,
  trust_level   TEXT NOT NULL DEFAULT 'unknown' CHECK (trust_level IN ('trusted','suspicious','blocked','unknown')),
  trust_score   INTEGER NOT NULL DEFAULT 50 CHECK (trust_score >= 0 AND trust_score <= 100),
  verified      BOOLEAN DEFAULT FALSE,
  report_count  INTEGER DEFAULT 0,
  metadata      JSONB DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── ANOMALY BASELINES ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS anomaly_baselines (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    TEXT NOT NULL,
  tool_name   TEXT NOT NULL,
  mean_calls  FLOAT NOT NULL DEFAULT 0,
  std_calls   FLOAT NOT NULL DEFAULT 0,
  mean_args   FLOAT NOT NULL DEFAULT 0,
  std_args    FLOAT NOT NULL DEFAULT 0,
  sample_size INTEGER NOT NULL DEFAULT 0,
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (agent_id, tool_name)
);

COMMIT;
