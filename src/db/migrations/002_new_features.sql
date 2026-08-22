-- Migration 002: All new features — webhooks, SDK, registry, tenants, anomaly, sandbox
-- Run: psql $DATABASE_URL -f src/db/migrations/002_new_features.sql

BEGIN;

-- ── TENANTS ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  plan            TEXT NOT NULL DEFAULT 'starter' CHECK (plan IN ('starter','growth','enterprise')),
  billing_email   TEXT NOT NULL,
  api_key_hash    TEXT NOT NULL,
  api_calls_limit INTEGER NOT NULL DEFAULT 10000,
  agents_limit    INTEGER NOT NULL DEFAULT 5,
  active          BOOLEAN DEFAULT TRUE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Add tenant_id to all existing tables
ALTER TABLE audit_log        ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE policies         ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE agent_tokens     ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
ALTER TABLE tool_arg_rules   ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE agent_oidc_mappings ADD COLUMN IF NOT EXISTS tenant_id UUID;

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policies_tenant   ON policies(tenant_id, agent_id);

-- Usage metering
CREATE TABLE IF NOT EXISTS usage_metrics (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  month       TEXT NOT NULL,
  api_calls   INTEGER DEFAULT 0,
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, month)
);

CREATE TABLE IF NOT EXISTS usage_overage (
  tenant_id       UUID NOT NULL REFERENCES tenants(id),
  month           TEXT NOT NULL,
  overage_calls   INTEGER DEFAULT 0,
  PRIMARY KEY (tenant_id, month)
);

-- ── ALERT RULES & LOG ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alert_rules (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL REFERENCES tenants(id),
  name             TEXT NOT NULL,
  event_type       TEXT NOT NULL,
  threshold        NUMERIC NOT NULL,
  window_seconds   INTEGER NOT NULL DEFAULT 300,
  severity         TEXT NOT NULL DEFAULT 'medium',
  channels         JSONB NOT NULL DEFAULT '[]',
  cooldown_seconds INTEGER NOT NULL DEFAULT 300,
  active           BOOLEAN DEFAULT TRUE,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  rule_id     UUID,
  event_type  TEXT NOT NULL,
  severity    TEXT NOT NULL,
  message     TEXT NOT NULL,
  details     JSONB,
  sent_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_log_tenant ON alert_log(tenant_id, sent_at DESC);

CREATE TABLE IF NOT EXISTS alert_channel_configs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  channel_type TEXT NOT NULL,
  config       JSONB NOT NULL,
  active       BOOLEAN DEFAULT TRUE,
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, channel_type)
);

-- ── TOOL REGISTRY ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS registry_servers (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name             TEXT NOT NULL UNIQUE,
  version          TEXT NOT NULL DEFAULT '0.0.0',
  description      TEXT,
  author           TEXT,
  repo_url         TEXT,
  trust_level      TEXT NOT NULL DEFAULT 'unverified' CHECK (trust_level IN ('trusted','unverified','suspicious','blocked')),
  trust_score      INTEGER NOT NULL DEFAULT 50 CHECK (trust_score BETWEEN 0 AND 100),
  total_calls      BIGINT DEFAULT 0,
  denial_rate      NUMERIC(5,2) DEFAULT 0,
  reported_vulns   INTEGER DEFAULT 0,
  community_votes  INTEGER DEFAULT 0,
  last_seen        TIMESTAMPTZ DEFAULT NOW(),
  categories       JSONB DEFAULT '[]',
  tools            JSONB DEFAULT '[]',
  checksum         TEXT,
  verified         BOOLEAN DEFAULT FALSE,
  active           BOOLEAN DEFAULT TRUE,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registry_trust  ON registry_servers(trust_level, trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_registry_name   ON registry_servers(name);

CREATE TABLE IF NOT EXISTS registry_reports (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id    UUID NOT NULL REFERENCES registry_servers(id),
  report_type  TEXT NOT NULL,
  description  TEXT NOT NULL,
  reported_by  TEXT,
  evidence     TEXT,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── ANOMALY DETECTION BASELINES ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_baselines (
  agent_id              TEXT NOT NULL,
  tenant_id             UUID NOT NULL REFERENCES tenants(id),
  avg_calls_per_hour    NUMERIC DEFAULT 0,
  avg_calls_per_minute  NUMERIC DEFAULT 0,
  top_tools             JSONB DEFAULT '[]',
  typical_call_hours    JSONB DEFAULT '[]',
  avg_arg_length        NUMERIC DEFAULT 200,
  std_dev_arg_length    NUMERIC DEFAULT 50,
  baseline_sample_size  INTEGER DEFAULT 0,
  last_updated          TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (agent_id, tenant_id)
);

-- Add args_length column to audit_log for baseline building
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS args_length INTEGER;

-- ── FEDERATED THREAT SIGNALS ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS federated_threat_signals (
  signal_hash         TEXT PRIMARY KEY,
  signal_type         TEXT NOT NULL,
  data                JSONB NOT NULL,
  reported_by_count   INTEGER DEFAULT 1,
  confidence          INTEGER DEFAULT 30,
  active              BOOLEAN DEFAULT TRUE,
  first_seen          TIMESTAMPTZ DEFAULT NOW(),
  last_seen           TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_threat_reports (
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  signal_hash  TEXT NOT NULL REFERENCES federated_threat_signals(signal_hash),
  reported_at  TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (tenant_id, signal_hash)
);

CREATE TABLE IF NOT EXISTS tenant_injection_patterns (
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  pattern     TEXT NOT NULL,
  source      TEXT DEFAULT 'manual',
  confidence  INTEGER DEFAULT 50,
  updated_at  TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (tenant_id, pattern)
);

-- ── SANDBOX POLICIES ─────────────────────────────────────────────────
ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS allowed_capabilities  JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS network_policy        TEXT DEFAULT 'internal_only',
  ADD COLUMN IF NOT EXISTS memory_limit_mb       INTEGER DEFAULT 256,
  ADD COLUMN IF NOT EXISTS cpu_quota             NUMERIC DEFAULT 0.5;

-- ── SEED: Default registry entries ───────────────────────────────────
INSERT INTO registry_servers (name, version, description, author, trust_level, trust_score, verified, categories, tools) VALUES
  ('filesystem-mcp',    '1.0.0', 'File system operations', 'MCP Core',    'trusted',    95, true, '["files"]', '["read_file","write_file","list_dir"]'),
  ('postgres-mcp',      '1.2.0', 'PostgreSQL operations',  'MCP Core',    'trusted',    90, true, '["database"]', '["query","execute"]'),
  ('brave-search-mcp',  '0.8.0', 'Brave web search',       'Brave',       'trusted',    85, true, '["search"]', '["search"]'),
  ('github-mcp',        '1.1.0', 'GitHub API access',      'GitHub',      'trusted',    88, true, '["code","vcs"]', '["create_pr","search_repos"]'),
  ('kali-mcp',          '0.1.0', 'Kali Linux toolset — NO whitelisting', 'Community', 'suspicious', 25, false, '["security","pentest"]', '["run_command","nmap","burpsuite"]')
ON CONFLICT (name) DO NOTHING;

COMMIT;
