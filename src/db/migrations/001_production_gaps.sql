-- Production gaps migration — run after schema.sql and audit/schema.sql
-- Command: psql $DATABASE_URL -f src/db/migrations/001_production_gaps.sql

BEGIN;

-- 1. OIDC identity mappings (OAuth 2.1)
CREATE TABLE IF NOT EXISTS agent_oidc_mappings (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id   TEXT NOT NULL,
  provider   TEXT NOT NULL,
  oidc_sub   TEXT NOT NULL,
  email      TEXT,
  scopes     TEXT[] DEFAULT '{}',
  active     BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (provider, oidc_sub)
);
CREATE INDEX IF NOT EXISTS idx_oidc_sub ON agent_oidc_mappings(oidc_sub, provider);

-- 2. Tool argument allowlist rules
CREATE TABLE IF NOT EXISTS tool_arg_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_name       TEXT NOT NULL,
  arg_key         TEXT NOT NULL,
  allowed_pattern TEXT,
  max_length      INTEGER DEFAULT 4096,
  required        BOOLEAN DEFAULT FALSE,
  active          BOOLEAN DEFAULT TRUE,
  description     TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tool_name, arg_key)
);
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints 
    WHERE table_name='tool_arg_rules' AND constraint_type='UNIQUE'
  ) THEN
    ALTER TABLE tool_arg_rules ADD CONSTRAINT tool_arg_rules_tool_name_arg_key_key UNIQUE (tool_name, arg_key);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_tool_arg_rules ON tool_arg_rules(tool_name) WHERE active=TRUE;

-- Seed default rules
INSERT INTO tool_arg_rules (tool_name, arg_key, allowed_pattern, max_length, required, description) VALUES
  ('query_database','query',   '^[^;|&`$(){}[\]<>\\]+$', 2048, TRUE, 'No shell metacharacters'),
  ('query_database','database','^[a-zA-Z0-9_-]{1,64}$',  64,   TRUE, 'Alphanumeric DB name only'),
  ('read_file',     'path',    '^[^/\\][^\0]*$',          512,  TRUE, 'No absolute paths'),
  ('write_file',    'path',    '^[^/\\][^\0]*$',          512,  TRUE, 'No absolute paths'),
  ('write_file',    'content', NULL,                       65536,TRUE, 'Max 64KB'),
  ('http_request',  'url',     '^https?://((?!localhost|127\.|10\.|192\.168\.|0\.0\.0\.0).)+', 1024, TRUE, 'No internal targets'),
  ('http_request',  'method',  '^(GET|POST|PUT|PATCH|DELETE)$', 10, TRUE, 'Allowlisted methods only')
ON CONFLICT (tool_name, arg_key) DO NOTHING;

-- 3. Add columns to audit_log if missing
ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS execution_time_ms  INTEGER,
  ADD COLUMN IF NOT EXISTS inspection_result  JSONB,
  ADD COLUMN IF NOT EXISTS auth_provider      TEXT DEFAULT 'bearer';

-- 4. Performance indexes
CREATE INDEX IF NOT EXISTS idx_audit_agent_time  ON audit_log(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_decision    ON audit_log(decision, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tool_time   ON audit_log(tool_name, created_at DESC);

-- 5. Audit log rotation (run via cron or pg_cron)
CREATE OR REPLACE FUNCTION rotate_audit_logs() RETURNS void AS $$
BEGIN
  DELETE FROM audit_log WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

COMMIT;
