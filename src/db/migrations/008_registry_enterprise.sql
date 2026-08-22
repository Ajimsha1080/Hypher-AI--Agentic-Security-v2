-- Migration 008: Enterprise Tool Registry metadata, scope, schema, and history

BEGIN;

ALTER TABLE registry_servers
  ADD COLUMN IF NOT EXISTS owner_email TEXT,
  ADD COLUMN IF NOT EXISTS owner_team TEXT,
  ADD COLUMN IF NOT EXISTS allowed_tenants JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS allowed_agents JSONB DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS schema_json JSONB DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS schema_validation TEXT DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS last_reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_reviewed_by TEXT,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

CREATE TABLE IF NOT EXISTS registry_trust_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id UUID NOT NULL REFERENCES registry_servers(id),
  previous_trust_level TEXT,
  new_trust_level TEXT,
  previous_trust_score INTEGER,
  new_trust_score INTEGER,
  changed_by TEXT,
  reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_registry_history_server ON registry_trust_history(server_id, created_at DESC);

COMMIT;
