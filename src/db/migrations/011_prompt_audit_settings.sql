-- Enterprise-safe prompt and command logging controls.

BEGIN;

CREATE TABLE IF NOT EXISTS prompt_audit_settings (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
  mode TEXT NOT NULL DEFAULT 'SUMMARY_ONLY'
    CHECK (mode IN ('OFF', 'SUMMARY_ONLY', 'FULL_REDACTED', 'FULL_RAW')),
  retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 365),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO prompt_audit_settings (tenant_id, mode, retention_days)
SELECT id, 'SUMMARY_ONLY', 30 FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
