-- Tenant-scoped argument rules for policy assistant generated policies.
-- Keeps one global default rule plus optional tenant-specific overrides.

ALTER TABLE tool_arg_rules
  ADD COLUMN IF NOT EXISTS tenant_id UUID;

ALTER TABLE tool_arg_rules
  DROP CONSTRAINT IF EXISTS tool_arg_rules_tool_name_arg_key_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_arg_rules_global_unique
  ON tool_arg_rules(tool_name, arg_key)
  WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_arg_rules_tenant_unique
  ON tool_arg_rules(tool_name, arg_key, tenant_id)
  WHERE tenant_id IS NOT NULL;
