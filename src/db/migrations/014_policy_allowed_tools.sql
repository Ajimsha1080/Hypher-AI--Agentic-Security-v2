-- Migration 014: Policy schema compatibility for per-agent allowed tool arrays.
-- Keeps legacy tool_name/action policies working while enabling newer allowed_tools paths.

BEGIN;

ALTER TABLE policies
  ADD COLUMN IF NOT EXISTS allowed_tools TEXT[];

CREATE INDEX IF NOT EXISTS idx_policies_allowed_tools
  ON policies USING GIN (allowed_tools);

COMMIT;
