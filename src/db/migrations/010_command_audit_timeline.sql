-- Command-to-tool audit timeline
-- Captures user/session context that explains why an MCP tool call happened.

BEGIN;

ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS user_id TEXT,
  ADD COLUMN IF NOT EXISTS session_id TEXT,
  ADD COLUMN IF NOT EXISTS conversation_id TEXT,
  ADD COLUMN IF NOT EXISTS request_id TEXT,
  ADD COLUMN IF NOT EXISTS user_command TEXT,
  ADD COLUMN IF NOT EXISTS tool_arguments JSONB,
  ADD COLUMN IF NOT EXISTS response_summary TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_session_time ON audit_log(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_conversation_time ON audit_log(conversation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_log(user_id, created_at DESC);

COMMIT;
