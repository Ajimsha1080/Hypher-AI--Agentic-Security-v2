-- Migration 009: F11-F20 feature tables
-- Per-tool rate limits, geo-blocking, anomaly feedback API,
-- policy dry-run, audit S3 export, Slack HITL, agent graph,
-- OTel tracing, webhook auto-retry

BEGIN;

-- ── F11: Per-Tool Rate Limits ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tool_rate_limits (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID REFERENCES tenants(id),   -- NULL = global default
  tool_name       TEXT NOT NULL,
  max_calls       INTEGER NOT NULL,
  window_seconds  INTEGER NOT NULL DEFAULT 60,
  action          TEXT NOT NULL DEFAULT 'block'
                  CHECK (action IN ('block','throttle','require_hitl')),
  active          BOOLEAN DEFAULT TRUE,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, tool_name)
);
CREATE INDEX IF NOT EXISTS idx_tool_rate_limits_lookup
  ON tool_rate_limits(tool_name, active) WHERE active=TRUE;

-- ── F12: Geo-Blocking ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant_geo_blocks (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES tenants(id),
  country_code CHAR(2) NOT NULL,   -- ISO 3166-1 alpha-2
  mode        TEXT NOT NULL DEFAULT 'block'
              CHECK (mode IN ('block','allow')),  -- block=denylist, allow=allowlist
  description TEXT,
  active      BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, country_code)
);
CREATE INDEX IF NOT EXISTS idx_geo_blocks_tenant ON tenant_geo_blocks(tenant_id) WHERE active=TRUE;

-- Store country lookups cache (avoid repeated GeoIP calls)
CREATE TABLE IF NOT EXISTS ip_country_cache (
  ip_hash     TEXT PRIMARY KEY,   -- SHA-256 of IP for privacy
  country_code CHAR(2),
  cached_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── F13: Prompt Injection Debug Log ───────────────────────────────────
CREATE TABLE IF NOT EXISTS injection_debug_log (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID REFERENCES tenants(id),
  agent_id      TEXT,
  tool_name     TEXT,
  pattern_name  TEXT,     -- which regex fired
  arg_key       TEXT,     -- which argument contained the injection
  flagged_text  TEXT,     -- redacted snippet
  full_args_hash TEXT,    -- SHA-256 of full args for correlation
  created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_injection_debug_tenant ON injection_debug_log(tenant_id, created_at DESC);

-- ── F14: Anomaly Feedback (table already exists in 008, add API tracking)
ALTER TABLE anomaly_events
  ADD COLUMN IF NOT EXISTS feedback_note TEXT,
  ADD COLUMN IF NOT EXISTS reviewed_by TEXT;

-- ── F15: Policy Dry-Run Results ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_dry_run_results (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL REFERENCES tenants(id),
  run_by         TEXT,
  sample_size    INTEGER,
  would_allow    INTEGER DEFAULT 0,
  would_deny     INTEGER DEFAULT 0,
  delta_vs_live  JSONB DEFAULT '{}',  -- tools whose outcome would change
  policy_snapshot JSONB NOT NULL DEFAULT '{}',
  created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- ── F16: Audit Log Export Jobs ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_export_jobs (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  destination  TEXT NOT NULL,    -- 's3://bucket/path' or 'gs://bucket/path'
  status       TEXT DEFAULT 'pending'
               CHECK (status IN ('pending','running','done','failed')),
  rows_exported INTEGER,
  period_start TIMESTAMPTZ,
  period_end   TIMESTAMPTZ,
  error_msg    TEXT,
  started_at   TIMESTAMPTZ,
  finished_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── F17: Slack HITL Bot Config ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS slack_hitl_config (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id) UNIQUE,
  bot_token    TEXT NOT NULL,          -- xoxb-...
  channel_id   TEXT NOT NULL,          -- C01XXXXXXX
  signing_secret TEXT NOT NULL,        -- for verifying Slack payloads
  active       BOOLEAN DEFAULT TRUE,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Track Slack interactive message state
CREATE TABLE IF NOT EXISTS slack_hitl_messages (
  approval_id  TEXT PRIMARY KEY REFERENCES hitl_approvals(approval_id),
  slack_ts     TEXT NOT NULL,    -- Slack message timestamp for updates
  channel_id   TEXT NOT NULL,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── F18: Agent Dependency Graph ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_tool_cooccurrence (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL REFERENCES tenants(id),
  agent_id     TEXT NOT NULL,
  tool_a       TEXT NOT NULL,
  tool_b       TEXT NOT NULL,
  co_count     INTEGER DEFAULT 1,   -- how often called together (same session/hour)
  last_seen    TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, agent_id, tool_a, tool_b)
);
CREATE INDEX IF NOT EXISTS idx_cooccurrence_tenant ON agent_tool_cooccurrence(tenant_id, agent_id);

-- ── F19: OpenTelemetry Trace Spans ────────────────────────────────────
CREATE TABLE IF NOT EXISTS otel_traces (
  trace_id     TEXT NOT NULL,
  span_id      TEXT NOT NULL,
  parent_span  TEXT,
  tenant_id    UUID REFERENCES tenants(id),
  operation    TEXT NOT NULL,
  start_time   TIMESTAMPTZ NOT NULL,
  end_time     TIMESTAMPTZ,
  duration_ms  INTEGER,
  status       TEXT CHECK (status IN ('ok','error','unset')),
  attributes   JSONB DEFAULT '{}',
  PRIMARY KEY (trace_id, span_id)
);
CREATE INDEX IF NOT EXISTS idx_otel_traces_tenant ON otel_traces(tenant_id, start_time DESC);

-- ── F20: Webhook Auto-Retry Schedule ─────────────────────────────────
ALTER TABLE webhook_deliveries
  ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS max_retries    INTEGER DEFAULT 5,
  ADD COLUMN IF NOT EXISTS dead_lettered  BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS rule_name      TEXT,
  ADD COLUMN IF NOT EXISTS destination_type TEXT,
  ADD COLUMN IF NOT EXISTS destination_url  TEXT,
  ADD COLUMN IF NOT EXISTS payload_json     JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS retry_count      INTEGER DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_webhook_retry_queue
  ON webhook_deliveries(next_retry_at)
  WHERE delivered=FALSE AND dead_lettered=FALSE AND next_retry_at IS NOT NULL;

COMMIT;
