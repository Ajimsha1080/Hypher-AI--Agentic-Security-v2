-- Migration 015: UCP (Universal Commerce Protocol) Shield
-- Adds spending limits and cart state tracking tables for AI shopping agents.

BEGIN;

CREATE TABLE IF NOT EXISTS ucp_spending_limits (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL,
  max_per_transaction NUMERIC(12, 2) NOT NULL DEFAULT 50.00,
  daily_limit NUMERIC(12, 2) NOT NULL DEFAULT 200.00,
  current_daily_spend NUMERIC(12, 2) NOT NULL DEFAULT 0.00,
  last_reset_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS ucp_cart_sessions (
  session_id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id TEXT NOT NULL,
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ucp_cart_sessions_tenant_agent
  ON ucp_cart_sessions (tenant_id, agent_id);

COMMIT;
