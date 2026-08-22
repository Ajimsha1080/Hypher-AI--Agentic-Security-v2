-- Migration 016: UCP Connections — External Commerce Platform Endpoints
-- Manages separate UCP connection profiles for commerce providers.

BEGIN;

CREATE TABLE IF NOT EXISTS ucp_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'custom',      -- shopify | stripe | woocommerce | amazon | custom
  endpoint_url TEXT NOT NULL,
  api_key_encrypted TEXT,                        -- encrypted API key / token
  auth_type TEXT NOT NULL DEFAULT 'bearer',      -- bearer | api_key | oauth2 | hmac
  webhook_secret TEXT,
  status TEXT NOT NULL DEFAULT 'inactive',       -- active | inactive | error | testing
  last_health_check TIMESTAMP WITH TIME ZONE,
  last_health_status TEXT DEFAULT 'unknown',     -- healthy | degraded | down | unknown
  health_latency_ms INTEGER,
  tls_verified BOOLEAN NOT NULL DEFAULT false,
  allowed_methods TEXT[] DEFAULT ARRAY['cart/add','cart/update','checkout','payment','identity','loyalty'],
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_ucp_connections_tenant
  ON ucp_connections (tenant_id);

CREATE INDEX IF NOT EXISTS idx_ucp_connections_status
  ON ucp_connections (tenant_id, status);

-- Audit log for connection events
CREATE TABLE IF NOT EXISTS ucp_connection_events (
  id BIGSERIAL PRIMARY KEY,
  connection_id UUID REFERENCES ucp_connections(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  event_type TEXT NOT NULL,        -- created | updated | activated | deactivated | health_check | test_success | test_fail | error
  details JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ucp_conn_events_conn
  ON ucp_connection_events (connection_id, created_at DESC);

COMMIT;
