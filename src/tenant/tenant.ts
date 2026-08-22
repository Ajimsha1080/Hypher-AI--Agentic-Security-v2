/**
 * Multi-Tenant Support — Tenant isolation, billing, and management
 * One deployment serves unlimited tenants with strict data isolation.
 * Each tenant gets: isolated policies, audit logs, alert rules, and usage metering.
 */

import { FastifyInstance, FastifyRequest } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import { decryptValue } from '../security/secrets';

export interface Tenant {
  id: string;
  name: string;
  plan: 'starter' | 'growth' | 'enterprise';
  apiCallsLimit: number;
  agentsLimit: number;
  usageThisMonth: number;
  active: boolean;
  createdAt: Date;
  billingEmail: string;
}

export interface TenantContext {
  id: string;
  name: string;
  plan: Tenant['plan'];
  apiCallsLimit: number;
  agentsLimit: number;
  metadata?: any;
}

// ── Tenant resolution middleware ───────────────────────────────────────

export async function resolveTenant(
  request: FastifyRequest,
  db: Pool,
  redis: Redis
): Promise<TenantContext> {
  const tenantId =
    (request.headers['x-tenant-id'] as string) ||
    ((request as any).authenticatedTenantId as string | undefined) ||
    extractTenantFromSubdomain(request.headers.host as string);

  if (!tenantId) throw new Error('Missing tenant ID — pass X-Tenant-ID header');

  const cacheKey = `tenant:${tenantId}`;
  const cached = await redis.get(cacheKey);
  if (cached) return JSON.parse(cached);

  const r = await db.query(
    `SELECT id, name, plan, api_calls_limit, agents_limit, metadata FROM tenants WHERE id=$1 AND active=true`,
    [tenantId]
  );

  if (!r.rows.length) throw new Error(`Tenant ${tenantId} not found or inactive`);

  const tenant: TenantContext = r.rows[0];
  if (tenant.metadata && tenant.metadata.mcpProxyAuthToken) {
    tenant.metadata.mcpProxyAuthToken = decryptValue(tenant.metadata.mcpProxyAuthToken);
  }
  await redis.setex(cacheKey, 60, JSON.stringify(tenant)); // 1-min cache
  return tenant;
}

function extractTenantFromSubdomain(host: string): string | null {
  if (!host) return null;
  const parts = host.split('.');
  if (parts.length >= 3) return parts[0]; // tenant-id.gateway.example.com
  return null;
}

// ── Usage metering ─────────────────────────────────────────────────────

export async function checkAndMeterUsage(tenantId: string, db: Pool, redis: Redis): Promise<void> {
  const monthKey = `usage:${tenantId}:${new Date().toISOString().slice(0, 7)}`; // YYYY-MM

  const usage = await redis.incr(monthKey);
  if (usage === 1) await redis.expire(monthKey, 32 * 24 * 3600); // expire after ~32 days

  const tenant = await db.query(
    `SELECT api_calls_limit, plan FROM tenants WHERE id=$1`,
    [tenantId]
  );

  if (!tenant.rows.length) return;

  const { api_calls_limit, plan } = tenant.rows[0];

  if (usage > api_calls_limit) {
    // Soft limit — warn; hard limit — block
    if (plan === 'starter') {
      throw new Error('Monthly API call limit exceeded. Upgrade your plan.');
    }
    // enterprise/growth: log overage for billing, don't block
    await db.query(
      `INSERT INTO usage_overage (tenant_id, month, overage_calls, recorded_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (tenant_id, month) DO UPDATE SET overage_calls = $3`,
      [tenantId, new Date().toISOString().slice(0, 7), usage - api_calls_limit]
    );
  }

  // Persist to DB every 100 calls for accurate billing
  if (usage % 100 === 0) {
    await db.query(
      `INSERT INTO usage_metrics (tenant_id, month, api_calls)
       VALUES ($1, $2, $3)
       ON CONFLICT (tenant_id, month) DO UPDATE SET api_calls = $3, updated_at = NOW()`,
      [tenantId, new Date().toISOString().slice(0, 7), usage]
    );
  }
}

// ── Tenant management API ──────────────────────────────────────────────

export async function tenantPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;

  // Create tenant
  fastify.post('/api/tenants', async (req: any, reply) => {
    const { name, plan, billingEmail } = req.body;
    const limits = PLAN_LIMITS[plan as keyof typeof PLAN_LIMITS] || PLAN_LIMITS.starter;
    const id = crypto.randomUUID();

    const apiKey = generateApiKey();
    const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

    await db.query(
      `INSERT INTO tenants (id, name, plan, billing_email, api_calls_limit, agents_limit, api_key_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, name, plan, billingEmail, limits.apiCalls, limits.agents, apiKeyHash]
    );

    // Create default alert rules for new tenant
    await createDefaultAlertRules(id, db);

    return { tenantId: id, apiKey, plan, limits };
  });

  // Get tenant usage
  fastify.get('/api/tenants/:id/usage', async (req: any) => {
    const monthKey = `usage:${req.params.id}:${new Date().toISOString().slice(0, 7)}`;
    const currentUsage = parseInt(await redis.get(monthKey) || '0', 10);

    const tenant = await db.query(
      `SELECT plan, api_calls_limit, agents_limit FROM tenants WHERE id=$1`,
      [req.params.id]
    );

    const agentCount = await db.query(
      `SELECT COUNT(DISTINCT agent_id) as cnt FROM audit_log
       WHERE tenant_id=$1 AND created_at > DATE_TRUNC('month', NOW())`,
      [req.params.id]
    );

    return {
      plan: tenant.rows[0]?.plan,
      apiCalls: { used: currentUsage, limit: tenant.rows[0]?.api_calls_limit },
      agents: { used: parseInt(agentCount.rows[0]?.cnt || '0', 10), limit: tenant.rows[0]?.agents_limit },
      month: new Date().toISOString().slice(0, 7),
    };
  });

  // Upgrade plan
  fastify.put('/api/tenants/:id/plan', async (req: any) => {
    const { plan } = req.body;
    const limits = PLAN_LIMITS[plan as keyof typeof PLAN_LIMITS];
    if (!limits) return { error: 'Invalid plan' };

    await db.query(
      `UPDATE tenants SET plan=$1, api_calls_limit=$2, agents_limit=$3 WHERE id=$4`,
      [plan, limits.apiCalls, limits.agents, req.params.id]
    );

    await redis.del(`tenant:${req.params.id}`);
    return { updated: true, newLimits: limits };
  });

  // Rotate API key
  fastify.post('/api/tenants/:id/rotate-key', async (req: any) => {
    const newKey = generateApiKey();
    const hash = crypto.createHash('sha256').update(newKey).digest('hex');
    await db.query(`UPDATE tenants SET api_key_hash=$1 WHERE id=$2`, [hash, req.params.id]);
    await redis.del(`tenant:${req.params.id}`);
    return { apiKey: newKey };
  });

  // Tenant audit log (isolated)
  fastify.get('/api/tenants/:id/audit', async (req: any) => {
    const r = await db.query(
      `SELECT * FROM audit_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`,
      [req.params.id]
    );
    return { logs: r.rows };
  });
}

// ── Plan limits ────────────────────────────────────────────────────────

export const PLAN_LIMITS = {
  starter:    { apiCalls: 10_000,   agents: 5,    price: 49  },
  growth:     { apiCalls: 100_000,  agents: 25,   price: 199 },
  enterprise: { apiCalls: 1_000_000, agents: 200, price: 999 },
};

function generateApiKey(): string {
  return 'mcpsg_' + crypto.randomBytes(32).toString('hex');
}

async function createDefaultAlertRules(tenantId: string, db: Pool): Promise<void> {
  const defaults = [
    { name: 'High denial rate', eventType: 'denial_rate_spike', threshold: 20, windowSeconds: 300, severity: 'high', channels: ['slack'], cooldown: 600 },
    { name: 'Injection attempt', eventType: 'injection_detected', threshold: 1, windowSeconds: 60, severity: 'critical', channels: ['slack', 'pagerduty'], cooldown: 60 },
    { name: 'Auth failures', eventType: 'auth_failure', threshold: 10, windowSeconds: 300, severity: 'medium', channels: ['slack'], cooldown: 300 },
  ];

  for (const rule of defaults) {
    await db.query(
      `INSERT INTO alert_rules (tenant_id, name, event_type, threshold, window_seconds, severity, channels, cooldown_seconds)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
      [tenantId, rule.name, rule.eventType, rule.threshold, rule.windowSeconds, rule.severity, JSON.stringify(rule.channels), rule.cooldown]
    );
  }
}
