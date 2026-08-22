/**
 * F11 — Per-Tool Rate Limiting
 *
 * Rate limits applied per-tool (not just per-agent/plan).
 * Dangerous tools (run_command, delete_file) get independent caps
 * regardless of the agent's plan-level rate limit.
 *
 * Routes:
 *   GET  /api/tool-rate-limits          List all limits for tenant
 *   POST /api/tool-rate-limits          Create/update a limit
 *   DEL  /api/tool-rate-limits/:id      Remove a limit
 *   GET  /api/tool-rate-limits/usage    Current usage stats
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';

export interface ToolRateLimitResult {
  allowed: boolean;
  reason?: string;
  currentCount?: number;
  limit?: number;
  windowSeconds?: number;
  retryAfterSeconds?: number;
}

// ── Core check (called from /mcp pipeline) ────────────────────────────

export async function checkToolRateLimit(
  tenantId: string,
  agentId: string,
  toolName: string,
  db: Pool,
  redis: Redis
): Promise<ToolRateLimitResult> {
  // Check tenant-specific limit first, then global default
  const ruleRow = await db.query(
    `SELECT id, max_calls, window_seconds, action
     FROM tool_rate_limits
     WHERE tool_name=$1 AND active=TRUE
       AND (tenant_id=$2 OR tenant_id IS NULL)
     ORDER BY tenant_id NULLS LAST LIMIT 1`,
    [toolName, tenantId]
  ).then(r => r.rows[0]).catch(() => null);

  if (!ruleRow) return { allowed: true }; // no rule = allow

  const key = `tool_rl:${tenantId}:${agentId}:${toolName}`;
  const current = await redis.incr(key);

  if (current === 1) {
    // First call in window — set expiry
    await redis.expire(key, ruleRow.window_seconds);
  }

  if (current > ruleRow.max_calls) {
    const ttl = await redis.ttl(key);
    return {
      allowed: false,
      reason: `tool_rate_limit:${toolName}(${current}>${ruleRow.max_calls}/${ruleRow.window_seconds}s)`,
      currentCount: current,
      limit: ruleRow.max_calls,
      windowSeconds: ruleRow.window_seconds,
      retryAfterSeconds: ttl > 0 ? ttl : ruleRow.window_seconds,
    };
  }

  return {
    allowed: true,
    currentCount: current,
    limit: ruleRow.max_calls,
    windowSeconds: ruleRow.window_seconds,
  };
}

// ── Fastify plugin ────────────────────────────────────────────────────

async function hasGrowthOrEnterprisePlan(req: any, db: Pool): Promise<boolean> {
  if (['growth', 'enterprise'].includes(req.tenant?.plan)) return true;
  const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
  if (!tenantId) return false;
  const r = await db.query(`SELECT plan FROM tenants WHERE id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [] as any[] }));
  return ['growth', 'enterprise'].includes(r.rows[0]?.plan);
}
export async function toolRateLimitPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;

  // GET /api/tool-rate-limits
  fastify.get('/api/tool-rate-limits', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Per-tool rate limiting requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, tool_name, max_calls, window_seconds, action, active, created_at
       FROM tool_rate_limits
       WHERE (tenant_id=$1 OR tenant_id IS NULL) AND active=TRUE
       ORDER BY tool_name`,
      [tenantId]
    );
    return { limits: r.rows };
  });

  // POST /api/tool-rate-limits
  fastify.post('/api/tool-rate-limits', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Per-tool rate limiting requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { toolName, maxCalls, windowSeconds = 60, action = 'block' } = req.body as any;
    if (!toolName || !maxCalls) {
      return reply.code(400).send({ error: 'toolName and maxCalls are required' });
    }
    if (!['block', 'throttle', 'require_hitl'].includes(action)) {
      return reply.code(400).send({ error: 'action must be: block | throttle | require_hitl' });
    }
    if (maxCalls < 1 || windowSeconds < 1) {
      return reply.code(400).send({ error: 'maxCalls and windowSeconds must be positive integers' });
    }

    const r = await db.query(
      `INSERT INTO tool_rate_limits (tenant_id, tool_name, max_calls, window_seconds, action)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (tenant_id, tool_name) DO UPDATE
         SET max_calls=$3, window_seconds=$4, action=$5, active=TRUE
       RETURNING *`,
      [tenantId, toolName, maxCalls, windowSeconds, action]
    );
    return { created: r.rows[0] };
  });

  // DELETE /api/tool-rate-limits/:id
  fastify.delete('/api/tool-rate-limits/:id', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Per-tool rate limiting requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      'UPDATE tool_rate_limits SET active=FALSE WHERE id=$1 AND tenant_id=$2',
      [(req.params as any).id, tenantId]
    );
    return { removed: true };
  });

  // GET /api/tool-rate-limits/usage — live usage from Redis
  fastify.get('/api/tool-rate-limits/usage', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Per-tool rate limiting requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const limits = await db.query(
      `SELECT tool_name, max_calls, window_seconds FROM tool_rate_limits
       WHERE tenant_id=$1 AND active=TRUE`,
      [tenantId]
    );

    const usage = await Promise.all(
      limits.rows.map(async (row: any) => {
        // Get all agent keys for this tool
        const pattern = `tool_rl:${tenantId}:*:${row.tool_name}`;
        const keys = await redis.keys(pattern).catch(() => []);
        const counts = keys.length
          ? await redis.mget(...keys).then(vals => vals.map(v => parseInt(v || '0', 10)))
          : [];
        return {
          toolName: row.tool_name,
          limit: row.max_calls,
          windowSeconds: row.window_seconds,
          activeAgentCount: keys.length,
          totalCallsInWindow: counts.reduce((a, b) => a + b, 0),
          agentBreakdown: keys.map((k, i) => ({
            agentId: k.split(':')[2],
            calls: counts[i],
          })),
        };
      })
    );
    return { usage };
  });
}
