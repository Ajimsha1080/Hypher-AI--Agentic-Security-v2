/**
 * Customer Usage Analytics — Know exactly how customers use your product
 *
 * Tracks:
 * - API integration method (SDK vs raw HTTP vs curl)
 * - Which tools are most called per tenant
 * - Latency trends per tenant
 * - Geographic origin of requests
 * - Agent lifecycle (when created, last active, dormant)
 * - Tool call patterns (time of day, frequency)
 * - Integration health (error rates, timeouts)
 * - SDK version being used
 * - Customer journey (free → starter → growth → enterprise signals)
 */

import { FastifyInstance, FastifyRequest } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { ensurePlanLimitSchema, enforceMaxValue, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';

function tenantIdFrom(req: any): string | undefined {
  return req?.tenant?.id || req?.headers?.['x-tenant-id'];
}

function daysFrom(req: any, fallback = 30): number {
  const n = parseInt(String(req.query?.days || fallback), 10);
  return Math.max(1, Math.min(365, Number.isFinite(n) ? n : fallback));
}

function csvEscape(value: any): string {
  const s = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// ── Track integration method from request headers ──────────────────────

export function detectIntegrationMethod(request: FastifyRequest): string {
  const ua = request.headers['user-agent'] || '';
  const sdk = request.headers['x-mcp-sdk-version'] as string;

  if (sdk) return `sdk:${sdk}`;
  if (ua.includes('mcpsg-sdk')) return 'sdk:typescript';
  if (ua.includes('python')) return 'sdk:python';
  if (ua.includes('curl')) return 'manual:curl';
  if (ua.includes('Postman')) return 'manual:postman';
  if (ua.includes('axios') || ua.includes('node-fetch') || ua.includes('got')) return 'http:node';
  if (ua.includes('python-requests') || ua.includes('httpx')) return 'http:python';
  if (ua.includes('Go-http-client')) return 'http:go';
  return 'http:unknown';
}

// ── Track a tool call event ────────────────────────────────────────────

export async function trackUsageEvent(opts: {
  tenantId: string;
  agentId: string;
  toolName: string;
  decision: 'ALLOW' | 'DENY';
  integrationMethod: string;
  latencyMs: number;
  sourceIp?: string;
  sdkVersion?: string;
  db: Pool;
  redis: Redis;
}): Promise<void> {
  const { tenantId, agentId, toolName, decision, integrationMethod, latencyMs, db, redis } = opts;

  // Increment real-time counters in Redis (fast path)
  const hour = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const day  = new Date().toISOString().slice(0, 10);
  const month = new Date().toISOString().slice(0, 7);

  const pipe = redis.pipeline();
  pipe.incr(`usage:${tenantId}:calls:${hour}`);
  pipe.expire(`usage:${tenantId}:calls:${hour}`, 48 * 3600);
  pipe.incr(`usage:${tenantId}:tool:${toolName}:${day}`);
  pipe.expire(`usage:${tenantId}:tool:${toolName}:${day}`, 8 * 24 * 3600);
  if (decision === 'DENY') pipe.incr(`usage:${tenantId}:denials:${hour}`);
  pipe.lpush(`usage:${tenantId}:latency:${day}`, latencyMs);
  pipe.ltrim(`usage:${tenantId}:latency:${day}`, 0, 999);
  pipe.expire(`usage:${tenantId}:latency:${day}`, 8 * 24 * 3600);
  await pipe.exec();

  // Track integration method (how they use the API)
  await redis.setex(`usage:${tenantId}:integration`, 3600, integrationMethod);

  // Update agent last-seen
  await redis.setex(`agent:${tenantId}:${agentId}:lastseen`, 90 * 24 * 3600, new Date().toISOString());
}

// ── Analytics API plugin ───────────────────────────────────────────────

export async function analyticsPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;
  await ensurePlanLimitSchema(db);

  // ── Customer: How am I using this? ──────────────────────────────────

  fastify.get('/api/analytics/usage', async (req: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { error: 'Missing X-Tenant-ID header' };
    const days = daysFrom(req, 7);

    // Build daily stats from Redis + Postgres
    const daily: Record<string, { calls: number; denials: number; avgLatencyMs: number }> = {};

    for (let i = 0; i < days; i++) {
      const d = new Date(Date.now() - i * 24 * 3600 * 1000).toISOString().slice(0, 10);
      daily[d] = { calls: 0, denials: 0, avgLatencyMs: 0 };
    }

    const r = await db.query(
      `SELECT DATE(created_at) as day,
              COUNT(*) as calls,
              COUNT(*) FILTER (WHERE decision='DENY') as denials,
              ROUND(AVG(execution_time_ms)) as avg_ms
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
       GROUP BY day ORDER BY day DESC`,
      [tenantId, days]
    );

    r.rows.forEach((row: any) => {
      daily[row.day] = { calls: parseInt(row.calls, 10), denials: parseInt(row.denials, 10), avgLatencyMs: parseInt(row.avg_ms, 10) };
    });

    return { daily, daysRequested: days };
  });

  // ── How are you integrating? (SDK vs raw HTTP vs curl) ───────────────

  fastify.get('/api/analytics/integration', async (req: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { error: 'Missing X-Tenant-ID header' };
    const days = daysFrom(req, 7);

    const [methods, sdkVersions, topAgents] = await Promise.all([
      db.query(
        `SELECT integration_method, COUNT(*) as calls
         FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY integration_method ORDER BY calls DESC`,
        [tenantId, days]
      ),
      db.query(
        `SELECT sdk_version, COUNT(*) as calls FROM audit_log
         WHERE tenant_id=$1 AND sdk_version IS NOT NULL AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY sdk_version`,
        [tenantId, days]
      ),
      db.query(
        `SELECT agent_id, COUNT(*) as calls, MAX(created_at) as last_active,
                MIN(created_at) as first_seen
         FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY agent_id ORDER BY calls DESC LIMIT 20`,
        [tenantId, Math.max(days, 30)]
      ),
    ]);

    const currentMethod = await redis.get(`usage:${tenantId}:integration`);

    return {
      integrationMethods: methods.rows,
      sdkVersions: sdkVersions.rows,
      topAgents: topAgents.rows,
      currentIntegrationMethod: currentMethod,
      recommendation: getIntegrationRecommendation(methods.rows, currentMethod),
    };
  });

  // ── Which tools do my agents call most? ─────────────────────────────

  fastify.get('/api/analytics/tools', async (req: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { error: 'Missing X-Tenant-ID header' };
    const days = daysFrom(req, 30);

    const r = await db.query(
      `SELECT
         tool_name,
         COUNT(*) as total_calls,
         COUNT(*) FILTER (WHERE decision='ALLOW') as allowed,
         COUNT(*) FILTER (WHERE decision='DENY')  as denied,
         ROUND(AVG(execution_time_ms)) as avg_ms,
         ROUND(100.0 * COUNT(*) FILTER (WHERE decision='DENY') / NULLIF(COUNT(*),0), 1) as denial_pct,
         DATE_TRUNC('day', MIN(created_at)) as first_used,
         DATE_TRUNC('day', MAX(created_at)) as last_used
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
       GROUP BY tool_name ORDER BY total_calls DESC`,
      [tenantId, days]
    );

    return { tools: r.rows };
  });

  // ── Agent health — dormant / active / new ─────────────────────────

  fastify.get('/api/analytics/agents', async (req: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { error: 'Missing X-Tenant-ID header' };
    const days = daysFrom(req, 90);

    const r = await db.query(
      `SELECT
         agent_id,
         COUNT(*) as total_calls,
         COUNT(*) FILTER (WHERE decision='DENY') as denials,
         ROUND(AVG(execution_time_ms)) as avg_ms,
         MAX(created_at) as last_active,
         MIN(created_at) as created,
         CASE
           WHEN MAX(created_at) < NOW()-INTERVAL '7d' THEN 'dormant'
           WHEN MIN(created_at) > NOW()-INTERVAL '1d' THEN 'new'
           ELSE 'active'
         END as status
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
       GROUP BY agent_id ORDER BY last_active DESC`,
      [tenantId, days]
    );

    const summary = {
      active:  r.rows.filter((a: any) => a.status === 'active').length,
      dormant: r.rows.filter((a: any) => a.status === 'dormant').length,
      new:     r.rows.filter((a: any) => a.status === 'new').length,
    };

    return { agents: r.rows, summary };
  });

  // ── Latency trends ────────────────────────────────────────────────

  fastify.get('/api/analytics/latency', async (req: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { error: 'Missing X-Tenant-ID header' };
    const hours = Math.max(1, Math.min(168, parseInt(String(req.query?.hours || 24), 10) || 24));

    const r = await db.query(
      `SELECT
         DATE_TRUNC('hour', created_at) as hour,
         ROUND(AVG(execution_time_ms)) as avg_ms,
         ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms)) as p95_ms,
         ROUND(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms)) as p99_ms,
         MAX(execution_time_ms) as max_ms
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' hours')::interval
         AND execution_time_ms IS NOT NULL
       GROUP BY hour ORDER BY hour`,
      [tenantId, hours]
    );

    return { hourly: r.rows };
  });

  fastify.get('/api/analytics/enterprise-summary', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const days = daysFrom(req, 30);
    const [summary, byUser, bySession, byTool, exports] = await Promise.all([
      db.query(
        `SELECT COUNT(*)::int AS total_calls,
                COUNT(*) FILTER (WHERE decision='DENY')::int AS denied_calls,
                COUNT(DISTINCT agent_id)::int AS agents,
                COUNT(DISTINCT NULLIF(user_id,''))::int AS users,
                COUNT(DISTINCT NULLIF(session_id,''))::int AS sessions,
                ROUND(AVG(execution_time_ms))::int AS avg_ms,
                ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms))::int AS p95_ms
         FROM audit_log
         WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval`,
        [tenantId, days]
      ),
      db.query(
        `SELECT COALESCE(NULLIF(user_id,''),'unknown') AS user_id, COUNT(*)::int AS calls,
                COUNT(*) FILTER (WHERE decision='DENY')::int AS denials
         FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY COALESCE(NULLIF(user_id,''),'unknown') ORDER BY calls DESC LIMIT 20`,
        [tenantId, days]
      ),
      db.query(
        `SELECT COALESCE(NULLIF(session_id,''),'unknown') AS session_id, COUNT(*)::int AS calls,
                MAX(created_at) AS last_seen
         FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY COALESCE(NULLIF(session_id,''),'unknown') ORDER BY calls DESC LIMIT 20`,
        [tenantId, days]
      ),
      db.query(
        `SELECT tool_name, COUNT(*)::int AS calls,
                COUNT(*) FILTER (WHERE decision='DENY')::int AS denials,
                ROUND(AVG(execution_time_ms))::int AS avg_ms
         FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
         GROUP BY tool_name ORDER BY calls DESC LIMIT 20`,
        [tenantId, days]
      ),
      db.query(
        `SELECT COUNT(*)::int AS export_jobs FROM audit_export_jobs WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30 days'`,
        [tenantId]
      ).catch(() => ({ rows: [{ export_jobs: 0 }] })),
    ]);
    return {
      days,
      summary: summary.rows[0],
      byUser: byUser.rows,
      bySession: bySession.rows,
      byTool: byTool.rows,
      governance: {
        exportJobs30d: exports.rows[0].export_jobs,
        source: 'audit_log',
        retention: 'uses configured audit retention policy',
      },
    };
  });

  fastify.get('/api/analytics/export', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const days = daysFrom(req, 30);
    try {
      await enforceMaxValue(db, {
        tenantId,
        featureKey: 'analytics_export_days',
        requested: days,
        action: 'analytics.export',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }
    const r = await db.query(
      `SELECT created_at, agent_id, tool_name, decision, reason, execution_time_ms,
              integration_method, user_id, session_id, request_id
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval
       ORDER BY created_at DESC LIMIT 10000`,
      [tenantId, days]
    );
    const header = ['created_at','agent_id','tool_name','decision','reason','execution_time_ms','integration_method','user_id','session_id','request_id'];
    const csv = [header.join(','), ...r.rows.map(row => header.map(k => csvEscape(row[k])).join(','))].join('\n');
    return reply.header('Content-Type', 'text/csv').send(csv);
  });

  // ── What is MCP Security Gateway? — in-app explainer ───────────────

  fastify.get('/api/analytics/product-explainer', async (req: any) => {
    return {
      what: 'MCP Security Gateway is a zero-trust proxy that sits between your AI agents and your MCP tool servers.',
      how: 'Every tool call your AI agent makes is routed through this gateway. It checks who the agent is, what it is trying to do, and whether the arguments are safe — before forwarding to your actual tool server.',
      where: 'You integrate it by pointing your AI agent\'s MCP client URL to your gateway URL instead of directly to your tool server.',
      integration: {
        before: 'AI Agent → MCP Tool Server (direct, unprotected)',
        after: 'AI Agent → MCP Security Gateway → MCP Tool Server (authenticated, inspected, logged)',
        howToConnect: `const client = new McpGatewayClient({
  gatewayUrl: 'https://your-gateway.mcpsecurity.dev',
  token: 'your-bearer-token',
});
const result = await client.callTool('query_database', { query: 'SELECT...' });`,
      },
    };
  });
}

function getIntegrationRecommendation(methods: any[], current: string | null): string {
  if (!methods.length) return 'No usage yet — integrate using the TypeScript SDK for best experience.';
  const topMethod = methods[0]?.integration_method || '';
  if (topMethod.startsWith('sdk:')) return 'Great — using the SDK gives you typed errors, auto-retry, and future compatibility.';
  if (topMethod === 'manual:curl') return 'Consider switching to the TypeScript SDK for auto-retry and typed responses.';
  if (topMethod.includes('http:')) return 'You are making raw HTTP calls. The SDK adds auto-retry, typed errors, and easier auth management.';
  return 'Integration detected.';
}
