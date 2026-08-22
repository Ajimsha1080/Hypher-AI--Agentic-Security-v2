/**
 * OpenTelemetry + Prometheus Metrics Export
 *
 * Enterprise Gap 3. Enterprise customers running Datadog, Grafana, or
 * their own observability stack want gateway metrics there — not just
 * the built-in dashboard.
 *
 * Exposes:
 *   GET /metrics           Prometheus-format metrics (scrape endpoint)
 *   GET /api/otel/config   Current OTEL export configuration
 *   PUT /api/otel/config   Configure OTEL endpoint
 *
 * Metrics exported:
 *   mcp_requests_total{tenant,decision,tool}        Counter
 *   mcp_request_duration_ms{tenant,tool,p}          Histogram (p50/p95/p99)
 *   mcp_dlp_detections_total{tenant,pii_type}       Counter
 *   mcp_hitl_pending{tenant}                        Gauge
 *   mcp_active_agents{tenant}                       Gauge
 *   mcp_anomaly_flags_total{tenant}                 Counter
 *   process_uptime_seconds                          Gauge
 *   nodejs_heap_bytes{type}                         Gauge
 *
 * Wire in server.ts:
 *   import { metricsPlugin } from '../observability/metrics';
 *   await fastify.register(metricsPlugin, { db, redis });
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { requestTenantId } from '../utils/request-context';
import { encryptValue } from '../security/secrets';

// ── In-process metric counters (lightweight, no external lib needed) ──

const counters: Record<string, number> = {};
const histograms: Record<string, number[]> = {};

export function incCounter(name: string, labels: Record<string, string> = {}): void {
  const key = name + '{' + Object.entries(labels).map(([k,v]) => `${k}="${v}"`).join(',') + '}';
  counters[key] = (counters[key] || 0) + 1;
}

export function recordHistogram(name: string, value: number, labels: Record<string, string> = {}): void {
  const key = name + JSON.stringify(labels);
  if (!histograms[key]) histograms[key] = [];
  histograms[key].push(value);
  // Keep last 1000 measurements per label set
  if (histograms[key].length > 1000) histograms[key].shift();
}

function percentile(arr: number[], p: number): number {
  if (!arr.length) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return Math.round(sorted[Math.max(0, idx)]);
}

// ── Prometheus format helpers ─────────────────────────────────────────

function promLine(name: string, labels: Record<string,string>, value: number): string {
  const lblStr = Object.entries(labels).map(([k,v]) => `${k}="${v}"`).join(',');
  return `${name}{${lblStr}} ${value}`;
}

// ── Plugin ────────────────────────────────────────────────────────────

export async function metricsPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db } = opts;

  // GET /metrics — Prometheus scrape endpoint
  // Protect with Bearer token in production (METRICS_TOKEN env var)
  fastify.get('/metrics', async (req: any, reply) => {
    const authHeader = req.headers.authorization || '';
    const metricsToken = process.env.METRICS_TOKEN;
    if (metricsToken && authHeader !== `Bearer ${metricsToken}`) {
      return reply.code(401).send('Unauthorized');
    }

    // Compute live metrics from DB for last 1 minute
    const [reqs, dlp, hitl, agents] = await Promise.all([
      db.query(`
        SELECT tenant_id, decision, tool_name, COUNT(*)::int as cnt,
               PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY execution_time_ms) as p50,
               PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) as p95,
               PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms) as p99
        FROM audit_log
        WHERE created_at > NOW() - INTERVAL '1 minute'
          AND execution_time_ms IS NOT NULL
        GROUP BY tenant_id, decision, tool_name
        LIMIT 500`),
      db.query(`
        SELECT tenant_id, pii_types, COUNT(*)::int as cnt
        FROM dlp_events
        WHERE created_at > NOW() - INTERVAL '1 minute'
        GROUP BY tenant_id, pii_types LIMIT 200`),
      db.query(`
        SELECT tenant_id, COUNT(*)::int as cnt
        FROM hitl_approvals WHERE decision='pending'
        GROUP BY tenant_id`),
      db.query(`
        SELECT tenant_id, COUNT(DISTINCT agent_id)::int as cnt
        FROM audit_log
        WHERE created_at > NOW() - INTERVAL '5 minutes'
        GROUP BY tenant_id`),
    ]).catch(() => [{ rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }]);

    const lines: string[] = [
      '# HELP mcp_requests_total Total MCP tool call requests',
      '# TYPE mcp_requests_total counter',
    ];

    for (const row of (reqs as any).rows || []) {
      lines.push(promLine('mcp_requests_total', {
        tenant: row.tenant_id?.slice(0, 8) || 'unknown',
        decision: row.decision,
        tool: row.tool_name,
      }, row.cnt));
    }

    lines.push('', '# HELP mcp_request_duration_ms Request latency percentiles', '# TYPE mcp_request_duration_ms gauge');
    for (const row of (reqs as any).rows || []) {
      if (!row.p50) continue;
      const lblBase = { tenant: row.tenant_id?.slice(0, 8) || 'unknown', tool: row.tool_name };
      lines.push(promLine('mcp_request_duration_ms', { ...lblBase, quantile: '0.5'  }, Math.round(row.p50 || 0)));
      lines.push(promLine('mcp_request_duration_ms', { ...lblBase, quantile: '0.95' }, Math.round(row.p95 || 0)));
      lines.push(promLine('mcp_request_duration_ms', { ...lblBase, quantile: '0.99' }, Math.round(row.p99 || 0)));
    }

    lines.push('', '# HELP mcp_dlp_detections_total DLP PII detection events', '# TYPE mcp_dlp_detections_total counter');
    for (const row of (dlp as any).rows || []) {
      const types = JSON.parse(row.pii_types || '[]');
      for (const t of types) {
        lines.push(promLine('mcp_dlp_detections_total', {
          tenant: row.tenant_id?.slice(0, 8) || 'unknown', pii_type: t,
        }, row.cnt));
      }
    }

    lines.push('', '# HELP mcp_hitl_pending Pending HITL approval requests', '# TYPE mcp_hitl_pending gauge');
    for (const row of (hitl as any).rows || []) {
      lines.push(promLine('mcp_hitl_pending', { tenant: row.tenant_id?.slice(0, 8) || 'unknown' }, row.cnt));
    }

    lines.push('', '# HELP mcp_active_agents Active agents in last 5 minutes', '# TYPE mcp_active_agents gauge');
    for (const row of (agents as any).rows || []) {
      lines.push(promLine('mcp_active_agents', { tenant: row.tenant_id?.slice(0, 8) || 'unknown' }, row.cnt));
    }

    // Process metrics
    const mem = process.memoryUsage();
    lines.push('', '# HELP process_uptime_seconds Process uptime', '# TYPE process_uptime_seconds gauge');
    lines.push(`process_uptime_seconds ${Math.round(process.uptime())}`);
    lines.push('', '# HELP nodejs_heap_bytes Node.js heap memory', '# TYPE nodejs_heap_bytes gauge');
    lines.push(promLine('nodejs_heap_bytes', { type: 'used' }, mem.heapUsed));
    lines.push(promLine('nodejs_heap_bytes', { type: 'total' }, mem.heapTotal));
    lines.push(promLine('nodejs_heap_bytes', { type: 'rss' }, mem.rss));

    reply.header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return reply.send(lines.join('\n') + '\n');
  });

  // GET /api/otel/config
  fastify.get('/api/otel/config', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT metadata->>'otel' AS otel FROM tenants WHERE id=$1`, [tenantId]
    );
    if (!r.rows[0]?.otel) return { configured: false };
    const config = JSON.parse(r.rows[0].otel);
    return {
      configured: !!config.configured,
      endpoint: config.endpoint,
      enabled: config.enabled !== false,
      headersEncrypted: !!config.headersEncrypted,
      hasHeaders: !!config.headers && Object.keys(config.headers).length > 0,
      updatedAt: config.updatedAt,
    };
  });

  // PUT /api/otel/config — configure OTEL endpoint
  fastify.put('/api/otel/config', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'OpenTelemetry export requires Enterprise plan' });
    }

    const { endpoint, headers = {}, enabled = true } = req.body as any;
    if (!endpoint) return reply.code(400).send({ error: 'endpoint required' });

    let endpointUrl: URL;
    try {
      endpointUrl = new URL(endpoint);
      if (!['http:', 'https:'].includes(endpointUrl.protocol)) throw new Error('bad protocol');
    } catch {
      return reply.code(400).send({ error: 'valid http(s) endpoint required' });
    }

    const safeHeaders: Record<string, string> = {};
    if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
      for (const [key, value] of Object.entries(headers)) {
        if (!/^[A-Za-z0-9-]+$/.test(key)) {
          return reply.code(400).send({ error: `invalid header name: ${key}` });
        }
        safeHeaders[key] = encryptValue(String(value));
      }
    }

    const config = {
      endpoint: endpointUrl.toString(),
      headers: safeHeaders,
      headersEncrypted: true,
      enabled,
      configured: true,
      updatedAt: new Date().toISOString(),
    };
    await db.query(
      `UPDATE tenants SET metadata = jsonb_set(COALESCE(metadata,'{}'), '{otel}', $1::jsonb) WHERE id=$2`,
      [JSON.stringify(config), tenantId]
    );

    return {
      configured: true,
      scrapeUrl: `${process.env.APP_URL}/metrics`,
      note: 'Add Bearer token auth via METRICS_TOKEN env var. Prometheus scrape interval: 15s recommended.',
    };
  });
}
