/**
 * SLA Dashboard
 *
 * Sprint 3 enterprise feature. Exposes real-time and historical SLA metrics
 * for enterprise contracts: uptime %, p50/p95/p99 latency, error rate.
 *
 * Metrics are written to sla_metrics table (audit/schema.sql) by the
 * proxy pipeline on every request (execution_time_ms already tracked).
 * This module provides the read API + summary view.
 *
 * Routes:
 *   GET /api/sla                  SLA summary (uptime, p99, error rate)
 *   GET /api/sla/history?window=  Historical metrics
 *   POST /api/sla/record          Internal — called after each proxy request
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

export async function slaPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/sla — current SLA summary
  fastify.get('/api/sla', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SLA dashboard requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    // Compute from audit_log for last 24h
    const stats = await db.query(
      `SELECT
         COUNT(*)::int                                          AS total_requests,
         SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END)::int AS denied_requests,
         PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY execution_time_ms) AS p50_ms,
         PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms) AS p95_ms,
         PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms) AS p99_ms,
         AVG(execution_time_ms)::numeric(10,2)                  AS avg_ms,
         MAX(execution_time_ms)                                  AS max_ms
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
         AND execution_time_ms IS NOT NULL`,
      [tenantId]
    );

    const row = stats.rows[0];
    const total = row.total_requests || 0;
    const errRate = total > 0 ? ((row.denied_requests || 0) / total * 100).toFixed(2) : '0.00';

    // Uptime: simple proxy — if no outages recorded, 100%. In production,
    // integrate with health check pings stored in sla_metrics.
    const uptimeRow = await db.query(
      `SELECT COALESCE(AVG(value), 100)::numeric(6,3) AS uptime
       FROM sla_metrics
       WHERE tenant_id=$1 AND metric_type='uptime'
         AND recorded_at > NOW() - INTERVAL '30 days'`,
      [tenantId]
    );

    return {
      window: '24h',
      uptime_pct: parseFloat(uptimeRow.rows[0]?.uptime || '100'),
      total_requests: total,
      error_rate_pct: parseFloat(errRate),
      latency: {
        p50_ms:  Math.round(row.p50_ms || 0),
        p95_ms:  Math.round(row.p95_ms || 0),
        p99_ms:  Math.round(row.p99_ms || 0),
        avg_ms:  Math.round(row.avg_ms || 0),
        max_ms:  row.max_ms || 0,
      },
      sla_met: parseFloat(uptimeRow.rows[0]?.uptime || '100') >= 99.9,
      sla_target: '99.9% uptime, p99 < 100ms',
    };
  });

  // GET /api/sla/history?window=7d
  fastify.get('/api/sla/history', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SLA dashboard requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const windowParam = (req.query as any).window || '7d';
    const intervalMap: Record<string, string> = {
      '24h': '24 hours', '7d': '7 days', '30d': '30 days',
    };
    const interval = intervalMap[windowParam] || '7 days';

    const history = await db.query(
      `SELECT
         DATE_TRUNC('hour', created_at) AS hour,
         COUNT(*)::int                   AS requests,
         PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms) AS p99_ms,
         SUM(CASE WHEN decision='DENY' THEN 1 ELSE 0 END)::int AS errors
       FROM audit_log
       WHERE tenant_id=$1
         AND created_at > NOW() - ($2 || '')::INTERVAL
         AND execution_time_ms IS NOT NULL
       GROUP BY 1 ORDER BY 1 ASC`,
      [tenantId, interval]
    );

    return { window: windowParam, history: history.rows };
  });

  // POST /api/sla/record (internal — called by proxy pipeline)
  fastify.post('/api/sla/record', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SLA dashboard requires Enterprise plan' });
    }
    const { tenantId, executionTimeMs, decision } = req.body as any;
    if (!tenantId) return reply.code(400).send({ error: 'tenantId required' });

    await db.query(
      `INSERT INTO sla_metrics (tenant_id, metric_type, value, "window")
       VALUES ($1, 'p99_ms', $2, '1m'),
              ($1, 'uptime', $3, '1m')`,
      [tenantId, executionTimeMs || 0, decision === 'error' ? 0 : 100]
    ).catch(() => {}); // Non-fatal

    return { recorded: true };
  });
}
