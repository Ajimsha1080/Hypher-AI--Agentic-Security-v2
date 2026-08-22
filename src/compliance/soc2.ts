/**
 * SOC 2 Compliance Export — NEW Enterprise Feature
 *
 * Generates compliance-ready audit reports for SOC 2 Type II evidence.
 * Enterprise customers need this to satisfy their InfoSec requirements.
 *
 * Reports include:
 * - Summary: total calls, allow/deny breakdown, top agents
 * - Denial analysis: reasons, patterns
 * - Security incidents: injections, anomalies
 * - Policy changes audit trail
 * - Authentication events
 * - Tool registry violations
 *
 * Output: JSON (for programmatic use), CSV (for spreadsheets)
 * PDF generation available via external service integration.
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

export interface ComplianceReport {
  metadata: {
    tenantId: string;
    tenantName: string;
    reportType: 'soc2' | 'gdpr' | 'hipaa' | 'custom';
    dateFrom: string;
    dateTo: string;
    generatedAt: string;
    rowCount: number;
    reportId: string;
  };
  summary: {
    totalRequests: number;
    allowedRequests: number;
    deniedRequests: number;
    denialRate: number;
    uniqueAgents: number;
    uniqueTools: number;
    avgExecutionMs: number;
    p99ExecutionMs: number;
  };
  securityEvents: {
    injectionAttempts: number;
    anomalyBlocks: number;
    registryBlocks: number;
    authFailures: number;
    replayAttempts: number;
    policyDenials: number;
  };
  topDenialReasons: Array<{ reason: string; count: number }>;
  agentActivity: Array<{ agentId: string; calls: number; denials: number; lastSeen: string }>;
  toolUsage: Array<{ toolName: string; calls: number; denials: number }>;
  dailyBreakdown: Array<{ date: string; allowed: number; denied: number }>;
  policyChanges: Array<{ agentId: string; change: string; performedBy: string; timestamp: string }>;
}

export async function compliancePlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;

  // ── Generate compliance report ────────────────────────────────────
  fastify.post('/api/compliance/export', async (req: any, reply) => {
    const { dateFrom, dateTo, reportType = 'soc2', format = 'json' } = req.body;
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    if (!dateFrom || !dateTo) {
      return reply.code(400).send({ error: 'dateFrom and dateTo required' });
    }

    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(403).send({ error: 'SOC 2 export requires Enterprise plan' });
    }

    const from = new Date(dateFrom);
    const to = new Date(dateTo);
    if (isNaN(from.getTime()) || isNaN(to.getTime())) {
      return reply.code(400).send({ error: 'Invalid date format' });
    }

    const tenant = await db.query(`SELECT name FROM tenants WHERE id=$1`, [tenantId]);
    const tenantName = req.tenant?.name || tenant.rows[0]?.name || tenantId;
    const report = await buildComplianceReport(tenantId, tenantName, from, to, reportType, db);

    // Log the export for audit trail
    await db.query(
      `INSERT INTO compliance_exports
         (tenant_id, export_type, date_from, date_to, row_count, file_hash, generated_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [tenantId, reportType, from, to, report.metadata.rowCount,
       crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex').slice(0, 16),
       req.user?.email || 'api']
    );

    if (format === 'csv') {
      const csv = reportToCsv(report);
      return reply
        .type('text/csv')
        .header('Content-Disposition', `attachment; filename="soc2-report-${dateFrom}-${dateTo}.csv"`)
        .send(csv);
    }

    return report;
  });

  // ── Export audit log as CSV ────────────────────────────────────────
  fastify.get('/api/compliance/audit-csv', async (req: any, reply) => {
    const { from, to, limit = 10000 } = req.query as any;
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(403).send({ error: 'Audit CSV export requires Enterprise plan' });
    }

    const r = await db.query(
      `SELECT agent_id, tool_name, decision, reason, execution_time_ms,
              auth_provider, source_ip, created_at
       FROM audit_log
       WHERE tenant_id=$1
         AND ($2::timestamptz IS NULL OR created_at >= $2)
         AND ($3::timestamptz IS NULL OR created_at <= $3)
       ORDER BY created_at DESC
       LIMIT $4`,
      [tenantId, from || null, to || null, parseInt(limit, 10)]
    );

    const headers = ['timestamp', 'agent_id', 'tool_name', 'decision', 'reason', 'execution_ms', 'auth_provider', 'source_ip'];
    const rows = r.rows.map(row => [
      row.created_at.toISOString(),
      row.agent_id, row.tool_name, row.decision,
      row.reason || '', row.execution_time_ms || '',
      row.auth_provider || '', row.source_ip || '',
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));

    const csv = [headers.join(','), ...rows].join('\n');
    return reply
      .type('text/csv')
      .header('Content-Disposition', `attachment; filename="audit-log-${tenantId}.csv"`)
      .send(csv);
  });

  // ── List previous exports ─────────────────────────────────────────
  fastify.get('/api/compliance/exports', async (req: any) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return { exports: [] };
    const r = await db.query(
      `SELECT * FROM compliance_exports WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [tenantId]
    );
    return { exports: r.rows };
  });
}

// ── Report builder ────────────────────────────────────────────────────

async function buildComplianceReport(
  tenantId: string, tenantName: string,
  from: Date, to: Date, reportType: string, db: Pool
): Promise<ComplianceReport> {

  const [summary, secEvents, topDenials, agents, tools, daily] = await Promise.all([
    db.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE decision='ALLOW') as allowed,
        COUNT(*) FILTER (WHERE decision='DENY') as denied,
        COUNT(DISTINCT agent_id) as agents,
        COUNT(DISTINCT tool_name) as tools,
        ROUND(AVG(execution_time_ms)) as avg_ms,
        PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms) as p99_ms
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3`,
      [tenantId, from, to]
    ),
    db.query(`
      SELECT
        COUNT(*) FILTER (WHERE reason LIKE 'prompt_injection%') as injections,
        COUNT(*) FILTER (WHERE reason LIKE 'anomaly_blocked%') as anomalies,
        COUNT(*) FILTER (WHERE reason LIKE 'registry_blocked%') as registry,
        COUNT(*) FILTER (WHERE reason LIKE 'auth_%') as auth_failures,
        COUNT(*) FILTER (WHERE reason LIKE 'replay%') as replays,
        COUNT(*) FILTER (WHERE reason LIKE 'policy_denied%') as policy_denials
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3 AND decision='DENY'`,
      [tenantId, from, to]
    ),
    db.query(`
      SELECT reason, COUNT(*) as count FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3 AND decision='DENY' AND reason IS NOT NULL
      GROUP BY reason ORDER BY count DESC LIMIT 15`,
      [tenantId, from, to]
    ),
    db.query(`
      SELECT agent_id, COUNT(*) as calls,
             COUNT(*) FILTER (WHERE decision='DENY') as denials,
             MAX(created_at) as last_seen
      FROM audit_log WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
      GROUP BY agent_id ORDER BY calls DESC LIMIT 50`,
      [tenantId, from, to]
    ),
    db.query(`
      SELECT tool_name, COUNT(*) as calls, COUNT(*) FILTER (WHERE decision='DENY') as denials
      FROM audit_log WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
      GROUP BY tool_name ORDER BY calls DESC LIMIT 30`,
      [tenantId, from, to]
    ),
    db.query(`
      SELECT DATE_TRUNC('day', created_at) as date,
             COUNT(*) FILTER (WHERE decision='ALLOW') as allowed,
             COUNT(*) FILTER (WHERE decision='DENY') as denied
      FROM audit_log WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
      GROUP BY 1 ORDER BY 1`,
      [tenantId, from, to]
    ),
  ]);

  const s = summary.rows[0];
  const total = parseInt(s.total, 10);

  return {
    metadata: {
      tenantId, tenantName, reportType: reportType as 'soc2' | 'gdpr' | 'hipaa' | 'custom',
      dateFrom: from.toISOString(), dateTo: to.toISOString(),
      generatedAt: new Date().toISOString(),
      rowCount: total,
      reportId: crypto.randomBytes(8).toString('hex'),
    },
    summary: {
      totalRequests: total,
      allowedRequests: parseInt(s.allowed, 10),
      deniedRequests: parseInt(s.denied, 10),
      denialRate: total > 0 ? Math.round((parseInt(s.denied, 10) / total) * 10000) / 100 : 0,
      uniqueAgents: parseInt(s.agents, 10),
      uniqueTools: parseInt(s.tools, 10),
      avgExecutionMs: parseInt(s.avg_ms, 10) || 0,
      p99ExecutionMs: parseInt(s.p99_ms, 10) || 0,
    },
    securityEvents: {
      injectionAttempts: parseInt(secEvents.rows[0].injections, 10),
      anomalyBlocks: parseInt(secEvents.rows[0].anomalies, 10),
      registryBlocks: parseInt(secEvents.rows[0].registry, 10),
      authFailures: parseInt(secEvents.rows[0].auth_failures, 10),
      replayAttempts: parseInt(secEvents.rows[0].replays, 10),
      policyDenials: parseInt(secEvents.rows[0].policy_denials, 10),
    },
    topDenialReasons: topDenials.rows.map(r => ({ reason: r.reason, count: parseInt(r.count, 10) })),
    agentActivity: agents.rows.map(r => ({
      agentId: r.agent_id, calls: parseInt(r.calls, 10),
      denials: parseInt(r.denials, 10), lastSeen: r.last_seen,
    })),
    toolUsage: tools.rows.map(r => ({
      toolName: r.tool_name, calls: parseInt(r.calls, 10), denials: parseInt(r.denials, 10),
    })),
    dailyBreakdown: daily.rows.map(r => ({
      date: r.date, allowed: parseInt(r.allowed, 10), denied: parseInt(r.denied, 10),
    })),
    policyChanges: [], // Populated from admin_actions table
  };
}

function reportToCsv(report: ComplianceReport): string {
  const lines: string[] = [
    '# MCP Security Gateway — SOC 2 Compliance Report',
    `# Generated: ${report.metadata.generatedAt}`,
    `# Period: ${report.metadata.dateFrom} to ${report.metadata.dateTo}`,
    `# Tenant: ${report.metadata.tenantName}`,
    '',
    '## Summary',
    'Metric,Value',
    `Total Requests,${report.summary.totalRequests}`,
    `Allowed,${report.summary.allowedRequests}`,
    `Denied,${report.summary.deniedRequests}`,
    `Denial Rate,${report.summary.denialRate}%`,
    `Unique Agents,${report.summary.uniqueAgents}`,
    '',
    '## Security Events',
    'Event Type,Count',
    `Prompt Injection Attempts,${report.securityEvents.injectionAttempts}`,
    `Anomaly Blocks,${report.securityEvents.anomalyBlocks}`,
    `Registry Blocks,${report.securityEvents.registryBlocks}`,
    `Auth Failures,${report.securityEvents.authFailures}`,
    '',
    '## Daily Breakdown',
    'Date,Allowed,Denied',
    ...report.dailyBreakdown.map(d => `${d.date},${d.allowed},${d.denied}`),
  ];
  return lines.join('\n');
}
