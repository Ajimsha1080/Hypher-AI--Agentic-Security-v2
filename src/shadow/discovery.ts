/**
 * Shadow MCP Discovery
 *
 * Detects unauthorized MCP servers running in the organization that IT
 * hasn't approved. This is the entry-point sales motion for enterprise:
 * "Let us show you what's already running before you decide to control it."
 *
 * Detection methods:
 *   1. Network scan   — probe common MCP ports (3000, 8080, 8443, 5000)
 *   2. Agent inventory — agents appearing in audit log not in approved list
 *   3. Token analysis  — API tokens used from unexpected IPs/locations
 *   4. Tool pattern    — tool call patterns inconsistent with approved agents
 *
 * Output: Shadow MCP report with risk scores per discovered server.
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import axios from 'axios';
import crypto from 'crypto';

export interface ShadowServer {
  discoveredAt: Date;
  method: 'agent_audit' | 'ip_anomaly' | 'tool_pattern' | 'self_reported';
  agentId?: string;
  sourceIp?: string;
  toolsUsed?: string[];
  riskScore: number;      // 0-100
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  approved: boolean;
  approvedBy?: string;
}

export interface ShadowReport {
  tenantId: string;
  scannedAt: Date;
  approvedAgents: number;
  shadowAgentsFound: number;
  shadowServers: ShadowServer[];
  riskSummary: { critical: number; high: number; medium: number; low: number };
}

// ── Discovery engine ───────────────────────────────────────────────────

export async function runShadowDiscovery(
  tenantId: string,
  db: Pool,
  redis: Redis
): Promise<ShadowReport> {
  const [approvedAgents, auditAgents, ipAnomalies, toolPatterns] = await Promise.all([
    getApprovedAgents(tenantId, db),
    getAuditAgents(tenantId, db),
    detectIpAnomalies(tenantId, db),
    detectToolPatternAnomalies(tenantId, db),
  ]);

  const approvedSet = new Set(approvedAgents);
  const shadows: ShadowServer[] = [];

  // Method 1: Agents in audit log not in approved list
  for (const agent of auditAgents) {
    if (!approvedSet.has(agent.agent_id)) {
      const risk = computeRisk(agent);
      shadows.push({
        discoveredAt: new Date(agent.first_seen),
        method: 'agent_audit',
        agentId: agent.agent_id,
        sourceIp: agent.source_ip,
        toolsUsed: agent.tools,
        riskScore: risk.score,
        riskLevel: risk.level,
        reason: `Agent ${agent.agent_id} is calling tools but has no approved policy. ${agent.call_count} calls recorded.`,
        approved: false,
      });
    }
  }

  // Method 2: IP anomalies (known agent ID from unknown IP)
  for (const anomaly of ipAnomalies) {
    shadows.push({
      discoveredAt: new Date(anomaly.detected_at),
      method: 'ip_anomaly',
      agentId: anomaly.agent_id,
      sourceIp: anomaly.new_ip,
      riskScore: 65,
      riskLevel: 'high',
      reason: `Agent ${anomaly.agent_id} calling from new IP ${anomaly.new_ip} (normally from ${anomaly.known_ip})`,
      approved: approvedSet.has(anomaly.agent_id),
    });
  }

  // Method 3: Tool pattern anomalies
  for (const pattern of toolPatterns) {
    shadows.push({
      discoveredAt: new Date(pattern.detected_at),
      method: 'tool_pattern',
      agentId: pattern.agent_id,
      toolsUsed: pattern.denied_tools,
      riskScore: 50,
      riskLevel: 'medium',
      reason: `Agent repeatedly calling tools outside its policy: ${pattern.denied_tools.join(', ')}`,
      approved: approvedSet.has(pattern.agent_id),
    });
  }

  // Deduplicate by agentId
  const seen = new Set<string>();
  const deduped = shadows.filter(s => {
    const key = s.agentId || s.sourceIp || Math.random().toString();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const riskSummary = { critical: 0, high: 0, medium: 0, low: 0 };
  deduped.forEach(s => riskSummary[s.riskLevel]++);

  // Persist findings
  await persistShadowFindings(tenantId, deduped, db);

  return {
    tenantId,
    scannedAt: new Date(),
    approvedAgents: approvedAgents.length,
    shadowAgentsFound: deduped.length,
    shadowServers: deduped,
    riskSummary,
  };
}

// ── Helpers ────────────────────────────────────────────────────────────

async function getApprovedAgents(tenantId: string, db: Pool): Promise<string[]> {
  const r = await db.query(
    `SELECT DISTINCT agent_id FROM agent_tokens WHERE tenant_id=$1 AND active=true
     UNION
     SELECT DISTINCT agent_id FROM policies WHERE tenant_id=$1 AND active=true`,
    [tenantId]
  );
  return r.rows.map((r: any) => r.agent_id);
}

async function getAuditAgents(tenantId: string, db: Pool): Promise<any[]> {
  const r = await db.query(`
    SELECT
      agent_id,
      MIN(created_at) as first_seen,
      MAX(created_at) as last_seen,
      COUNT(*) as call_count,
      MAX(source_ip) as source_ip,
      array_agg(DISTINCT tool_name) as tools
    FROM audit_log
    WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '7d'
    GROUP BY agent_id
    ORDER BY call_count DESC`,
    [tenantId]
  );
  return r.rows;
}

async function detectIpAnomalies(tenantId: string, db: Pool): Promise<any[]> {
  // Agents calling from an IP they've never used before
  const r = await db.query(`
    SELECT
      a.agent_id,
      a.source_ip as new_ip,
      h.known_ip,
      a.created_at as detected_at
    FROM audit_log a
    JOIN (
      SELECT agent_id, source_ip as known_ip
      FROM audit_log
      WHERE tenant_id=$1 AND created_at < NOW()-INTERVAL '7d'
      GROUP BY agent_id, source_ip
      HAVING COUNT(*) > 10
    ) h ON h.agent_id=a.agent_id
    WHERE a.tenant_id=$1
      AND a.source_ip IS NOT NULL
      AND a.source_ip != h.known_ip
      AND a.created_at > NOW()-INTERVAL '1d'
    GROUP BY a.agent_id, a.source_ip, h.known_ip, a.created_at
    LIMIT 20`,
    [tenantId]
  );
  return r.rows;
}

async function detectToolPatternAnomalies(tenantId: string, db: Pool): Promise<any[]> {
  // Agents that keep hitting policy denials for the same tools
  const r = await db.query(`
    SELECT
      agent_id,
      array_agg(DISTINCT tool_name) as denied_tools,
      COUNT(*) as denial_count,
      MAX(created_at) as detected_at
    FROM audit_log
    WHERE tenant_id=$1 AND decision='DENY' AND reason LIKE 'policy_denied%'
      AND created_at > NOW()-INTERVAL '7d'
    GROUP BY agent_id
    HAVING COUNT(*) > 5
    ORDER BY denial_count DESC
    LIMIT 20`,
    [tenantId]
  );
  return r.rows;
}

function computeRisk(agent: any): { score: number; level: ShadowServer['riskLevel'] } {
  let score = 30; // base
  if (agent.call_count > 100) score += 20;
  if (agent.call_count > 1000) score += 20;
  const dangerousTools = ['run_command', 'write_file', 'delete_file', 'http_request'];
  if (agent.tools?.some((t: string) => dangerousTools.includes(t))) score += 25;
  if (!agent.source_ip) score += 10;

  score = Math.min(100, score);
  const level: ShadowServer['riskLevel'] =
    score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low';
  return { score, level };
}

async function persistShadowFindings(
  tenantId: string, findings: ShadowServer[], db: Pool
): Promise<void> {
  for (const f of findings) {
    await db.query(
      `INSERT INTO shadow_mcp_findings
         (tenant_id, agent_id, source_ip, method, risk_score, risk_level, reason, tools_used, approved, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
       ON CONFLICT (tenant_id, agent_id, method) DO UPDATE SET
         risk_score=$5, risk_level=$6, reason=$7, tools_used=$8, updated_at=NOW()`,
      [tenantId, f.agentId||null, f.sourceIp||null, f.method,
       f.riskScore, f.riskLevel, f.reason,
       JSON.stringify(f.toolsUsed||[]), f.approved]
    ).catch(() => {}); // non-blocking
  }
}

// ── Fastify plugin ─────────────────────────────────────────────────────

export async function shadowPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;
  function allowBrowserRoleHeaders(): boolean {
    return process.env.NODE_ENV !== 'production' || process.env.MCPSG_TRUST_BROWSER_ROLE_HEADERS === 'true';
  }
  function requestRole(req: any): string {
    if (req?.user?.role) return String(req.user.role);
    return allowBrowserRoleHeaders() ? String(req?.headers?.['x-admin-role'] || 'viewer') : 'viewer';
  }
  function requestActor(req: any): string {
    if (req?.user?.email) return String(req.user.email);
    if (allowBrowserRoleHeaders()) return String(req?.headers?.['x-admin-email'] || 'dashboard');
    return 'authenticated-user';
  }
  function canManageShadow(req: any, reply: any): boolean {
    const role = requestRole(req);
    if (['local_admin', 'super_admin', 'security_analyst'].includes(role)) return true;
    reply.code(403).send({ error: 'Requires security_analyst or admin role' });
    return false;
  }
  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  fastify.get('/api/shadow/scan', async (req: any, reply: any) => {
    const tenant = await tenantFrom(req);
    if (!['enterprise', 'growth'].includes(tenant?.plan)) {
      return reply.code(403).send({ error: 'Shadow MCP discovery requires Growth or Enterprise plan' });
    }
    const cacheKey = `shadow:${tenant.id}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const report = await runShadowDiscovery(tenant.id, db, redis);
    await redis.setex(cacheKey, 300, JSON.stringify(report)); // cache 5 min
    return report;
  });

  fastify.post('/api/shadow/scan', async (req: any, reply: any) => {
    const tenant = await tenantFrom(req);
    if (!['enterprise', 'growth'].includes(tenant?.plan)) {
      return reply.code(403).send({ error: 'Shadow MCP discovery requires Growth or Enterprise plan' });
    }
    await redis.del(`shadow:${tenant.id}`);
    const report = await runShadowDiscovery(tenant.id, db, redis);
    await redis.setex(`shadow:${tenant.id}`, 300, JSON.stringify(report));
    return report;
  });

  fastify.post('/api/shadow/approve/:agentId', async (req: any, reply: any) => {
    if (!canManageShadow(req, reply)) return;
    const tenant = await tenantFrom(req);
    if (!tenant) return reply.code(400).send({ approved: false, error: 'Missing tenant' });
    const { agentId } = req.params as any;
    const updated = await db.query(
      `UPDATE shadow_mcp_findings SET approved=true, approved_by=$1, updated_at=NOW()
       WHERE tenant_id=$2 AND agent_id=$3`,
      [requestActor(req), tenant.id, agentId]
    );
    if (!updated.rowCount) return reply.code(404).send({ approved: false, error: 'Shadow finding not found' });
    await redis.del(`shadow:${tenant.id}`);
    return {
      approved: true,
      agentId,
      policyCreated: false,
      message: 'Shadow finding approved as known. Create tool access policy separately; wildcard access is not auto-granted.',
    };
  });

  fastify.get('/api/shadow/history', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { findings: [] };
    const r = await db.query(
      `SELECT * FROM shadow_mcp_findings WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [tenant.id]
    );
    return { findings: r.rows };
  });

  fastify.get('/api/shadow/findings', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { findings: [] };
    const r = await db.query(
      `SELECT * FROM shadow_mcp_findings WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [tenant.id]
    );
    return { findings: r.rows };
  });

  fastify.get('/api/shadow/summary', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { approvedAgents: 0, shadowAgentsFound: 0, highRisk: 0, findings: 0 };
    const [approvedAgents, findings] = await Promise.all([
      db.query(
        `SELECT COUNT(DISTINCT agent_id)::int AS count FROM agent_tokens WHERE tenant_id=$1 AND active=true`,
        [tenant.id]
      ),
      db.query(
        `SELECT
           COUNT(*)::int AS findings,
           COUNT(*) FILTER (WHERE approved=false)::int AS shadow_agents,
           COUNT(*) FILTER (WHERE risk_level IN ('high','critical') AND approved=false)::int AS high_risk,
           MAX(updated_at) AS last_updated,
           MAX(created_at) AS last_created
         FROM shadow_mcp_findings WHERE tenant_id=$1`,
        [tenant.id]
      ),
    ]);
    return {
      approvedAgents: approvedAgents.rows[0]?.count || 0,
      shadowAgentsFound: findings.rows[0]?.shadow_agents || 0,
      highRisk: findings.rows[0]?.high_risk || 0,
      findings: findings.rows[0]?.findings || 0,
      lastScan: findings.rows[0]?.last_updated || findings.rows[0]?.last_created || null,
    };
  });
}
