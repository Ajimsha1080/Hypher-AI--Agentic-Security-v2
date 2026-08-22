/**
 * Future Features Backend — F1, F2, F3
 *
 * F1: Policy version history + rollback
 * F2: AI-powered anomaly explanations (uses Anthropic SDK already in package.json)
 * F3: Tool call replay from audit log
 *
 * Wire in server.ts:
 *   import { policyVersionsPlugin } from '../features/policy-versions';
 *   import { anomalyExplainPlugin } from '../features/anomaly-explain';
 *   import { replayPlugin } from '../features/replay';
 *   await fastify.register(policyVersionsPlugin, { db });
 *   await fastify.register(anomalyExplainPlugin, { db });
 *   await fastify.register(replayPlugin, { db });
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Anthropic from '@anthropic-ai/sdk';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

// ═══════════════════════════════════════════════════════
// F1: Policy Version History + Rollback
// ═══════════════════════════════════════════════════════

export async function policyVersionsPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // Table: policy_versions — created by migration 007
  // Each policy change writes a snapshot here

  // GET /api/policies/history — list version history for tenant
  fastify.get('/api/policies/history', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const agentId = (req.query as any).agentId;
    const r = await db.query(
      `SELECT pv.id, pv.agent_id, pv.version, pv.changed_by, pv.change_reason,
              pv.snapshot_json, pv.created_at,
              pv.version - LAG(pv.version) OVER (PARTITION BY pv.agent_id ORDER BY pv.version) AS version_gap
       FROM policy_versions pv
       WHERE pv.tenant_id=$1 ${agentId ? 'AND pv.agent_id=$2' : ''}
       ORDER BY pv.created_at DESC LIMIT 50`,
      agentId ? [tenantId, agentId] : [tenantId]
    );
    return { versions: r.rows };
  });

  // GET /api/policies/diff/:v1/:v2 — diff two versions
  fastify.get('/api/policies/diff/:v1/:v2', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const params = req.params as any;
    const [r1, r2] = await Promise.all([
      db.query('SELECT * FROM policy_versions WHERE id=$1 AND tenant_id=$2', [params.v1, tenantId]),
      db.query('SELECT * FROM policy_versions WHERE id=$1 AND tenant_id=$2', [params.v2, tenantId]),
    ]);
    if (!r1.rows[0] || !r2.rows[0]) return reply.code(404).send({ error: 'Version not found' });

    const snap1 = JSON.parse(r1.rows[0].snapshot_json || '{}');
    const snap2 = JSON.parse(r2.rows[0].snapshot_json || '{}');

    // Compute added/removed/changed tools
    const tools1 = new Set((snap1.allowedTools || []) as string[]);
    const tools2 = new Set((snap2.allowedTools || []) as string[]);
    const added   = [...tools2].filter(t => !tools1.has(t));
    const removed = [...tools1].filter(t => !tools2.has(t));

    return {
      v1: { id: params.v1, createdAt: r1.rows[0].created_at, changedBy: r1.rows[0].changed_by },
      v2: { id: params.v2, createdAt: r2.rows[0].created_at, changedBy: r2.rows[0].changed_by },
      diff: { added, removed, unchanged: [...tools1].filter(t => tools2.has(t)) },
    };
  });

  // POST /api/policies/rollback/:versionId — restore a previous version
  fastify.post('/api/policies/rollback/:versionId', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const params = req.params as any;
    const r = await db.query(
      'SELECT * FROM policy_versions WHERE id=$1 AND tenant_id=$2', [params.versionId, tenantId]
    );
    if (!r.rows[0]) return reply.code(404).send({ error: 'Version not found' });

    const snapshot = JSON.parse(r.rows[0].snapshot_json || '{}');
    const agentId = r.rows[0].agent_id;

    await db.query('BEGIN');
    try {
      // Deactivate all current policies for this agent
      await db.query(
        'UPDATE policies SET active=FALSE WHERE tenant_id=$1 AND agent_id=$2',
        [tenantId, agentId]
      );
      // Restore allowed tools from snapshot
      for (const tool of (snapshot.allowedTools || [])) {
        await db.query(
          `INSERT INTO policies (agent_id, tool_name, action, priority, tenant_id, description)
           VALUES ($1,$2,'allow',100,$3,'Restored from version ' || $4)
           ON CONFLICT DO NOTHING`,
          [agentId, tool, tenantId, params.versionId]
        );
      }
      // Write the rollback as a new version
      await db.query(
        `INSERT INTO policy_versions (tenant_id, agent_id, version, changed_by, change_reason, snapshot_json)
         VALUES ($1,$2,(SELECT COALESCE(MAX(version),0)+1 FROM policy_versions WHERE tenant_id=$1 AND agent_id=$2),$3,'Rollback to version ' || $4,$5)`,
        [tenantId, agentId, (req as any).user?.agentId || 'admin', params.versionId, r.rows[0].snapshot_json]
      );
      await db.query('COMMIT');
    } catch (err) {
      await db.query('ROLLBACK');
      throw err;
    }

    return { rolled_back: true, agentId, restoredFrom: params.versionId };
  });
}

// ═══════════════════════════════════════════════════════
// F2: AI-Powered Anomaly Explanations
// ═══════════════════════════════════════════════════════

export async function anomalyExplainPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;
  const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  // POST /api/anomaly/explain — explain a specific anomaly event in plain English
  fastify.post('/api/anomaly/explain', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId, toolName, eventTime, zScore, actualCount, baselineMean } = req.body as any;
    if (!agentId || !toolName) return reply.code(400).send({ error: 'agentId and toolName required' });

    // Fetch recent call context for this agent
    const context = await db.query(
      `SELECT tool_name, COUNT(*)::int as calls, 
              MIN(created_at) as first, MAX(created_at) as last
       FROM audit_log
       WHERE tenant_id=$1 AND agent_id=$2 
         AND created_at > NOW() - INTERVAL '1 hour'
       GROUP BY tool_name ORDER BY calls DESC LIMIT 10`,
      [tenantId, agentId]
    );

    const prompt = `You are a security analyst for an AI agent security gateway. Explain this anomaly detection event in plain English to a security team member.

Agent ID: ${agentId}
Flagged tool: ${toolName}
Event time: ${eventTime || new Date().toISOString()}
Z-score: ${zScore?.toFixed(2) || 'N/A'} (3.0+ = anomalous)
Actual call count in window: ${actualCount || 'unknown'}
Baseline mean: ${baselineMean?.toFixed(1) || 'unknown'}

Agent's recent tool usage (last 1 hour):
${context.rows.map((r: any) => `  ${r.tool_name}: ${r.calls} calls (${r.first} → ${r.last})`).join('\n') || '  No recent data'}

Write 2–3 sentences explaining:
1. What the anomaly means in plain English
2. What the likely cause could be (data export, bug, attack, or normal peak usage)
3. What the security team should check first

Be direct and specific. Do not use jargon. Do not say "z-score".`;

    try {
      const msg = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 300,
        messages: [{ role: 'user', content: prompt }],
      });
      const explanation = (msg.content[0] as any).text;
      return { explanation, agentId, toolName, zScore };
    } catch (err: any) {
      return { explanation: `Agent ${agentId} called ${toolName} ${actualCount || 'many'} times — ${(zScore || 0).toFixed(1)}x above its baseline. Check if this is expected behaviour or investigate for data exfiltration.`, agentId, toolName };
    }
  });
}

// ═══════════════════════════════════════════════════════
// F3: Tool Call Replay from Audit Log
// ═══════════════════════════════════════════════════════

export async function replayPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // POST /api/audit/replay/:logId — replay a past tool call through current policies
  fastify.post('/api/audit/replay/:logId', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const params = req.params as any;
    const r = await db.query(
      `SELECT agent_id, tool_name, reason, decision, auth_provider, source_ip,
              inspection_result, created_at
       FROM audit_log WHERE id=$1 AND tenant_id=$2 LIMIT 1`,
      [params.logId, tenantId]
    );
    if (!r.rows[0]) return reply.code(404).send({ error: 'Log entry not found' });

    const entry = r.rows[0];

    // Simulate running through current RBAC policies without actually forwarding
    const policyCheck = await db.query(
      `SELECT id FROM policies
       WHERE agent_id=$1 AND tenant_id=$2
         AND (allowed_tools @> ARRAY[$3::text] OR allowed_tools=ARRAY['*'])
         AND active=true LIMIT 1`,
      [entry.agent_id, tenantId, entry.tool_name]
    );

    // Check current anomaly baseline
    const baseline = await db.query(
      `SELECT mean_calls, std_calls FROM anomaly_baselines
       WHERE agent_id=$1 AND tool_name=$2 LIMIT 1`,
      [entry.agent_id, entry.tool_name]
    );

    const wouldBeAllowed = policyCheck.rows.length > 0;
    const originalDecision = entry.decision;
    const decisionChanged = (originalDecision === 'ALLOW') !== wouldBeAllowed;

    return {
      logId: params.logId,
      originalCall: {
        agentId: entry.agent_id,
        toolName: entry.tool_name,
        decision: originalDecision,
        reason: entry.reason,
        at: entry.created_at,
      },
      replayResult: {
        wouldBeAllowed,
        wouldBeDecision: wouldBeAllowed ? 'ALLOW' : 'DENY',
        reason: wouldBeAllowed ? 'policy_match' : 'no_matching_policy',
        decisionChanged,
        currentBaseline: baseline.rows[0] || null,
      },
      note: decisionChanged
        ? `Policy change detected: call was ${originalDecision} at ${entry.created_at} but would be ${wouldBeAllowed ? 'ALLOW' : 'DENY'} today`
        : 'Decision unchanged — current policies match original outcome',
    };
  });

  // GET /api/audit/replayable?agentId= — list replayable entries
  fastify.get('/api/audit/replayable', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Policy versioning and replay requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const agentId = (req.query as any).agentId;
    const r = await db.query(
      `SELECT id, agent_id, tool_name, decision, reason, created_at
       FROM audit_log
       WHERE tenant_id=$1 ${agentId ? 'AND agent_id=$2' : ''}
       ORDER BY created_at DESC LIMIT 100`,
      agentId ? [tenantId, agentId] : [tenantId]
    );
    return { entries: r.rows };
  });
}
