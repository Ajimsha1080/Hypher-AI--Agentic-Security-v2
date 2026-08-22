/**
 * Dashboard Plugin — serves the combined UI (user + admin in one file)
 * User Dashboard: /dashboard
 * Admin Panel:    /dashboard (switch via top bar — Admin Panel button)
 * Combined file:  /dashboard/combined (same file, full access)
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { verifyHashChain } from '../audit/hash-chain';
import { ensurePlanLimitSchema, enforceMaxValue, enforcePlanLimit, getPlanLimits, getPlanUsage, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';
import { encryptValue, decryptValue } from '../security/secrets';

function tenantIdFrom(req: any): string | undefined {
  return req.headers['x-tenant-id'] || req.tenant?.id;
}

function allowBrowserRoleHeaders(): boolean {
  return process.env.NODE_ENV !== 'production' || process.env.ALLOW_DEV_ROLE_HEADERS === 'true';
}

const ROLE_CAPABILITIES: Record<string, string[]> = {
  super_admin: ['manage_alerts','approve_hitl','view_audit','export_audit','manage_policies','manage_team','configure_integrations','manage_ml','manage_agents'],
  security_analyst: ['manage_alerts','approve_hitl','view_audit','export_audit','manage_policies','manage_ml'],
  billing_admin: ['view_audit'],
  viewer: ['view_audit'],
  local_admin: ['manage_alerts','approve_hitl','view_audit','export_audit','manage_policies','manage_team','configure_integrations','manage_ml','manage_agents'],
};

function roleFrom(req: any): string {
  const sessionRole = req.user?.role;
  if (sessionRole) return String(sessionRole);
  if (allowBrowserRoleHeaders()) return String(req.headers['x-admin-role'] || 'viewer');
  return 'viewer';
}

function actorEmailFrom(req: any): string {
  const sessionEmail = req.user?.email;
  if (sessionEmail) return String(sessionEmail);
  if (allowBrowserRoleHeaders()) return String(req.headers['x-admin-email'] || req.headers['x-approver-id'] || 'local-admin');
  return 'session-required';
}

function hasCapability(req: any, capability: string): boolean {
  const caps = ROLE_CAPABILITIES[roleFrom(req)] || ROLE_CAPABILITIES.viewer;
  return caps.includes(capability);
}

function requireCapability(req: any, reply: any, capability: string): boolean {
  if (hasCapability(req, capability)) return true;
  reply.code(403).send({ error: `Requires ${capability} permission` });
  return false;
}

async function auditAdminAction(db: Pool, req: any, action: string, target: string, details: Record<string, unknown> = {}) {
  const tenantId = tenantIdFrom(req);
  if (!tenantId) return;
  await db.query(
    `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
    [
      tenantId,
      actorEmailFrom(req),
      roleFrom(req),
      action,
      target,
      JSON.stringify(details),
    ]
  ).catch(() => {});
}

function asInt(value: any, fallback: number, min: number, max: number): number {
  const n = parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function csvEscape(value: any): string {
  const s = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function redactPreview(value: string): string {
  return String(value || '')
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[^"'\s,}]+/gi, '$1=[REDACTED_SECRET]')
    .replace(/\b\d{13,19}\b/g, '[REDACTED_CARD]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
}

function classifyAgentRisk(totalCalls: number, denialPct: number, lastActive?: string | Date | null): string {
  if (denialPct >= 30) return 'high';
  if (denialPct >= 10) return 'medium';
  if (!lastActive && totalCalls === 0) return 'new';
  return 'low';
}

function safeAgentId(value: unknown): string | null {
  const s = String(value || '').trim();
  if (!s) return null;
  return /^[a-zA-Z0-9_.:-]{3,80}$/.test(s) ? s : null;
}

function upsertEnvValues(values: Record<string, string | undefined>) {
  const envPath = join(process.cwd(), '.env');
  const existing = existsSync(envPath) ? readFileSync(envPath, 'utf-8') : '';
  const lines = existing.split(/\r?\n/);
  const seen = new Set<string>();
  const next = lines.map(line => {
    const match = line.match(/^([A-Z0-9_]+)=/);
    if (!match || !(match[1] in values)) return line;
    const key = match[1];
    seen.add(key);
    const value = values[key] || '';
    return `${key}=${value}`;
  }).filter((line, index, arr) => line.length > 0 || index < arr.length - 1);
  for (const [key, value] of Object.entries(values)) {
    if (!seen.has(key) && value !== undefined) next.push(`${key}=${value}`);
  }
  writeFileSync(envPath, `${next.join('\n')}\n`, 'utf-8');
}

function safePublicUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return '';
  }
}

export async function dashboardPlugin(fastify: FastifyInstance, opts: { db: Pool; redis?: Redis }) {
  const { db, redis } = opts;
  await ensurePlanLimitSchema(db);
  await db.query(`
    CREATE TABLE IF NOT EXISTS policy_versions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      agent_id TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      changed_by TEXT,
      change_reason TEXT,
      snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      status TEXT NOT NULL DEFAULT 'active',
      owner_email TEXT,
      approved_by TEXT,
      approved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_policy_versions_tenant ON policy_versions(tenant_id, agent_id, version DESC)`).catch(() => {});
  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_action_log (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      actor_email TEXT,
      actor_role TEXT,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_admin_action_tenant_time ON admin_action_log(tenant_id, created_at DESC)`).catch(() => {});
  await db.query(`ALTER TABLE agent_tokens ADD COLUMN IF NOT EXISTS scopes TEXT[] DEFAULT ARRAY[]::TEXT[]`).catch(() => {});
  await db.query(`ALTER TABLE agent_tokens ADD COLUMN IF NOT EXISTS created_by TEXT`).catch(() => {});
  await db.query(`ALTER TABLE agent_tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`).catch(() => {});
  await db.query(`ALTER TABLE agent_tokens ADD COLUMN IF NOT EXISTS revoked_by TEXT`).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_agent_tokens_tenant_active ON agent_tokens(tenant_id, active, created_at DESC)`).catch(() => {});

  // Serve combined UI (user + admin switcher)
  fastify.get('/dashboard', async (req, reply) => {
    try {
      const html = readFileSync(join(__dirname, 'combined.html'), 'utf-8')
        .replace(
          '__LOCAL_DEV_ADMIN_SECRET__',
          process.env.NODE_ENV === 'production' ? '' : (process.env.ADMIN_SECRET || '')
        )
        .replace(
          '__ALLOW_LOCAL_TENANT_FALLBACK__',
          process.env.NODE_ENV === 'production' ? 'false' : 'true'
        );
      reply
        .header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
        .header('Pragma', 'no-cache')
        .header('Expires', '0')
        .type('text/html')
        .send(html);
    } catch {
      reply.type('text/html').send('<h2>Dashboard not found. Run npm run build first.</h2>');
    }
  });

  // Metrics API
  fastify.get('/api/dashboard/metrics', async (req: any) => {
    const tenantId = req.headers['x-tenant-id'];
    const base = tenantId ? 'WHERE tenant_id=$1' : 'WHERE 1=1';
    const params = tenantId ? [tenantId] : [];

    const [summary, topTools, topAgents, recentDenials, hourly] = await Promise.all([
      db.query(`SELECT
        COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '1h') AS calls_1h,
        COUNT(*) FILTER (WHERE decision='DENY' AND created_at > NOW()-INTERVAL '1h') AS denials_1h,
        COUNT(*) FILTER (WHERE created_at > NOW()-INTERVAL '24h') AS calls_24h,
        COUNT(*) FILTER (WHERE decision='DENY' AND created_at > NOW()-INTERVAL '24h') AS denials_24h,
        COUNT(DISTINCT agent_id) FILTER (WHERE created_at > NOW()-INTERVAL '1h') AS active_agents,
        AVG(execution_time_ms) FILTER (WHERE created_at > NOW()-INTERVAL '1h') AS avg_latency_ms
        FROM audit_log ${base}`, params),
      db.query(`SELECT tool_name, COUNT(*) as total,
        COUNT(*) FILTER (WHERE decision='ALLOW') as allowed,
        COUNT(*) FILTER (WHERE decision='DENY') as denied
        FROM audit_log ${base} AND created_at > NOW()-INTERVAL '24h'
        GROUP BY tool_name ORDER BY total DESC LIMIT 10`, params),
      db.query(`SELECT a.agent_id, COUNT(*) as total_calls,
        COUNT(*) FILTER (WHERE a.decision='DENY') as denials,
        MAX(a.created_at) as last_seen,
        COALESCE(bool_and(t.active), true) as active
        FROM audit_log a
        LEFT JOIN agent_tokens t ON a.agent_id = t.agent_id AND a.tenant_id = t.tenant_id
        ${base.replace('tenant_id', 'a.tenant_id')} AND a.created_at > NOW()-INTERVAL '24h'
        GROUP BY a.agent_id ORDER BY total_calls DESC LIMIT 10`, params),
      db.query(`SELECT agent_id, tool_name, reason, created_at
        FROM audit_log ${base} AND decision='DENY'
        ORDER BY created_at DESC LIMIT 20`, params),
      db.query(`SELECT DATE_TRUNC('hour', created_at) as hour,
        COUNT(*) as calls,
        COUNT(*) FILTER (WHERE decision='DENY') as denials
        FROM audit_log ${base} AND created_at > NOW()-INTERVAL '24h'
        GROUP BY hour ORDER BY hour ASC`, params),
    ]);

    return {
      summary: summary.rows[0],
      topTools: topTools.rows,
      topAgents: topAgents.rows,
      recentDenials: recentDenials.rows,
      hourly: hourly.rows,
    };
  });

  // Audit log API
  fastify.get('/api/dashboard/audit', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const q = req.query || {};
    const where = ['tenant_id=$1'];
    const params: any[] = [tenantId];
    const add = (sql: string, value: any) => {
      params.push(value);
      where.push(sql.replace('?', `$${params.length}`));
    };
    if (q.agentId) add('agent_id=?', q.agentId);
    if (q.toolName) add('tool_name=?', q.toolName);
    if (q.decision) add('decision=?', String(q.decision).toUpperCase());
    if (q.userId) add('user_id=?', q.userId);
    if (q.sessionId) add('session_id=?', q.sessionId);
    if (q.sinceHours) add(`created_at > NOW()-(?::int * INTERVAL '1 hour')`, asInt(q.sinceHours, 24, 1, 8760));
    const limit = asInt(q.limit, 100, 1, 500);
    params.push(limit);
    const r = await db.query(
      `SELECT id, agent_id, tool_name, decision, reason, created_at, execution_time_ms, auth_provider,
              user_id, session_id, conversation_id, request_id, user_command, tool_arguments, response_summary
       FROM audit_log WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT $${params.length}`,
      params
    );
    return { logs: r.rows };
  });

  fastify.get('/api/dashboard/audit/export', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'export_audit')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const limit = asInt(req.query?.limit, 1000, 1, 5000);
    const days = asInt(req.query?.days, 30, 1, 365);
    try {
      await enforceMaxValue(db, {
        tenantId,
        featureKey: 'audit_export_days',
        requested: days,
        action: 'audit.export',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }
    const r = await db.query(
      `SELECT created_at, agent_id, tool_name, decision, reason, user_id, session_id,
              user_command, tool_arguments, response_summary
       FROM audit_log WHERE tenant_id=$1 AND created_at > NOW() - ($2 || ' days')::interval ORDER BY created_at DESC LIMIT $3`,
      [tenantId, days, limit]
    );
    const header = ['created_at','agent_id','tool_name','decision','reason','user_id','session_id','user_command','tool_arguments','response_summary'];
    const csv = [header.join(','), ...r.rows.map(row => header.map(k => csvEscape(row[k])).join(','))].join('\n');
    await auditAdminAction(db, req, 'audit.export', 'audit_log', { rows: r.rows.length, limit, days });
    return reply.header('Content-Type', 'text/csv').send(csv);
  });

  fastify.get('/api/plan-limits/usage', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const [{ plan, limits }, usage, blocked] = await Promise.all([
      getPlanLimits(db, tenantId),
      getPlanUsage(db, tenantId),
      db.query(
        `SELECT feature_key, action, message, used, limit_value, actor_email, created_at
         FROM plan_limit_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 25`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
    ]);
    return { plan, limits, usage, blockedActions: blocked.rows };
  });

  fastify.put('/api/plan-limits/overrides', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_team')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const featureKey = String(req.body?.featureKey || '');
    const limitValue = parseInt(req.body?.limitValue, 10);
    const allowed = ['alert_channels','alert_rules','agents','integrations','audit_export_days','analytics_export_days','retention_days','team_members','ml_profiles','hitl_policies'];
    if (!allowed.includes(featureKey) || !Number.isFinite(limitValue) || limitValue < 0) {
      return reply.code(400).send({ error: 'Valid featureKey and non-negative limitValue required' });
    }
    await db.query(
      `INSERT INTO tenant_limit_overrides (tenant_id, feature_key, limit_value, updated_by, updated_at)
       VALUES ($1,$2,$3,$4,NOW())
       ON CONFLICT (tenant_id, feature_key)
       DO UPDATE SET limit_value=$3, updated_by=$4, updated_at=NOW()`,
      [tenantId, featureKey, limitValue, String(req.headers['x-admin-email'] || 'local-admin')]
    );
    await auditAdminAction(db, req, 'plan_limits.override', `limit:${featureKey}`, { limitValue });
    return { saved: true, featureKey, limitValue };
  });

  fastify.delete('/api/plan-limits/overrides/:featureKey', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_team')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const featureKey = String(req.params?.featureKey || '');
    await db.query(
      `DELETE FROM tenant_limit_overrides WHERE tenant_id=$1 AND feature_key=$2`,
      [tenantId, featureKey]
    );
    await auditAdminAction(db, req, 'plan_limits.override.delete', `limit:${featureKey}`, {});
    return { deleted: true, featureKey };
  });

  fastify.post('/api/audit/redaction-preview', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const input = typeof req.body?.text === 'string' ? req.body.text : JSON.stringify(req.body || {});
    return { redacted: redactPreview(input), changed: redactPreview(input) !== input };
  });

  fastify.get('/api/audit/retention-status', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const r = await db.query(
      `SELECT
         (SELECT COUNT(*)::int FROM audit_log WHERE tenant_id=$1) AS audit_rows,
         (SELECT MIN(created_at) FROM audit_log WHERE tenant_id=$1) AS oldest_audit,
         (SELECT COUNT(*)::int FROM audit_log WHERE tenant_id=$1 AND user_command IS NOT NULL) AS prompt_detail_rows,
         COALESCE((SELECT audit_log_days FROM retention_policies WHERE tenant_id=$1), 90) AS audit_log_days,
         COALESCE((SELECT retention_days FROM prompt_audit_settings WHERE tenant_id=$1), 30) AS prompt_detail_days`,
      [tenantId]
    );
    return { status: r.rows[0] };
  });

  fastify.get('/api/audit/hash-chain/verify', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    try {
      return await verifyHashChain(db, tenantId, asInt(req.query?.limit, 10000, 1, 100000));
    } catch (err: any) {
      return { valid: false, totalChecked: 0, detail: err.message || 'Hash-chain verification unavailable' };
    }
  });

  fastify.get('/api/prompt-audit/settings', async (req: any, reply) => {
    const tenantId = req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    await db.query(
      `INSERT INTO prompt_audit_settings (tenant_id, mode, retention_days)
       VALUES ($1, 'SUMMARY_ONLY', 30) ON CONFLICT DO NOTHING`,
      [tenantId]
    );
    const r = await db.query(
      `SELECT tenant_id, mode, retention_days, updated_at
       FROM prompt_audit_settings WHERE tenant_id=$1`,
      [tenantId]
    );
    return { settings: r.rows[0] };
  });

  fastify.put('/api/prompt-audit/settings', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_policies')) return;
    const tenantId = req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const { mode, retentionDays } = req.body || {};
    const allowedModes = ['OFF', 'SUMMARY_ONLY', 'FULL_REDACTED', 'FULL_RAW'];
    if (!allowedModes.includes(mode)) {
      return reply.code(400).send({ error: 'Invalid mode' });
    }
    const days = Math.max(1, Math.min(365, parseInt(retentionDays, 10) || 30));
    try {
      await enforceMaxValue(db, {
        tenantId,
        featureKey: 'retention_days',
        requested: days,
        action: 'prompt_audit.retention.update',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }
    const r = await db.query(
      `INSERT INTO prompt_audit_settings (tenant_id, mode, retention_days, updated_at)
       VALUES ($1,$2,$3,NOW())
       ON CONFLICT (tenant_id)
       DO UPDATE SET mode=$2, retention_days=$3, updated_at=NOW()
       RETURNING tenant_id, mode, retention_days, updated_at`,
      [tenantId, mode, days]
    );
    if (mode === 'OFF') {
      await db.query(
        `UPDATE audit_log
         SET user_command=NULL, tool_arguments=NULL, response_summary=NULL
         WHERE tenant_id=$1`,
        [tenantId]
      );
    }
    await auditAdminAction(db, req, 'prompt_audit.update_settings', 'prompt_audit_settings', { mode, retentionDays: days });
    return { settings: r.rows[0] };
  });

  fastify.get('/api/ml/agents', async (req: any, reply) => {
    const tenantId = req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const r = await db.query(
      `SELECT agent_id, sample_size, built_at
       FROM agent_ml_profiles
       WHERE tenant_id=$1
       ORDER BY built_at DESC`,
      [tenantId]
    );
    return { agents: r.rows };
  });

  fastify.get('/api/ml/profile', async (req: any, reply) => {
    const tenantId = req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const agentId = req.query?.agentId;
    if (!agentId) {
      const r = await db.query(
        `SELECT agent_id, sample_size, built_at
         FROM agent_ml_profiles
         WHERE tenant_id=$1
         ORDER BY built_at DESC LIMIT 20`,
        [tenantId]
      );
      return { agents: r.rows };
    }

    const profileR = await db.query(
      `SELECT profile_json, built_at, sample_size
       FROM agent_ml_profiles
       WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    if (!profileR.rows.length) return reply.code(404).send({ error: 'ML profile not found' });

    const profile = typeof profileR.rows[0].profile_json === 'string'
      ? JSON.parse(profileR.rows[0].profile_json)
      : profileR.rows[0].profile_json;
    const topTools = Object.entries(profile.toolProfiles || {})
      .sort((a: any, b: any) => (b[1].callCount || 0) - (a[1].callCount || 0))
      .slice(0, 5)
      .map(([name]) => name);
    const eventsR = await db.query(
      `SELECT id, tool_name, score, confidence, action, reasons_json, created_at
       FROM anomaly_events
       WHERE tenant_id=$1 AND agent_id=$2
       ORDER BY created_at DESC LIMIT 20`,
      [tenantId, agentId]
    );
    return {
      agentId,
      builtAt: profileR.rows[0].built_at,
      sampleSize: profileR.rows[0].sample_size,
      profile: {
        ...profile,
        sampleSize: profileR.rows[0].sample_size,
        topTools,
      },
      events: eventsR.rows,
    };
  });

  fastify.post('/api/ml/events/:id/feedback', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_ml')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const eventId = req.params?.id;
    const { falsePositive, note } = req.body || {};
    if (typeof falsePositive !== 'boolean') return reply.code(400).send({ error: 'falsePositive boolean required' });
    const updated = await db.query(
      `UPDATE anomaly_events
       SET human_feedback=$1, feedback_note=$2, feedback_at=NOW()
       WHERE id=$3 AND tenant_id=$4
       RETURNING id, agent_id, tool_name, human_feedback`,
      [!falsePositive, note || null, eventId, tenantId]
    );
    if (!updated.rows.length) return reply.code(404).send({ error: 'Anomaly event not found' });
    await db.query(
      `INSERT INTO anomaly_feedback_log (tenant_id, event_id, was_false_positive, note)
       VALUES ($1,$2,$3,$4)`,
      [tenantId, eventId, falsePositive, note || null]
    );
    await auditAdminAction(db, req, 'ml.feedback', `anomaly_event:${eventId}`, { falsePositive, note: note || null });
    return { recorded: true, event: updated.rows[0] };
  });

  fastify.get('/api/ml/feedback/stats', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const r = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE was_false_positive=TRUE)::int AS false_positives,
         COUNT(*) FILTER (WHERE was_false_positive=FALSE)::int AS true_positives,
         COUNT(*)::int AS total_reviewed,
         ROUND(100.0 * COUNT(*) FILTER (WHERE was_false_positive=TRUE) / NULLIF(COUNT(*),0), 1) AS fp_rate_pct
       FROM anomaly_feedback_log
       WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30 days'`,
      [tenantId]
    );
    return { stats: r.rows[0] };
  });

  fastify.put('/api/ml/agents/:agentId/sensitivity', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_ml')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const agentId = req.params?.agentId;
    const sensitivity = String(req.body?.sensitivity || 'normal');
    if (!['low', 'normal', 'high'].includes(sensitivity)) return reply.code(400).send({ error: 'sensitivity must be low, normal, or high' });
    const r = await db.query(
      `UPDATE agent_ml_profiles
       SET profile_json=jsonb_set(COALESCE(profile_json,'{}'::jsonb), '{enterprise,sensitivity}', to_jsonb($3::text), true)
       WHERE tenant_id=$1 AND agent_id=$2
       RETURNING agent_id, profile_json`,
      [tenantId, agentId, sensitivity]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'ML profile not found' });
    await auditAdminAction(db, req, 'ml.update_sensitivity', `agent:${agentId}`, { sensitivity });
    return { saved: true, agentId, sensitivity };
  });

  fastify.post('/api/ml/agents/:agentId/reset-baseline', async (req: any, reply) => {
    if (!requireCapability(req, reply, 'manage_ml')) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const agentId = req.params?.agentId;
    const deleted = await db.query(
      `DELETE FROM agent_ml_profiles WHERE tenant_id=$1 AND agent_id=$2 RETURNING agent_id`,
      [tenantId, agentId]
    );
    await db.query(
      `UPDATE anomaly_events
       SET feedback_note=COALESCE(feedback_note,'') || CASE WHEN feedback_note IS NULL OR feedback_note='' THEN '' ELSE '; ' END || 'baseline reset requested'
       WHERE tenant_id=$1 AND agent_id=$2 AND created_at > NOW()-INTERVAL '24 hours'`,
      [tenantId, agentId]
    ).catch(() => {});
    await auditAdminAction(db, req, 'ml.reset_baseline', `agent:${agentId}`, { removedProfile: deleted.rowCount || 0 });
    return { reset: true, agentId, removedProfile: deleted.rowCount || 0, note: 'Profile removed. It will be rebuilt from fresh audit history on next rebuild.' };
  });

  fastify.get('/api/tool-registry/enterprise', async (req: any, reply) => {
    tenantIdFrom(req); // endpoint is global registry, but keep same header contract for dashboards
    const r = await db.query(
      `SELECT id, name, version, trust_level, trust_score, total_calls, denial_rate,
              reported_vulns, last_seen, verified, active, tools, owner_email, owner_team,
              allowed_tenants, allowed_agents, schema_validation, last_reviewed_at, last_reviewed_by
       FROM registry_servers
       ORDER BY trust_score DESC, last_seen DESC LIMIT 100`
    );
    return {
      tools: r.rows.map(row => ({
        ...row,
        owner: row.owner_email || row.owner_team || 'unassigned',
        ownerEmail: row.owner_email || null,
        ownerTeam: row.owner_team || null,
        lastReviewed: row.last_reviewed_at || row.last_seen,
        schemaValidation: row.schema_validation || (Array.isArray(row.tools) && row.tools.length ? 'available' : 'missing'),
        allowedTenantCount: Array.isArray(row.allowed_tenants) ? row.allowed_tenants.length : 0,
        allowedAgentCount: Array.isArray(row.allowed_agents) ? row.allowed_agents.length : 0,
      })),
    };
  });

  fastify.get('/api/ops/readiness', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const [alerts, webhooks, audit, hitl, dlp] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS sent_24h FROM alert_log WHERE tenant_id=$1 AND sent_at > NOW()-INTERVAL '24 hours'`, [tenantId]),
      db.query(`SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE success=false)::int AS failed
        FROM webhook_deliveries WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '7 days'`, [tenantId]).catch(() => ({ rows: [{ total: 0, failed: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS rows_24h FROM audit_log WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '24 hours'`, [tenantId]),
      db.query(`SELECT COUNT(*) FILTER (WHERE decision IS NULL)::int AS pending FROM hitl_approvals WHERE tenant_id=$1`, [tenantId]).catch(() => ({ rows: [{ pending: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS blocked_7d FROM dlp_events WHERE tenant_id=$1 AND blocked=true AND created_at > NOW()-INTERVAL '7 days'`, [tenantId]).catch(() => ({ rows: [{ blocked_7d: 0 }] })),
    ]);
    return {
      status: 'ok',
      checks: {
        alerts24h: alerts.rows[0].sent_24h,
        webhookDeliveries7d: webhooks.rows[0],
        auditRows24h: audit.rows[0].rows_24h,
        pendingApprovals: hitl.rows[0].pending,
        dlpBlocked7d: dlp.rows[0].blocked_7d,
      },
    };
  });

  fastify.get('/api/rbac/capabilities', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const email = req.headers['x-admin-email'];
    const roleR = email
      ? await db.query(`SELECT role FROM admin_members WHERE tenant_id=$1 AND email=$2 AND active=true`, [tenantId, email])
      : { rows: [] };
    const role = roleR.rows[0]?.role || roleFrom(req);
    return { role, capabilities: ROLE_CAPABILITIES[role] || ROLE_CAPABILITIES.viewer };
  });

  fastify.get('/api/connect/status', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const [agents, lastAudit, lastActions] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS count FROM agent_tokens WHERE tenant_id=$1 AND active=true`, [tenantId]),
      db.query(`SELECT agent_id, tool_name, decision, reason, created_at FROM audit_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 1`, [tenantId]).catch(() => ({ rows: [] })),
      db.query(
        `SELECT action, actor_email, details_json, created_at
         FROM admin_action_log
         WHERE tenant_id=$1 AND action IN ('connect.configure_mcp_server','connect.test_upstream')
         ORDER BY created_at DESC
         LIMIT 5`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
    ]);
    const tenantResult = await db.query(`SELECT metadata FROM tenants WHERE id=$1`, [tenantId]);
    const metadata = tenantResult.rows[0]?.metadata || {};
    const upstreamUrl = metadata.mcpServerUrl || process.env.MCP_SERVER_URL || '';
    const upstreamName = metadata.mcpServerName || process.env.MCP_SERVER_NAME || 'Primary MCP server';
    const upstreamOwner = metadata.mcpServerOwner || process.env.MCP_SERVER_OWNER || '';
    const upstreamEnvironment = metadata.mcpServerEnvironment || process.env.MCP_SERVER_ENVIRONMENT || 'dev';
    const upstreamScope = metadata.mcpServerScope || process.env.MCP_SERVER_SCOPE || 'default';
    const upstreamAuthMode = metadata.mcpServerAuthMode || process.env.MCP_SERVER_AUTH_MODE || (metadata.mcpProxyAuthToken || process.env.MCP_PROXY_AUTH_TOKEN ? 'bearer' : 'none');
    const hasProxyToken = Boolean(metadata.mcpProxyAuthToken || process.env.MCP_PROXY_AUTH_TOKEN);
    const lastTest = lastActions.rows.find((row: any) => row.action === 'connect.test_upstream') || null;
    const lastConfig = lastActions.rows.find((row: any) => row.action === 'connect.configure_mcp_server') || null;
    return {
      gatewayUrl: 'http://localhost:3000/mcp',
      tenantId,
      activeAgents: agents.rows[0]?.count || 0,
      upstream: {
        configured: Boolean(upstreamUrl),
        url: upstreamUrl ? safePublicUrl(upstreamUrl) : '',
        name: upstreamName,
        owner: upstreamOwner,
        environment: upstreamEnvironment,
        scope: upstreamScope,
        authMode: upstreamAuthMode,
        hasProxyToken,
        routingMode: 'single_active_upstream',
        lastConfiguredAt: lastConfig?.created_at || null,
        lastConfiguredBy: lastConfig?.actor_email || null,
        lastTest: lastTest ? {
          ok: Boolean(lastTest.details_json?.ok),
          status: lastTest.details_json?.status || null,
          error: lastTest.details_json?.error || null,
          testedAt: lastTest.created_at,
          testedBy: lastTest.actor_email,
        } : null,
      },
      lastCall: lastAudit.rows[0] || null,
      nextSteps: [
        'Connect MCP server behind the gateway',
        'Create agent token',
        'Put gateway URL and token in external agent',
        'Test tools/list through gateway',
      ],
    };
  });

  fastify.post('/api/connect/mcp-server', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    if (!requireCapability(req, reply, 'configure_integrations')) return;
    const body = req.body || {};
    const url = String(body.url || '').trim();
    const token = String(body.token || '').trim();
    const name = String(body.name || 'Primary MCP server').trim().slice(0, 120);
    const owner = String(body.owner || '').trim().slice(0, 160);
    const environment = String(body.environment || 'dev').trim().slice(0, 40);
    const scope = String(body.scope || 'default').trim().slice(0, 120);
    const authMode = String(body.authMode || (token ? 'bearer' : 'none')).trim().slice(0, 40);
    let parsed: URL;
    try {
      parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('invalid protocol');
    } catch {
      return reply.code(400).send({ error: 'Invalid MCP server URL. Use http://host:port/mcp or https://host/mcp' });
    }
    const tenantResult = await db.query(`SELECT metadata FROM tenants WHERE id=$1`, [tenantId]);
    const existingMetadata = tenantResult.rows[0]?.metadata || {};
    const updatedMetadata = {
      ...existingMetadata,
      mcpServerUrl: parsed.toString(),
      mcpProxyAuthToken: token ? encryptValue(token) : existingMetadata.mcpProxyAuthToken || undefined,
      mcpServerName: name || 'Primary MCP server',
      mcpServerOwner: owner || undefined,
      mcpServerEnvironment: environment || 'dev',
      mcpServerScope: scope || 'default',
      mcpServerAuthMode: authMode || (token || existingMetadata.mcpProxyAuthToken ? 'bearer' : 'none'),
    };
    await db.query(
      `UPDATE tenants SET metadata=$1, updated_at=NOW() WHERE id=$2`,
      [JSON.stringify(updatedMetadata), tenantId]
    );
    if (redis) {
      await redis.del(`tenant:${tenantId}`).catch(() => {});
    }
    await auditAdminAction(db, req, 'connect.configure_mcp_server', 'mcp_upstream', {
      url: safePublicUrl(parsed.toString()),
      name,
      owner,
      environment,
      scope,
      authMode,
      tokenConfigured: Boolean(token || updatedMetadata.mcpProxyAuthToken),
    });
    return {
      configured: true,
      upstream: {
        url: safePublicUrl(parsed.toString()),
        name,
        owner,
        environment,
        scope,
        authMode,
        hasProxyToken: Boolean(token || updatedMetadata.mcpProxyAuthToken),
      },
      message: 'Gateway will forward approved /mcp calls to this MCP server.',
    };
  });

  fastify.post('/api/connect/test-upstream', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const tenantResult = await db.query(`SELECT metadata FROM tenants WHERE id=$1`, [tenantId]);
    const metadata = tenantResult.rows[0]?.metadata || {};
    const url = metadata.mcpServerUrl || process.env.MCP_SERVER_URL;
    if (!url) return reply.code(400).send({ error: 'MCP server URL is not configured' });
    const token = metadata.mcpProxyAuthToken ? decryptValue(metadata.mcpProxyAuthToken) : process.env.MCP_PROXY_AUTH_TOKEN;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json', 'X-Forwarded-By': 'mcp-security-gateway' };
      if (token) headers['X-MCP-Proxy-Auth'] = `Bearer ${token}`;
      const r = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ jsonrpc: '2.0', id: `dashboard-test-${Date.now()}`, method: 'tools/list', params: {} }),
        signal: controller.signal,
      });
      const text = await r.text();
      clearTimeout(timer);
      await auditAdminAction(db, req, 'connect.test_upstream', 'mcp_upstream', { ok: r.ok, status: r.status });
      return {
        ok: r.ok,
        status: r.status,
        upstreamUrl: safePublicUrl(url),
        responsePreview: text.slice(0, 600),
      };
    } catch (err: any) {
      clearTimeout(timer);
      await auditAdminAction(db, req, 'connect.test_upstream', 'mcp_upstream', { ok: false, error: err?.message || 'failed' });
      return reply.code(502).send({ ok: false, error: err?.message || 'Could not reach MCP server', upstreamUrl: safePublicUrl(url) });
    }
  });

  fastify.get('/api/agents', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    if (!requireCapability(req, reply, 'view_audit')) return;

    const r = await db.query(
      `SELECT
         t.agent_id,
         t.description,
         t.active,
         t.scopes,
         t.created_at,
         t.last_seen,
         t.expires_at,
         t.created_by,
         COALESCE(a.total_calls,0)::int AS total_calls,
         COALESCE(a.denied,0)::int AS denied,
         a.last_active
       FROM agent_tokens t
       LEFT JOIN (
         SELECT agent_id,
           COUNT(*)::int AS total_calls,
           COUNT(*) FILTER (WHERE decision='DENY')::int AS denied,
           MAX(created_at) AS last_active
         FROM audit_log
         WHERE tenant_id=$1
         GROUP BY agent_id
       ) a ON a.agent_id=t.agent_id
       WHERE t.tenant_id=$1 AND t.active=true
       ORDER BY COALESCE(a.last_active,t.created_at) DESC`,
      [tenantId]
    );

    return {
      agents: r.rows.map((row: any) => {
        const total = Number(row.total_calls || 0);
        const denied = Number(row.denied || 0);
        const denialPct = total > 0 ? Math.round((denied / total) * 100) : 0;
        return {
          agentId: row.agent_id,
          description: row.description || '',
          active: row.active,
          scopes: row.scopes || [],
          createdAt: row.created_at,
          lastSeen: row.last_seen,
          expiresAt: row.expires_at,
          createdBy: row.created_by || 'dashboard',
          totalCalls: total,
          denied,
          denialPct,
          lastActive: row.last_active || row.last_seen,
          risk: classifyAgentRisk(total, denialPct, row.last_active || row.last_seen),
        };
      }),
    };
  });

  fastify.post('/api/agents', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    if (!requireCapability(req, reply, 'manage_agents')) return;

    try {
      const usage = await getPlanUsage(db, tenantId);
      await enforcePlanLimit(db, {
        tenantId,
        featureKey: 'agents',
        used: usage.agents || 0,
        action: 'agents.create_token',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err) {
      if (err instanceof PlanLimitError) return reply.code(403).send(planLimitErrorPayload(err));
      throw err;
    }

    const body = req.body || {};
    const suppliedAgentId = safeAgentId(body.agentId);
    const agentId = suppliedAgentId || `agent_${crypto.randomBytes(6).toString('hex')}`;
    const description = String(body.description || 'Dashboard-created agent token').trim().slice(0, 240);
    const scopes = Array.isArray(body.scopes) ? body.scopes.map((s: any) => String(s).trim()).filter(Boolean).slice(0, 20) : ['mcp:call'];
    const rawToken = `mcpsg_${crypto.randomBytes(32).toString('hex')}`;
    const tokenHash = await bcrypt.hash(rawToken, 12);
    const actor = String(req.headers['x-admin-email'] || req.user?.email || 'local-admin');

    try {
      const created = await db.query(
        `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description, scopes, active, created_by)
         VALUES ($1,$2,$3,$4,$5,TRUE,$6)
         RETURNING agent_id, description, active, scopes, created_at, created_by`,
        [agentId, tenantId, tokenHash, description, scopes, actor]
      );
      await db.query(
        `INSERT INTO policies (agent_id, tenant_id, tool_name, action, priority, active, description)
         VALUES ($1,$2,'tools/list','allow',100,TRUE,'Bootstrap read-only MCP discovery allow')
         ON CONFLICT DO NOTHING`,
        [agentId, tenantId]
      ).catch(() => {});
      await auditAdminAction(db, req, 'agents.create_token', `agent:${agentId}`, {
        description,
        scopes,
        tokenShownOnce: true,
      });
      return reply.code(201).send({
        created: true,
        agent: {
          agentId: created.rows[0].agent_id,
          description: created.rows[0].description,
          active: created.rows[0].active,
          scopes: created.rows[0].scopes || [],
          createdAt: created.rows[0].created_at,
          createdBy: created.rows[0].created_by,
        },
        token: rawToken,
        warning: 'Copy this token now. The gateway stores only a hash and cannot show it again.',
      });
    } catch (err: any) {
      if (err?.code === '23505') return reply.code(409).send({ error: 'Agent ID already exists' });
      throw err;
    }
  });

  fastify.delete<{ Params: { agentId: string } }>('/api/agents/:agentId', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    if (!requireCapability(req, reply, 'manage_agents')) return;
    const agentId = safeAgentId(req.params.agentId);
    if (!agentId) return reply.code(400).send({ error: 'Invalid agent id' });
    const actor = String(req.headers['x-admin-email'] || req.user?.email || 'local-admin');
    const r = await db.query(
      `UPDATE agent_tokens
       SET active=false, revoked_at=NOW(), revoked_by=$3
       WHERE tenant_id=$1 AND agent_id=$2 AND active=true
       RETURNING agent_id`,
      [tenantId, agentId, actor]
    );
    if (!r.rowCount) return reply.code(404).send({ error: 'Active agent token not found' });
    await auditAdminAction(db, req, 'agents.revoke_token', `agent:${agentId}`, { revokedBy: actor });
    return { revoked: true, agentId };
  });

  fastify.get('/api/enterprise/readiness', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const [rules, alerts, approvals, auditRows, mlProfiles, retention, channels, admins, adminActions, hashCheck] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS count FROM alert_rules WHERE tenant_id=$1 AND active=true`, [tenantId]),
      db.query(`SELECT COUNT(*)::int AS count FROM alert_log WHERE tenant_id=$1`, [tenantId]),
      db.query(`SELECT COUNT(*)::int AS count FROM hitl_approvals WHERE tenant_id=$1`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS count FROM audit_log WHERE tenant_id=$1`, [tenantId]),
      db.query(`SELECT COUNT(*)::int AS count FROM agent_ml_profiles WHERE tenant_id=$1`, [tenantId]),
      db.query(`SELECT COUNT(*)::int AS count FROM retention_policies WHERE tenant_id=$1`, [tenantId]),
      db.query(`SELECT COUNT(*)::int AS count FROM alert_channel_configs WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS count FROM admin_members WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS count FROM admin_action_log WHERE tenant_id=$1`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
      verifyHashChain(db, tenantId, 5000).catch((err: any) => ({ valid: false, totalChecked: 0, detail: err.message || 'unavailable' })),
    ]);
    return {
      areas: {
        alertRules: { status: rules.rows[0].count > 0 ? 'partial' : 'needs_setup', evidence: `${rules.rows[0].count} active rules, ${alerts.rows[0].count} alerts logged` },
        humanApprovals: { status: approvals.rows[0].count > 0 ? 'partial' : 'needs_test', evidence: `${approvals.rows[0].count} approval records` },
        auditLog: { status: auditRows.rows[0].count > 0 && (hashCheck as any).valid ? 'working' : 'needs_traffic', evidence: `${auditRows.rows[0].count} audit rows, hash-chain valid=${Boolean((hashCheck as any).valid)}, admin actions=${adminActions.rows[0].count}` },
        mlAnomaly: { status: mlProfiles.rows[0].count > 0 ? 'working' : 'needs_profile', evidence: `${mlProfiles.rows[0].count} ML profiles, feedback/sensitivity/reset endpoints enabled` },
        integrations: { status: channels.rows[0].count > 0 ? 'partial' : 'needs_setup', evidence: `${channels.rows[0].count} configured alert channels` },
        retention: { status: retention.rows[0].count > 0 ? 'working' : 'default', evidence: `${retention.rows[0].count} custom retention policies` },
        rbac: { status: admins.rows[0].count > 0 ? 'partial' : 'local_admin_only', evidence: `${admins.rows[0].count} active admin members; backend capability gates enabled on sensitive dashboard APIs` },
        operations: { status: 'partial', evidence: 'health, readiness, alert log, webhook delivery counters enabled' },
      },
    };
  });

  // Per-agent stats
  fastify.get<{ Params: { agentId: string } }>('/api/dashboard/agent/:agentId', async (req) => {
    const { agentId } = req.params;
    const [calls, denials] = await Promise.all([
      db.query(`SELECT tool_name, COUNT(*) as count, AVG(execution_time_ms) as avg_ms
        FROM audit_log WHERE agent_id=$1 AND created_at > NOW()-INTERVAL '24h'
        GROUP BY tool_name ORDER BY count DESC`, [agentId]),
      db.query(`SELECT reason, COUNT(*) as count FROM audit_log
        WHERE agent_id=$1 AND decision='DENY' AND created_at > NOW()-INTERVAL '24h'
        GROUP BY reason ORDER BY count DESC`, [agentId]),
    ]);
    return { agentId, toolCalls: calls.rows, denialReasons: denials.rows };
  });
}
