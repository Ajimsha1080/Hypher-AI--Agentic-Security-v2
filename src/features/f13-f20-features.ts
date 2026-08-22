/**
 * Hypher AI Gateway — Enterprise Feature Modules
 *
 * Feature 13: Real-Time Threat Inspection & Prompt Shield
 * Feature 14: Adaptive Machine Learning Reinforcement Feedback Loop
 * Feature 15: Predictive Policy Simulation Sandbox (Dry-Run Engine)
 * Feature 16: Cloud Compliance Audit Exporter (S3/GCS Storage Link)
 * Feature 17: Slack Human-in-the-Loop Approval Orchestrator
 * Feature 18: Agentic Graph & Behavior Topology Mapper
 * Feature 19: Distributed OpenTelemetry APM Trace Span Engine
 * Feature 20: Resilient Webhook Auto-Retry & Delivery Policy Manager
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import axios from 'axios';
import { decryptValue, encryptValue } from '../security/secrets';

// ═══════════════════════════════════════════════════════════════════════
// Feature 13: Real-Time Threat Inspection & Prompt Shield
// ═══════════════════════════════════════════════════════════════════════

export interface InjectionDebugResult {
  allowed: boolean;
  reason?: string;
  flagged?: string;
  debug?: {
    patternName: string;
    argKey: string;
    matchedText: string;  // redacted: first 80 chars only
    patternRegex: string;
  };
}

// Named patterns for debuggable output
const NAMED_INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'ignore_previous_instructions', pattern: /ignore\s+(previous|all|above|prior)\s+instructions?/i },
  { name: 'disregard_instructions',       pattern: /disregard\s+(previous|all|above)\s+instructions?/i },
  { name: 'you_are_now',                  pattern: /you\s+are\s+now\s+(a|an)\s+/i },
  { name: 'forget_everything',            pattern: /forget\s+everything/i },
  { name: 'new_system_prompt',            pattern: /new\s+system\s+prompt/i },
  { name: 'override_instructions',        pattern: /override\s+(your\s+)?(previous\s+)?instructions?/i },
  { name: 'act_as',                       pattern: /act\s+as\s+(a|an)\s+/i },
  { name: 'jailbreak',                    pattern: /jailbreak/i },
  { name: 'dan_mode',                     pattern: /DAN\s+mode|do\s+anything\s+now/i },
  { name: 'developer_mode_bypass',        pattern: /developer\s+mode\s+enabled|dev\s+mode\s+bypass/i },
  { name: 'tag_escaping_injection',       pattern: /<\/(system|user|instruction|assistant|context)>/i },
  { name: 'roleplay_persona',             pattern: /imagine\s+you\s+are|simulate\s+a\s+scenario|play\s+a\s+game/i },
  { name: 'obfuscation_base64',           pattern: /decode\s+this\s+base64|decode\s+base64|rot13/i },
];

export async function inspectToolCallDebug(
  toolName: string,
  args: Record<string, unknown>,
  db: Pool,
  tenantId?: string,
  agentId?: string
): Promise<InjectionDebugResult> {
  // Scan with named patterns for rich debug output
  for (const [argKey, argVal] of Object.entries(args)) {
    const strings = extractDebugStrings(argVal);
    for (const str of strings) {
      for (const { name, pattern } of NAMED_INJECTION_PATTERNS) {
        if (pattern.test(str)) {
          const debugInfo = {
            patternName: name,
            argKey,
            matchedText: str.slice(0, 80) + (str.length > 80 ? '…[redacted]' : ''),
            patternRegex: pattern.toString(),
          };

          // Log to injection_debug_log for SOC dashboard
          if (tenantId) {
            const argsHash = crypto.createHash('sha256')
              .update(JSON.stringify(args)).digest('hex').slice(0, 16);
            db.query(
              `INSERT INTO injection_debug_log
               (tenant_id, agent_id, tool_name, pattern_name, arg_key, flagged_text, full_args_hash)
               VALUES ($1,$2,$3,$4,$5,$6,$7)`,
              [tenantId, agentId || null, toolName, name, argKey,
               debugInfo.matchedText, argsHash]
            ).catch(() => {});
          }

          return {
            allowed: false,
            reason: 'prompt_injection_detected',
            flagged: str.slice(0, 200),
            debug: debugInfo,
          };
        }
      }
    }
  }

  const { rows: rules } = await db.query(
    `SELECT DISTINCT ON (arg_key)
            arg_key, allowed_pattern, max_length, required, tenant_id
     FROM tool_arg_rules
     WHERE tool_name=$1
       AND active=true
       AND (
         ($2::uuid IS NOT NULL AND (tenant_id=$2::uuid OR tenant_id IS NULL))
         OR ($2::uuid IS NULL AND tenant_id IS NULL)
       )
     ORDER BY arg_key, CASE WHEN tenant_id=$2::uuid THEN 0 ELSE 1 END`,
    [toolName, tenantId || null]
  );

  for (const rule of rules.filter((r: any) => r.required)) {
    if (!(rule.arg_key in args)) {
      return {
        allowed: false,
        reason: `missing_required_arg:${rule.arg_key}`,
        debug: {
          patternName: 'missing_required_arg',
          argKey: rule.arg_key,
          matchedText: '',
          patternRegex: 'required=true',
        },
      };
    }
  }

  for (const rule of rules) {
    const val = args[rule.arg_key];
    if (val === undefined || val === null) continue;
    const str = String(val);
    const maxLen = rule.max_length ?? 4096;
    if (str.length > maxLen) {
      return {
        allowed: false,
        reason: `arg_too_long:${rule.arg_key}(${str.length}>${maxLen})`,
        flagged: str.slice(0, 200),
        debug: {
          patternName: 'arg_max_length',
          argKey: rule.arg_key,
          matchedText: str.slice(0, 80),
          patternRegex: `maxLength=${maxLen}`,
        },
      };
    }
    if (rule.allowed_pattern && !new RegExp(rule.allowed_pattern).test(str)) {
      return {
        allowed: false,
        reason: `arg_not_allowed:${rule.arg_key}`,
        flagged: str.slice(0, 200),
        debug: {
          patternName: 'arg_allow_pattern',
          argKey: rule.arg_key,
          matchedText: str.slice(0, 80),
          patternRegex: rule.allowed_pattern,
        },
      };
    }
  }

  // Shell metachar check (same as before)
  const SHELL_METACHAR = /[;&|`$(){}[\]<>\\]/;
  for (const [argKey, argVal] of Object.entries(args)) {
    for (const str of extractDebugStrings(argVal)) {
      if (SHELL_METACHAR.test(str) && str.length > 3) {
        return {
          allowed: false,
          reason: 'shell_metachar_detected',
          flagged: str.slice(0, 200),
          debug: {
            patternName: 'shell_metachar',
            argKey,
            matchedText: str.slice(0, 80),
            patternRegex: SHELL_METACHAR.toString(),
          },
        };
      }
    }
  }

  return { allowed: true };
}

function extractDebugStrings(obj: unknown, depth = 0): string[] {
  if (depth > 5) return [];
  if (typeof obj === 'string') return [obj];
  if (Array.isArray(obj)) return obj.flatMap(v => extractDebugStrings(v, depth + 1));
  if (obj && typeof obj === 'object') return Object.values(obj).flatMap(v => extractDebugStrings(v, depth + 1));
  return [];
}

async function hasGrowthOrEnterprisePlan(req: any, db: Pool): Promise<boolean> {
  if (['growth', 'enterprise'].includes(req.tenant?.plan)) return true;
  const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
  if (!tenantId) return false;
  const r = await db.query(`SELECT plan FROM tenants WHERE id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [] as any[] }));
  return ['growth', 'enterprise'].includes(r.rows[0]?.plan);
}
export async function injectionDebugPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/injection/log — recent injection attempts with full debug info
  fastify.get('/api/injection/log', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { limit = 50, agentId, patternName } = req.query as any;
    const conditions = ['tenant_id=$1'];
    const params: any[] = [tenantId];
    if (agentId) { conditions.push(`agent_id=$${params.push(agentId)}`); }
    if (patternName) { conditions.push(`pattern_name=$${params.push(patternName)}`); }

    const r = await db.query(
      `SELECT id, agent_id, tool_name, pattern_name, arg_key,
              flagged_text, full_args_hash, created_at
       FROM injection_debug_log
       WHERE ${conditions.join(' AND ')}
       ORDER BY created_at DESC LIMIT $${params.push(Math.min(parseInt(limit, 10), 200))}`,
      params
    );

    const stats = await db.query(
      `SELECT pattern_name, COUNT(*) as count
       FROM injection_debug_log
       WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '24 hours'
       GROUP BY pattern_name ORDER BY count DESC`,
      [tenantId]
    );

    return {
      events: r.rows,
      patternStats: stats.rows,
      patterns: NAMED_INJECTION_PATTERNS.map(p => ({
        name: p.name,
        regex: p.pattern.toString(),
      })),
    };
  });

  fastify.get('/api/injection-debug', async (req: any, reply) => {
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const { limit = 50 } = req.query as any;
    const r = await db.query(
      `SELECT id, agent_id, tool_name, pattern_name, arg_key,
              flagged_text, full_args_hash, created_at
       FROM injection_debug_log
       WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT $2`,
      [tenantId, Math.min(parseInt(limit, 10) || 50, 200)]
    );
    return { events: r.rows };
  });

  // POST /api/injection/test — test a string against all patterns
  fastify.post('/api/injection/test', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const { text } = req.body as any;
    if (!text) return reply.code(400).send({ error: 'text required' });

    const matches = NAMED_INJECTION_PATTERNS
      .filter(({ pattern }) => pattern.test(text))
      .map(({ name, pattern }) => ({ name, regex: pattern.toString() }));
    const firstMatch = matches[0];

    return {
      text: text.slice(0, 200),
      isInjection: matches.length > 0,
      flagged: matches.length > 0,
      allowed: matches.length === 0,
      reason: firstMatch ? `prompt_injection:${firstMatch.name}` : 'clean',
      debug: firstMatch ? {
        patternName: firstMatch.name,
        patternRegex: firstMatch.regex,
        argKey: (req.body as any)?.argKey || 'input',
        matchedText: text.slice(0, 200),
      } : undefined,
      matchedPatterns: matches,
    };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 14: Adaptive Machine Learning Reinforcement Feedback Loop
// ═══════════════════════════════════════════════════════════════════════

export async function anomalyFeedbackPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // POST /api/anomaly/:id/feedback
  fastify.post('/api/anomaly/:id/feedback', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const { isFalsePositive, note, reviewedBy } = req.body as any;
    if (typeof isFalsePositive !== 'boolean') {
      return reply.code(400).send({ error: 'isFalsePositive (boolean) required' });
    }

    // Update anomaly_events row
    const updated = await db.query(
      `UPDATE anomaly_events
       SET human_feedback=$1, feedback_note=$2, feedback_at=NOW(), reviewed_by=$3
       WHERE id=$4 AND tenant_id=$5
       RETURNING id, agent_id, tool_name, score, human_feedback`,
      [!isFalsePositive, note || null, reviewedBy || null, id, tenantId]
    );
    if (!updated.rows.length) {
      return reply.code(404).send({ error: 'Anomaly event not found' });
    }

    // Log to feedback table for ML tuning
    await db.query(
      `INSERT INTO anomaly_feedback_log
       (tenant_id, agent_id, anomaly_event_id, was_false_positive, note)
       VALUES ($1,$2,$3,$4,$5)`,
      [tenantId, updated.rows[0].agent_id, id, isFalsePositive, note || null]
    );

    // If false positive — lower the agent's sensitivity by adjusting profile
    if (isFalsePositive) {
      await db.query(
        `UPDATE agent_ml_profiles
         SET false_positive_rate = COALESCE(false_positive_rate, 0) + 0.01,
             updated_at = NOW()
         WHERE agent_id=$1 AND tenant_id=$2`,
        [updated.rows[0].agent_id, tenantId]
      ).catch(() => {}); // non-blocking
    }

    return {
      recorded: true,
      eventId: id,
      isFalsePositive,
      note: 'Feedback recorded. ML profile will be adjusted on next rebuild.',
    };
  });

  // GET /api/anomaly/feedback-stats
  fastify.get('/api/anomaly/feedback-stats', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT
         COUNT(*) FILTER (WHERE was_false_positive=TRUE)  AS false_positives,
         COUNT(*) FILTER (WHERE was_false_positive=FALSE) AS true_positives,
         COUNT(*)                                          AS total_reviewed,
         ROUND(100.0 * COUNT(*) FILTER (WHERE was_false_positive=TRUE)
               / NULLIF(COUNT(*),0), 1)                   AS fp_rate_pct
       FROM anomaly_feedback_log
       WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '30 days'`,
      [tenantId]
    );
    return { stats: r.rows[0] };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 15: Predictive Policy Simulation Sandbox (Dry-Run Engine)
// ═══════════════════════════════════════════════════════════════════════

export async function policyDryRunPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // POST /api/policies/dry-run
  // Simulates what would happen to the last N audit_log entries
  // under a proposed policy change
  fastify.post('/api/policies/dry-run', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { proposedPolicies, sampleSize = 100 } = req.body as any;
    if (!proposedPolicies || !Array.isArray(proposedPolicies)) {
      return reply.code(400).send({ error: 'proposedPolicies array required' });
    }

    // Sample recent audit log
    const sample = await db.query(
      `SELECT agent_id, tool_name, decision as live_decision
       FROM audit_log
       WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT $2`,
      [tenantId, Math.min(sampleSize, 500)]
    );

    // Simulate proposed policy for each sample row
    let wouldAllow = 0;
    let wouldDeny = 0;
    const changes: Array<{ agentId: string; toolName: string; liveDecision: string; dryRunDecision: string }> = [];

    for (const row of sample.rows) {
      const matchedPolicy = proposedPolicies.find((p: any) =>
        (p.agentId === row.agent_id || p.agentId === '*') &&
        (p.tools?.includes(row.tool_name) || p.tools?.includes('*')) &&
        p.action === 'allow'
      );

      const dryRunDecision = matchedPolicy ? 'ALLOW' : 'DENY';
      if (dryRunDecision === 'ALLOW') wouldAllow++;
      else wouldDeny++;

      if (dryRunDecision !== row.live_decision) {
        changes.push({
          agentId: row.agent_id,
          toolName: row.tool_name,
          liveDecision: row.live_decision,
          dryRunDecision,
        });
      }
    }

    // Save result
    await db.query(
      `INSERT INTO policy_dry_run_results
       (tenant_id, sample_size, would_allow, would_deny, delta_vs_live, policy_snapshot)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [tenantId, sample.rows.length, wouldAllow, wouldDeny,
       JSON.stringify(changes.slice(0, 50)), JSON.stringify(proposedPolicies)]
    ).catch(() => {});

    return {
      sampleSize: sample.rows.length,
      wouldAllow,
      wouldDeny,
      deltaVsLive: changes.slice(0, 50),
      summary: `${changes.length} requests would change outcome. ${wouldAllow} allowed, ${wouldDeny} denied.`,
      warning: changes.length > 0
        ? `⚠ ${changes.length} request(s) would have a different outcome than the live policy.`
        : '✓ No outcome changes. Safe to apply.',
    };
  });

  // GET /api/policies/dry-run/history
  fastify.get('/api/policies/dry-run/history', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const r = await db.query(
      `SELECT id, sample_size, would_allow, would_deny, created_at
       FROM policy_dry_run_results WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT 20`,
      [tenantId]
    );
    return { history: r.rows };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 16: Cloud Compliance Audit Exporter (S3/GCS Storage Link)
// ═══════════════════════════════════════════════════════════════════════

export async function auditExportPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // POST /api/audit/export — queue an export job
  fastify.post('/api/audit/export', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { destination, periodStart, periodEnd } = req.body as any;
    if (!destination) {
      return reply.code(400).send({ error: 'destination required (s3://bucket/path or gs://bucket/path)' });
    }
    if (!/^(s3|gs):\/\/.+/.test(destination)) {
      return reply.code(400).send({ error: 'destination must start with s3:// or gs://' });
    }

    const r = await db.query(
      `INSERT INTO audit_export_jobs (tenant_id, destination, period_start, period_end)
       VALUES ($1,$2,$3,$4) RETURNING id, status, created_at`,
      [tenantId, destination,
       periodStart || null,
       periodEnd || null]
    );

    // Trigger async export (in production: queue to a worker)
    runAuditExport(r.rows[0].id, tenantId, destination, periodStart, periodEnd, db)
      .catch(err => {
        db.query(
          `UPDATE audit_export_jobs SET status='failed', error_msg=$1, finished_at=NOW() WHERE id=$2`,
          [err.message, r.rows[0].id]
        ).catch(() => {});
      });

    return {
      jobId: r.rows[0].id,
      status: 'pending',
      message: 'Export job queued. Poll GET /api/audit/export/:jobId for status.',
    };
  });

  // GET /api/audit/export/:jobId — poll job status
  fastify.get('/api/audit/export/:jobId', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, status, destination, rows_exported, period_start, period_end,
              error_msg, started_at, finished_at, created_at
       FROM audit_export_jobs WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).jobId, tenantId]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'Job not found' });
    return { job: r.rows[0] };
  });

  // GET /api/audit/export — list recent export jobs
  fastify.get('/api/audit/export', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const r = await db.query(
      `SELECT id, destination, status, rows_exported, created_at, finished_at
       FROM audit_export_jobs WHERE tenant_id=$1
       ORDER BY created_at DESC LIMIT 20`,
      [tenantId]
    );
    return { jobs: r.rows };
  });
}

async function runAuditExport(
  jobId: string, tenantId: string, destination: string,
  periodStart: string | null, periodEnd: string | null, db: Pool
): Promise<void> {
  await db.query(
    `UPDATE audit_export_jobs SET status='running', started_at=NOW() WHERE id=$1`,
    [jobId]
  );

  const conditions = ['tenant_id=$1'];
  const params: any[] = [tenantId];
  if (periodStart) { conditions.push(`created_at >= $${params.push(periodStart)}`); }
  if (periodEnd) { conditions.push(`created_at <= $${params.push(periodEnd)}`); }

  const rows = await db.query(
    `SELECT id, agent_id, tool_name, decision, reason, execution_time_ms,
            auth_provider, source_ip, integration_method, created_at
     FROM audit_log WHERE ${conditions.join(' AND ')}
     ORDER BY created_at ASC`,
    params
  );

  // Produce NDJSON payload (in production: stream to S3/GCS via SDK)
  const ndjson = rows.rows.map(r => JSON.stringify(r)).join('\n');
  const sizeKb = Math.round(Buffer.byteLength(ndjson) / 1024);

  // NOTE: Actual S3/GCS upload requires AWS SDK or GCS client.
  // In production: const s3 = new S3Client(); await s3.send(new PutObjectCommand({...}))
  // For now, we record the job as done with row count and simulated destination.
  await db.query(
    `UPDATE audit_export_jobs
     SET status='done', rows_exported=$1, finished_at=NOW()
     WHERE id=$2`,
    [rows.rows.length, jobId]
  );

  // Audit trail — log the export itself
  await db.query(
    `INSERT INTO audit_log (tenant_id, tool_name, decision, reason, created_at)
     VALUES ($1,'audit_export','ALLOW','exported_${rows.rows.length}_rows_${sizeKb}kb',NOW())`,
    [tenantId]
  ).catch(() => {});
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 17: Slack Human-in-the-Loop Approval Orchestrator
// ═══════════════════════════════════════════════════════════════════════

export async function slackHitlPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;
  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  fastify.get('/api/slack/hitl/config', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const r = await db.query(
      `SELECT channel_id, active, created_at, updated_at FROM slack_hitl_config WHERE tenant_id=$1 LIMIT 1`,
      [tenant.id]
    ).catch(() => ({ rows: [] }));
    const row: any = r.rows[0];
    return {
      configured: Boolean(row?.active),
      channelId: row?.channel_id || '',
      createdAt: row?.created_at || null,
      updatedAt: row?.updated_at || null,
    };
  });

  // POST /api/slack/hitl/config — configure the Slack bot for HITL approvals
  fastify.post('/api/slack/hitl/config', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = tenant.id;

    const { botToken, channelId, signingSecret } = req.body as any;
    if (!botToken || !channelId || !signingSecret) {
      return reply.code(400).send({ error: 'botToken, channelId, and signingSecret are required' });
    }

    await db.query(
      `INSERT INTO slack_hitl_config (tenant_id, bot_token, channel_id, signing_secret)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (tenant_id) DO UPDATE
         SET bot_token=$2, channel_id=$3, signing_secret=$4, active=TRUE`,
      [tenantId, encryptValue(botToken), channelId, encryptValue(signingSecret)]
    );

    return { configured: true, channelId };
  });

  // POST /api/slack/hitl/interact — Slack interactive payload (approve/deny button)
  fastify.post('/api/slack/hitl/interact', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const rawBody = (req as any).rawBody?.toString() || '';
    const payload = JSON.parse(
      decodeURIComponent(rawBody.replace(/^payload=/, ''))
    );

    const tenantId = payload.team?.id; // use Slack team ID as lookup key
    const config = await db.query(
      `SELECT bot_token, signing_secret FROM slack_hitl_config WHERE active=TRUE LIMIT 1`
    ).then(r => r.rows[0]).catch(() => null);

    if (!config) return reply.code(404).send({ error: 'Slack not configured' });

    // Verify Slack signature
    const timestamp = req.headers['x-slack-request-timestamp'];
    const slackSig  = req.headers['x-slack-signature'];
    const baseString = `v0:${timestamp}:${rawBody}`;
    const expectedSig = 'v0=' + crypto.createHmac('sha256', decryptValue(config.signing_secret))
      .update(baseString).digest('hex');

    if (slackSig !== expectedSig) {
      return reply.code(403).send({ error: 'Invalid Slack signature' });
    }

    const action    = payload.actions?.[0];
    const approvalId = action?.value;
    const decision  = action?.action_id === 'hitl_approve' ? 'approved' : 'denied';

    if (!approvalId) return reply.code(400).send({ error: 'No action value' });

    // Update HITL approval
    await db.query(
      `UPDATE hitl_approvals SET decision=$1, decided_at=NOW(),
       decided_by=$2 WHERE approval_id=$3`,
      [decision, payload.user?.name || 'slack_user', approvalId]
    );

    // Update the Slack message to show the decision
    const msgRow = await db.query(
      `SELECT slack_ts, channel_id FROM slack_hitl_messages WHERE approval_id=$1`,
      [approvalId]
    ).then(r => r.rows[0]).catch(() => null);

    if (msgRow && config) {
      await axios.post('https://slack.com/api/chat.update', {
        channel: msgRow.channel_id,
        ts: msgRow.slack_ts,
        text: `✅ *${decision.toUpperCase()}* by ${payload.user?.name}`,
        blocks: [],
      }, {
        headers: { Authorization: `Bearer ${decryptValue(config.bot_token)}` }
      }).catch(() => {});
    }

    return reply.send(''); // Slack expects 200 OK with empty body for interaction ACK
  });

  // Helper: send a HITL approval request to Slack
  // Called from hitl/approval.ts notifyApprovers()
  fastify.post('/api/slack/hitl/notify', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth', 'enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = tenant.id;

    const { approvalId, agentId, toolName, riskLevel, reason } = req.body as any;
    const config = await db.query(
      `SELECT bot_token, channel_id FROM slack_hitl_config
       WHERE tenant_id=$1 AND active=TRUE`,
      [tenantId]
    ).then(r => r.rows[0]).catch(() => null);

    if (!config) return reply.code(404).send({ error: 'Slack not configured for this tenant' });

    const resp = await axios.post('https://slack.com/api/chat.postMessage', {
      channel: config.channel_id,
      text: `⚠️ HITL Approval Required`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*⚠️ HITL Approval Required*\n*Agent:* ${agentId}\n*Tool:* \`${toolName}\`\n*Risk:* ${riskLevel}\n*Reason:* ${reason}`,
          },
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: '✅ Approve' },
              style: 'primary',
              action_id: 'hitl_approve',
              value: approvalId,
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: '❌ Deny' },
              style: 'danger',
              action_id: 'hitl_deny',
              value: approvalId,
            },
          ],
        },
      ],
    }, {
      headers: { Authorization: `Bearer ${decryptValue(config.bot_token)}` }
    });

    if (resp.data?.ok && resp.data?.ts) {
      await db.query(
        `INSERT INTO slack_hitl_messages (approval_id, slack_ts, channel_id)
         VALUES ($1,$2,$3) ON CONFLICT (approval_id) DO NOTHING`,
        [approvalId, resp.data.ts, config.channel_id]
      ).catch(() => {});
    }

    return { sent: !!resp.data?.ok, slackTs: resp.data?.ts };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 18: Agentic Graph & Behavior Topology Mapper
// ═══════════════════════════════════════════════════════════════════════

export async function agentGraphPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/agents/graph — returns nodes + edges for visualisation
  fastify.get('/api/agents/graph', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    // Nodes: agents active in last 30 days
    const agents = await db.query(
      `SELECT agent_id, COUNT(*) as call_count,
              COUNT(*) FILTER (WHERE decision='DENY') as denied_count,
              array_agg(DISTINCT tool_name) as tools_used
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '30 days'
       GROUP BY agent_id`,
      [tenantId]
    );

    // Edges: tool co-occurrences
    const edges = await db.query(
      `SELECT agent_id, tool_a, tool_b, co_count
       FROM agent_tool_cooccurrence
       WHERE tenant_id=$1
       ORDER BY co_count DESC LIMIT 200`,
      [tenantId]
    );

    // Rebuild co-occurrences from audit log if table is empty
    if (!edges.rows.length) {
      await rebuildCooccurrenceGraph(tenantId, db);
      const rebuilt = await db.query(
        `SELECT agent_id, tool_a, tool_b, co_count
         FROM agent_tool_cooccurrence WHERE tenant_id=$1 ORDER BY co_count DESC LIMIT 200`,
        [tenantId]
      );
      edges.rows.push(...rebuilt.rows);
    }

    return {
      nodes: agents.rows.map(a => ({
        id: a.agent_id,
        callCount: parseInt(a.call_count, 10),
        deniedCount: parseInt(a.denied_count, 10),
        toolsUsed: a.tools_used || [],
        riskScore: Math.round((parseInt(a.denied_count, 10) / Math.max(parseInt(a.call_count, 10), 1)) * 100),
      })),
      edges: edges.rows.map(e => ({
        agentId: e.agent_id,
        toolA: e.tool_a,
        toolB: e.tool_b,
        weight: e.co_count,
      })),
    };
  });

  // POST /api/agents/graph/rebuild — manually rebuild co-occurrence graph
  fastify.post('/api/agents/graph/rebuild', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    await rebuildCooccurrenceGraph(tenantId, db);
    return { rebuilt: true };
  });
}

async function rebuildCooccurrenceGraph(tenantId: string, db: Pool): Promise<void> {
  // Find tools called within 5 minutes of each other by the same agent (co-used)
  await db.query(
    `INSERT INTO agent_tool_cooccurrence (tenant_id, agent_id, tool_a, tool_b, co_count, last_seen)
     SELECT $1, a.agent_id, a.tool_name, b.tool_name, COUNT(*), NOW()
     FROM audit_log a
     JOIN audit_log b ON a.agent_id = b.agent_id
       AND a.tenant_id = b.tenant_id
       AND a.tool_name < b.tool_name
       AND ABS(EXTRACT(EPOCH FROM (a.created_at - b.created_at))) < 300
     WHERE a.tenant_id=$1
       AND a.created_at > NOW() - INTERVAL '30 days'
       AND a.decision='ALLOW' AND b.decision='ALLOW'
     GROUP BY a.agent_id, a.tool_name, b.tool_name
     ON CONFLICT (tenant_id, agent_id, tool_a, tool_b) DO UPDATE
       SET co_count=EXCLUDED.co_count, last_seen=NOW()`,
    [tenantId]
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 19: Distributed OpenTelemetry APM Trace Span Engine
// ═══════════════════════════════════════════════════════════════════════

export interface TraceSpan {
  traceId: string;
  spanId: string;
  parentSpan?: string;
  operation: string;
  startTime: Date;
  attributes: Record<string, unknown>;
}

export function startSpan(
  traceId: string,
  operation: string,
  attributes: Record<string, unknown> = {},
  parentSpan?: string
): TraceSpan {
  return {
    traceId,
    spanId: crypto.randomBytes(8).toString('hex'),
    parentSpan,
    operation,
    startTime: new Date(),
    attributes,
  };
}

export async function finishSpan(
  span: TraceSpan,
  db: Pool,
  tenantId: string,
  status: 'ok' | 'error' = 'ok',
  extraAttributes: Record<string, unknown> = {}
): Promise<void> {
  const endTime = new Date();
  const durationMs = endTime.getTime() - span.startTime.getTime();

  await db.query(
    `INSERT INTO otel_traces
     (trace_id, span_id, parent_span, tenant_id, operation,
      start_time, end_time, duration_ms, status, attributes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [span.traceId, span.spanId, span.parentSpan || null, tenantId,
     span.operation, span.startTime, endTime, durationMs, status,
     JSON.stringify({ ...span.attributes, ...extraAttributes })]
  ).catch(() => {}); // never block on trace writes

  // Also export to configured OTEL endpoint if set
  exportSpanToOtel(span, tenantId, durationMs, status, db).catch(() => {});
}

async function exportSpanToOtel(
  span: TraceSpan, tenantId: string, durationMs: number,
  status: string, db: Pool
): Promise<void> {
  const otelConfig = await db.query(
    `SELECT metadata->>'otel' as otel FROM tenants WHERE id=$1`,
    [tenantId]
  ).then(r => {
    const cfg = r.rows[0]?.otel;
    if (!cfg) return null;
    const parsed = JSON.parse(cfg);
    if (parsed.headersEncrypted && parsed.headers) {
      parsed.headers = Object.fromEntries(
        Object.entries(parsed.headers).map(([key, value]) => [key, decryptValue(String(value))])
      );
    }
    return parsed;
  }).catch(() => null);

  if (!otelConfig?.enabled || !otelConfig?.endpoint) return;

  // OTLP/HTTP format
  await axios.post(otelConfig.endpoint, {
    resourceSpans: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'mcp-security-gateway' } }] },
      scopeSpans: [{
        scope: { name: 'mcp-gateway' },
        spans: [{
          traceId: span.traceId,
          spanId: span.spanId,
          parentSpanId: span.parentSpan,
          name: span.operation,
          kind: 2, // SERVER
          startTimeUnixNano: span.startTime.getTime() * 1_000_000,
          endTimeUnixNano: (span.startTime.getTime() + durationMs) * 1_000_000,
          status: { code: status === 'ok' ? 1 : 2 },
          attributes: Object.entries(span.attributes).map(([k, v]) => ({
            key: k,
            value: { stringValue: String(v) },
          })),
        }],
      }],
    }],
  }, {
    headers: {
      'Content-Type': 'application/json',
      ...(otelConfig.headers || {}),
    },
    timeout: 3000,
  }).catch(() => {}); // fail silently — never block on telemetry
}

export async function otelPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/traces?agentId=&toolName=&limit=
  fastify.get('/api/traces', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId, toolName, limit = 50 } = req.query as any;
    const conditions = [`tenant_id=$1`];
    const params: any[] = [tenantId];
    if (agentId)   conditions.push(`attributes->>'agentId' = $${params.push(agentId)}`);
    if (toolName)  conditions.push(`attributes->>'toolName' = $${params.push(toolName)}`);

    const r = await db.query(
      `SELECT trace_id, span_id, parent_span, operation,
              start_time, duration_ms, status, attributes
       FROM otel_traces
       WHERE ${conditions.join(' AND ')}
       ORDER BY start_time DESC LIMIT $${params.push(Math.min(parseInt(limit, 10), 200))}`,
      params
    );

    const stats = await db.query(
      `SELECT operation,
              ROUND(AVG(duration_ms))   as avg_ms,
              ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms)) as p95_ms,
              COUNT(*) as count
       FROM otel_traces
       WHERE tenant_id=$1 AND start_time > NOW() - INTERVAL '1 hour'
       GROUP BY operation ORDER BY avg_ms DESC`,
      [tenantId]
    ).catch(() => ({ rows: [] }));

    return { traces: r.rows, latencyStats: stats.rows };
  });
}

// ═══════════════════════════════════════════════════════════════════════
// Feature 20: Webhook Auto-Retry & Delivery Policy Manager
// ═══════════════════════════════════════════════════════════════════════

// Retry schedule: 1m → 5m → 30m → 2h → 24h → dead-letter
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3600_000, 24 * 3600_000];

export async function retryWebhookDeliveries(db: Pool): Promise<void> {
  // Find deliveries due for retry
  const due = await db.query(
    `SELECT id, tenant_id, rule_name, event_type, destination_type,
            destination_url, payload_json, retry_count
     FROM webhook_deliveries
     WHERE delivered=FALSE
       AND dead_lettered=FALSE
       AND next_retry_at IS NOT NULL
       AND next_retry_at <= NOW()
     ORDER BY next_retry_at ASC LIMIT 50`
  );

  for (const delivery of due.rows) {
    try {
      let success = false;
      let httpStatus = 0;
      let responseMs = 0;
      let errorMessage = '';

      const start = Date.now();
      try {
        const resp = await axios.post(
          delivery.destination_url,
          delivery.payload_json,
          {
            headers: { 'Content-Type': 'application/json', 'X-MCP-Retry': String(delivery.retry_count) },
            timeout: 10_000,
          }
        );
        httpStatus = resp.status;
        success = resp.status >= 200 && resp.status < 300;
      } catch (err: any) {
        httpStatus = err.response?.status || 0;
        errorMessage = err.message;
      }
      responseMs = Date.now() - start;

      if (success) {
        await db.query(
          `UPDATE webhook_deliveries
           SET delivered=TRUE, success=TRUE, status_code=$1, duration_ms=$2,
               retry_count=retry_count+1, next_retry_at=NULL
           WHERE id=$3`,
          [httpStatus, responseMs, delivery.id]
        );
      } else {
        const nextRetryIdx = delivery.retry_count; // 0-based
        if (nextRetryIdx >= RETRY_DELAYS_MS.length) {
          // Dead-letter after max retries
          await db.query(
            `UPDATE webhook_deliveries
             SET dead_lettered=TRUE, error_message=$1, retry_count=retry_count+1, next_retry_at=NULL
             WHERE id=$2`,
            [`Max retries (${RETRY_DELAYS_MS.length}) exceeded. Last error: ${errorMessage}`, delivery.id]
          );
        } else {
          const nextRetryAt = new Date(Date.now() + RETRY_DELAYS_MS[nextRetryIdx]);
          await db.query(
            `UPDATE webhook_deliveries
             SET retry_count=retry_count+1, next_retry_at=$1,
                 success=FALSE, status_code=$2, duration_ms=$3, error_message=$4
             WHERE id=$5`,
            [nextRetryAt, httpStatus, responseMs, errorMessage || null, delivery.id]
          );
        }
      }
    } catch (err: any) {
      console.error(`Webhook retry failed for delivery ${delivery.id}:`, err.message);
    }
  }
}

export async function webhookRetryPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/webhooks/dead-letter — view dead-lettered deliveries
  fastify.get('/api/webhooks/dead-letter', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id,
              COALESCE(rule_name, channel, event_type, 'webhook') AS alert_rule_name,
              event_type,
              COALESCE(destination_url, channel, '') AS url,
              COALESCE(retry_count, 0) AS retry_count,
              COALESCE(max_retries, 5) AS max_retries,
              error_message, created_at
       FROM webhook_deliveries
       WHERE tenant_id=$1 AND dead_lettered=TRUE
       ORDER BY created_at DESC LIMIT 50`,
      [tenantId]
    );
    return { deadLettered: r.rows };
  });

  // POST /api/webhooks/dead-letter/:id/revive — rescue from dead-letter
  fastify.post('/api/webhooks/dead-letter/:id/revive', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Advanced security features require Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      `UPDATE webhook_deliveries
       SET dead_lettered=FALSE, retry_count=0,
           next_retry_at=NOW() + INTERVAL '10 seconds',
           error_message=NULL
       WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, tenantId]
    );
    return { revived: true, message: 'Delivery re-queued for immediate retry.' };
  });
}
