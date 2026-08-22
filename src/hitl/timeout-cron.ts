/**
 * HITL Timeout Enforcer (Cron Job)
 *
 * Sprint 3 fix. Approvals have a 15-minute TTL (set in hitl_approvals.expires_at).
 * The existing cron/scheduler.ts never sweeps timed-out approvals.
 * This job runs every 60s and auto-denies all approvals where:
 *   decision = 'pending' AND expires_at < NOW()
 *
 * Wire into cron/scheduler.ts:
 *   import { sweepHitlTimeouts } from '../hitl/timeout-cron';
 *   setInterval(() => sweepHitlTimeouts(db, redis, log), 60_000);
 */

import { Pool } from 'pg';
import Redis from 'ioredis';

export async function sweepHitlTimeouts(
  db: Pool,
  redis: Redis,
  log: any
): Promise<void> {
  try {
    // Find all expired pending approvals
    const expired = await db.query(
      `UPDATE hitl_approvals
       SET decision='timeout', decided_at=NOW(), decision_note='Auto-denied: approval window expired'
       WHERE decision='pending' AND expires_at < NOW()
       RETURNING approval_id, tenant_id, agent_id, tool_name`
    );

    if (expired.rowCount && expired.rowCount > 0) {
      log.info({ count: expired.rowCount }, 'HITL: auto-denied timed-out approvals');

      // Publish timeout events via Redis so dashboard updates in real-time
      for (const row of expired.rows) {
        await redis.publish(
          `ws:hitl:${row.tenant_id}`,
          JSON.stringify({
            channel: 'hitl',
            tenantId: row.tenant_id,
            payload: {
              approvalId: row.approval_id,
              agentId: row.agent_id,
              toolName: row.tool_name,
              decision: 'timeout',
              reason: 'Approval window expired — auto-denied',
            },
            ts: new Date().toISOString(),
          })
        ).catch(() => {}); // Non-fatal if Redis pub fails
      }
    }
  } catch (err) {
    log.error({ err }, 'HITL timeout sweep failed');
  }
}

/**
 * Rate-per-plan enforcement
 * Sprint 3 fix: rate limit should be per-plan, not a single global env var.
 *
 * Call in bootstrap() when registering @fastify/rate-limit:
 *   keyGenerator: (req) => req.agentId || req.ip
 *   max: (req) => getPlanRateLimit(req.tenant?.plan)
 */
export function getPlanRateLimit(plan?: string): number {
  switch (plan) {
    case 'cloud':       return 100;
    case 'starter':     return 200;
    case 'growth':      return 1_000;
    case 'enterprise':  return 10_000;
    default:            return parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
  }
}

/**
 * Data retention enforcer
 * Runs daily.
 *
 * Enterprise-safe retention is intentionally split:
 * - prompt/tool detail fields are cleared after prompt_audit_settings.retention_days
 * - structured audit metadata is kept until retention_policies.audit_log_days
 * - HITL records are kept separately for approval evidence
 * - ML profile summaries are not deleted here; they are aggregated behavior baselines
 */
export async function enforceRetentionPolicies(db: Pool, log: any): Promise<void> {
  try {
    await db.query(
      `UPDATE audit_log al
       SET user_command=NULL, tool_arguments=NULL, response_summary=NULL
       FROM prompt_audit_settings pas
       WHERE al.tenant_id=pas.tenant_id
         AND al.created_at < NOW() - (pas.retention_days || ' days')::INTERVAL
         AND (al.user_command IS NOT NULL OR al.tool_arguments IS NOT NULL OR al.response_summary IS NOT NULL)`
    );

    const policies = await db.query(
      `SELECT tenant_id, audit_log_days, dlp_events_days, hitl_days, shadow_days
       FROM retention_policies`
    );

    for (const policy of policies.rows) {
      const tid = policy.tenant_id;

      // Delete old structured audit metadata only after its longer metadata TTL.
      if (policy.audit_log_days) {
        await db.query(
          `DELETE FROM audit_log WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL`,
          [tid, policy.audit_log_days]
        );
        await db.query(
          `DELETE FROM audit.immutable_log WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL`,
          [tid, policy.audit_log_days]
        ).catch(() => {});  // Immutable log rule blocks DELETE — expected
      }

      // Delete old DLP events
      if (policy.dlp_events_days) {
        await db.query(
          `DELETE FROM dlp_events WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL`,
          [tid, policy.dlp_events_days]
        );
      }

      // Delete old HITL approval evidence separately from general audit.
      if (policy.hitl_days) {
        await db.query(
          `DELETE FROM hitl_approvals WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL
           AND decision != 'pending'`,
          [tid, policy.hitl_days]
        );
      }

      // Delete old shadow findings
      if (policy.shadow_days) {
        await db.query(
          `DELETE FROM shadow_mcp_findings WHERE tenant_id=$1 AND created_at < NOW() - ($2 || ' days')::INTERVAL`,
          [tid, policy.shadow_days]
        );
      }
    }

    log.info('Data retention policies enforced');
  } catch (err) {
    log.error({ err }, 'Retention policy enforcement failed');
  }
}
