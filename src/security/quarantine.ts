import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';

const MAX_VIOLATIONS = 3;
const WINDOW_SECONDS = 300; // 5 minutes

export async function incrementViolation(
  tenantId: string,
  agentId: string,
  authHeader: string | undefined,
  reason: string,
  db: Pool,
  redis?: Redis
): Promise<void> {
  if (!redis) return;

  const key = `quarantine:violations:${tenantId}:${agentId}`;
  try {
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.expire(key, WINDOW_SECONDS);
    }

    if (current === MAX_VIOLATIONS) { // Trigger exactly once when it hits threshold
      // 1. Revoke in Database
      await db.query(
        `UPDATE agent_tokens SET active = false WHERE agent_id = $1 AND tenant_id = $2`,
        [agentId, tenantId]
      );

      // 2. Clear Auth Cache
      if (authHeader) {
        const [scheme, token] = authHeader.split(' ');
        if (scheme === 'Bearer' && token) {
          const cacheKey = `auth:token:${crypto.createHash('sha256').update(token).digest('hex')}`;
          await redis.del(cacheKey);
        }
      }

      // 3. Alert Generation
      const alertMessage = `Agent ${agentId} auto-quarantined after ${MAX_VIOLATIONS} security violations within ${WINDOW_SECONDS} seconds. Last violation: ${reason}`;
      await db.query(
        `INSERT INTO alert_log (tenant_id, event_type, severity, message, details)
         VALUES ($1, 'agent_quarantined', 'critical', $2, $3)`,
        [tenantId, alertMessage, JSON.stringify({ agentId, threshold: MAX_VIOLATIONS, lastReason: reason })]
      );
      
      console.log(`[QUARANTINE] Agent ${agentId} isolated for tenant ${tenantId}.`);
    }
  } catch (err) {
    console.error('Failed to process quarantine logic:', err);
  }
}
