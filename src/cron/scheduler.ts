/**
 * cron/scheduler.ts — Background job runner
 * FIX: anomaly baselines were never rebuilt. Alert rules were never evaluated.
 * This module wires both to recurring timers.
 */
import { Pool } from 'pg';
import Redis from 'ioredis';
import { rebuildBaselines } from '../anomaly/detector';
import { evaluateAlertRules } from '../webhooks/alerting';
import { enforceTrialExpiry } from '../tenant/trial';
import { processOverageBilling } from '../billing/overage';
import { runShadowDiscovery } from '../shadow/discovery';

export function startCronJobs(db: Pool, redis: Redis, log: any) {
  // Rebuild anomaly baselines hourly — FIX: was never called
  setInterval(async () => {
    try { await rebuildBaselines(db); log.info('Anomaly baselines rebuilt'); }
    catch (e) { log.error({ e }, 'Baseline rebuild failed'); }
  }, 60 * 60 * 1000);

  // Evaluate alert rules every 60s — FIX: was never called
  setInterval(async () => {
    try { await evaluateAlertRules(db); }
    catch (e) { log.error({ e }, 'Alert evaluation failed'); }
  }, 60 * 1000);

  // Check trial expiry every 6 hours — FIX: trials ran indefinitely
  setInterval(async () => {
    try { await enforceTrialExpiry(db); log.info('Trial expiry check done'); }
    catch (e) { log.error({ e }, 'Trial expiry check failed'); }
  }, 6 * 60 * 60 * 1000);

  // Process overage billing daily at midnight UTC
  const now = new Date();
  const msToMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1).getTime() - now.getTime();
  setTimeout(() => {
    processOverageBilling(db).catch(e => log.error({ e }, 'Overage billing failed'));
    setInterval(() => processOverageBilling(db).catch(() => {}), 24 * 60 * 60 * 1000);
  }, msToMidnight);

  // [F6] Expired API key cleanup — deactivate rotated keys past their grace period
  setInterval(async () => {
    try {
      const r = await db.query(
        `UPDATE agent_tokens SET active=FALSE
         WHERE expires_at IS NOT NULL AND expires_at < NOW() AND active=TRUE
         RETURNING agent_id`
      );
      if (r.rowCount && r.rowCount > 0) log.info({ count: r.rowCount }, 'Expired rotated API keys deactivated');
    } catch (e) { log.error({ e }, 'API key expiry cleanup failed'); }
  }, 5 * 60 * 1000); // every 5 minutes

  if (process.env.ENABLE_SHADOW_DISCOVERY_CRON !== 'false') {
    setInterval(async () => {
      try {
        const tenants = await db.query(
          `SELECT id FROM tenants WHERE plan IN ('growth','enterprise') LIMIT 500`
        );
        for (const row of tenants.rows) {
          await runShadowDiscovery(row.id, db, redis).catch((e) =>
            log.warn({ e, tenantId: row.id }, 'Shadow MCP discovery failed for tenant')
          );
        }
        log.info({ tenants: tenants.rowCount }, 'Shadow MCP discovery sweep complete');
      } catch (e) {
        log.error({ e }, 'Shadow MCP discovery cron failed');
      }
    }, 15 * 60 * 1000);
  }

  log.info('Cron jobs started: baselines(1h), alerts(60s), trials(6h), overage(daily), key-expiry(5m), shadow-discovery(15m)');
}
