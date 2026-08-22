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

  log.info('Cron jobs started: baselines(1h), alerts(60s), trials(6h), overage(daily)');
}
