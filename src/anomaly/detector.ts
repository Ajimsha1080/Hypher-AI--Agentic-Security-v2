/**
 * AI Behaviour Anomaly Detection — v3 feature
 * Builds a statistical baseline of normal agent behaviour,
 * then flags requests that deviate significantly.
 * No ML model required — uses statistical z-score approach first.
 */

import { Pool } from 'pg';
import Redis from 'ioredis';

export interface BehaviourBaseline {
  agentId: string;
  tenantId: string;
  avgCallsPerHour: number;
  avgCallsPerMinute: number;
  topTools: string[];           // most frequently called tools
  typicalCallHours: number[];   // hours of day when agent is usually active
  avgArgLength: number;
  stdDevArgLength: number;
  baselineSampleSize: number;
  lastUpdated: Date;
}

export interface AnomalyResult {
  isAnomaly: boolean;
  score: number;               // 0-100, higher = more anomalous
  reasons: string[];
  action: 'allow' | 'flag' | 'block';
}

// ── Anomaly detection (statistical, no ML required) ────────────────────

export async function detectAnomaly(
  agentId: string,
  tenantId: string,
  toolName: string,
  args: Record<string, unknown>,
  db: Pool,
  redis: Redis
): Promise<AnomalyResult> {
  const baseline = await getBaseline(agentId, tenantId, redis, db);

  // [BUG #1 FIX] During bootstrap (no baseline yet or fewer than 20 samples),
  // new agents previously had ZERO anomaly protection — the function returned early
  // with isAnomaly:false, letting attackers exploit the warm-up window freely.
  // Fix: apply a lightweight burst-rate guard during bootstrap so brand-new agents
  // are protected against call-volume attacks even before a full baseline exists.
  if (!baseline || baseline.baselineSampleSize < 20) {
    const burstKey = `bootstrap_burst:${tenantId}:${agentId}`;
    const burstCount = await redis.incr(burstKey);
    if (burstCount === 1) await redis.expire(burstKey, 60); // 1-minute window

    // More than 30 calls/min from a brand-new agent is suspicious regardless of baseline
    if (burstCount > 30) {
      return {
        isAnomaly: true,
        score: 60,
        reasons: [`Bootstrap burst: ${burstCount} calls/min from new agent (no baseline yet)`],
        action: 'flag',
      };
    }
    return { isAnomaly: false, score: 0, reasons: ['bootstrap_period'], action: 'allow' };
  }

  // Partial baseline (20–99 samples): run checks but use relaxed thresholds
  const partialBaseline = baseline.baselineSampleSize < 100;

  const reasons: string[] = [];
  let score = 0;

  // 1. Unusual tool for this agent
  if (!baseline.topTools.includes(toolName)) {
    reasons.push(`Agent has never called '${toolName}' before`);
    score += partialBaseline ? 15 : 30; // relaxed during partial baseline
  }

  // 2. Unusual time of day
  const currentHour = new Date().getUTCHours();
  if (!baseline.typicalCallHours.includes(currentHour)) {
    reasons.push(`Agent calling at unusual hour: ${currentHour}:00 UTC`);
    score += partialBaseline ? 10 : 20;
  }

  // 3. Unusual argument length (z-score > 3, or > 2 during partial baseline)
  const argStr = JSON.stringify(args);
  if (baseline.stdDevArgLength > 0) {
    const zScore = Math.abs(argStr.length - baseline.avgArgLength) / baseline.stdDevArgLength;
    const zThreshold = partialBaseline ? 4 : 3; // more lenient when data is sparse
    if (zScore > zThreshold) {
      reasons.push(`Argument length unusually ${argStr.length > baseline.avgArgLength ? 'large' : 'small'} (z-score: ${zScore.toFixed(1)})`);
      score += Math.min(30, zScore * 10);
    }
  }

  // 4. Burst rate — too many calls in last minute
  // Use a floor of 10 calls/min to avoid false positives for low-activity agents
  const recentCalls = await countRecentCalls(agentId, tenantId, 60, redis);
  const burstThreshold = Math.max(10, baseline.avgCallsPerMinute * 5);
  if (recentCalls > burstThreshold) {
    reasons.push(`Call burst: ${recentCalls} calls in last 60s (baseline: ${Math.round(baseline.avgCallsPerMinute)}/min)`);
    score += partialBaseline ? 15 : 25;
  }

  score = Math.min(100, Math.round(score));

  const action: AnomalyResult['action'] =
    score >= 80 ? 'block' :
    score >= 40 ? 'flag' :
    'allow';

  return { isAnomaly: score >= 40, score, reasons, action };
}

async function getBaseline(agentId: string, tenantId: string, redis: Redis, db: Pool): Promise<BehaviourBaseline | null> {
  const cacheKey = `baseline:${tenantId}:${agentId}`;
  const cached = await redis.get(cacheKey);
  if (cached) return JSON.parse(cached);

  const r = await db.query(
    `SELECT * FROM agent_baselines WHERE agent_id=$1 AND tenant_id=$2`,
    [agentId, tenantId]
  );

  if (!r.rows.length) return null;

  // Map snake_case DB columns → camelCase BehaviourBaseline interface
  const row = r.rows[0];
  const baseline: BehaviourBaseline = {
    agentId:           row.agent_id,
    tenantId:          row.tenant_id,
    avgCallsPerHour:   parseFloat(row.avg_calls_per_hour)   || 0,
    avgCallsPerMinute: parseFloat(row.avg_calls_per_minute) || 0,
    topTools:          typeof row.top_tools === 'string'          ? JSON.parse(row.top_tools)          : (row.top_tools         || []),
    typicalCallHours:  typeof row.typical_call_hours === 'string' ? JSON.parse(row.typical_call_hours) : (row.typical_call_hours || []),
    avgArgLength:      parseFloat(row.avg_arg_length)      || 200,
    stdDevArgLength:   parseFloat(row.std_dev_arg_length)  || 50,
    baselineSampleSize: parseInt(row.baseline_sample_size, 10) || 0,
    lastUpdated:       row.last_updated ? new Date(row.last_updated) : new Date(),
  };

  await redis.setex(cacheKey, 300, JSON.stringify(baseline));
  return baseline;
}

async function countRecentCalls(agentId: string, tenantId: string, seconds: number, redis: Redis): Promise<number> {
  const key = `burst:${tenantId}:${agentId}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, seconds);
  return count;
}

// ── Baseline builder — runs hourly via cron ────────────────────────────

export async function rebuildBaselines(db: Pool): Promise<void> {
  const agents = await db.query(
    `SELECT DISTINCT agent_id, tenant_id FROM audit_log
     WHERE created_at > NOW() - INTERVAL '7 days'`
  );

  for (const agent of agents.rows) {
    try {
      await rebuildAgentBaseline(agent.agent_id, agent.tenant_id, db);
    } catch (e) {
      console.error(`Failed to rebuild baseline for ${agent.agent_id}:`, e);
    }
  }
}

async function rebuildAgentBaseline(agentId: string, tenantId: string, db: Pool): Promise<void> {
  const logs = await db.query(
    `SELECT tool_name, args_length, EXTRACT(HOUR FROM created_at) as call_hour, created_at
     FROM audit_log
     WHERE agent_id=$1 AND tenant_id=$2
       AND created_at > NOW() - INTERVAL '7 days'
       AND decision = 'ALLOW'
     ORDER BY created_at DESC`,
    [agentId, tenantId]
  );

  if (logs.rows.length < 10) return;

  const toolCounts: Record<string, number> = {};
  const argLengths: number[] = [];
  const callHours: Record<number, number> = {};

  for (const row of logs.rows) {
    toolCounts[row.tool_name] = (toolCounts[row.tool_name] || 0) + 1;
    if (row.args_length) argLengths.push(parseInt(row.args_length, 10));
    const hour = parseInt(row.call_hour, 10);
    callHours[hour] = (callHours[hour] || 0) + 1;
  }

  const topTools = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([t]) => t);
  const typicalHours = Object.entries(callHours).filter(([, c]) => c >= logs.rows.length * 0.05).map(([h]) => parseInt(h, 10));
  const avgArgLength = argLengths.length ? argLengths.reduce((a, b) => a + b, 0) / argLengths.length : 200;
  const variance = argLengths.length ? argLengths.reduce((a, b) => a + Math.pow(b - avgArgLength, 2), 0) / argLengths.length : 0;
  const stdDev = Math.sqrt(variance);
  const ageHours = 7 * 24;
  const avgCallsPerHour = logs.rows.length / ageHours;

  await db.query(
    `INSERT INTO agent_baselines
       (agent_id, tenant_id, avg_calls_per_hour, avg_calls_per_minute, top_tools,
        typical_call_hours, avg_arg_length, std_dev_arg_length, baseline_sample_size, last_updated)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
     ON CONFLICT (agent_id, tenant_id) DO UPDATE SET
       avg_calls_per_hour=$3, avg_calls_per_minute=$4, top_tools=$5,
       typical_call_hours=$6, avg_arg_length=$7, std_dev_arg_length=$8,
       baseline_sample_size=$9, last_updated=NOW()`,
    [agentId, tenantId, avgCallsPerHour, avgCallsPerHour / 60,
     JSON.stringify(topTools), JSON.stringify(typicalHours),
     avgArgLength, stdDev, logs.rows.length]
  );
}
