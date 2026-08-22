import { buildMLProfile, detectAnomalyML } from '../anomaly/ml-engine';
import { createWsPublisher } from '../websocket/realtime';

const tenantId = '11111111-1111-1111-1111-111111111111';
const agentId = 'agent-ml-realtime';

function auditRows(count = 120) {
  const rows: any[] = [];
  const now = new Date();
  now.setUTCMinutes(0, 0, 0);

  for (let i = 0; i < count - 10; i++) {
    rows.push({
      tool_name: 'read_file',
      args_length: 28 + (i % 5),
      call_hour: now.getUTCHours(),
      created_at: new Date(now.getTime() - (count - i) * 60_000).toISOString(),
      prev_tool: i === 0 ? null : 'read_file',
    });
  }

  for (let i = count - 10; i < count; i++) {
    rows.push({
      tool_name: 'list_dir',
      args_length: 18 + (i % 3),
      call_hour: now.getUTCHours(),
      created_at: new Date(now.getTime() - (count - i) * 60_000).toISOString(),
      prev_tool: i === count - 10 ? 'read_file' : 'list_dir',
    });
  }

  return rows;
}

describe('ML anomaly profiles + realtime events', () => {
  it('builds an ML profile and flags a realtime-style anomalous call', async () => {
    let savedProfile: unknown;
    const db = {
      query: jest.fn(async (sql: string, params?: unknown[]) => {
        if (sql.includes('FROM audit_log')) return { rows: auditRows(), rowCount: 120 };
        if (sql.includes('INSERT INTO agent_ml_profiles')) {
          savedProfile = typeof params?.[2] === 'string' ? JSON.parse(params[2] as string) : params?.[2];
          return { rows: [], rowCount: 1 };
        }
        if (sql.includes('SELECT profile_json FROM agent_ml_profiles')) {
          return { rows: [{ profile_json: savedProfile }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      }),
    } as any;

    const redis = {
      get: jest.fn().mockResolvedValue(null),
      setex: jest.fn().mockResolvedValue('OK'),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn().mockResolvedValue(1),
    } as any;

    const profile = await buildMLProfile(agentId, tenantId, db);
    expect(profile).not.toBeNull();
    expect(profile!.sampleSize).toBe(120);
    expect(profile!.toolProfiles.read_file.callCount).toBe(110);
    expect(profile!.toolSeenCount.list_dir).toBe(10);

    const result = await detectAnomalyML(
      agentId,
      tenantId,
      'read_file',
      { path: 'ANOMALY_TEST_'.repeat(80) },
      'list_dir',
      db,
      redis
    );

    expect(result.isAnomaly).toBe(true);
    expect(result.action).toBe('flag');
    expect(result.score).toBeGreaterThanOrEqual(35);
    expect(result.reasons.map(r => r.model)).toEqual(
      expect.arrayContaining(['arg_distribution', 'transition_graph'])
    );
  });

  it('publishes ML anomaly audit and alert messages to tenant realtime channels', async () => {
    const redis = {
      publish: jest.fn().mockResolvedValue(1),
    } as any;
    const publisher = createWsPublisher(redis);

    await publisher.auditEvent(tenantId, {
      agentId,
      toolName: 'read_file',
      decision: 'ALLOW',
      reason: 'ml_anomaly:score=47',
      executionTimeMs: 12,
      authProvider: 'bearer',
    });

    await publisher.alert(tenantId, {
      severity: 'critical',
      eventType: 'anomaly_detected',
      message: 'ML anomaly profile flagged unusual realtime behavior',
      details: { agentId, score: 47 },
    });

    expect(redis.publish).toHaveBeenCalledWith(
      `ws:audit:${tenantId}`,
      expect.stringContaining('"channel":"audit"')
    );
    expect(redis.publish).toHaveBeenCalledWith(
      `ws:alert:${tenantId}`,
      expect.stringContaining('"eventType":"anomaly_detected"')
    );

    const alertPayload = JSON.parse(redis.publish.mock.calls[1][1]);
    expect(alertPayload.tenantId).toBe(tenantId);
    expect(alertPayload.payload.details.score).toBe(47);
  });
});
