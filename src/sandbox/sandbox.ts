/**
 * MCP Server Sandboxing — per-session Docker capability isolation
 * Each agent session gets an isolated container with zero capabilities by default.
 * Capabilities are granted only by policy, scoped to the session lifetime.
 */

import { Pool } from 'pg';

export interface SandboxConfig {
  sessionId: string;
  agentId: string;
  tenantId: string;
  allowedCapabilities: LinuxCapability[];
  networkPolicy: 'none' | 'internal_only' | 'allowlist';
  allowedHosts?: string[];
  memoryLimitMb: number;
  cpuQuota: number;         // 0.0-1.0 fraction of one CPU
  timeoutSeconds: number;
}

type LinuxCapability = 'NET_BIND_SERVICE' | 'NET_ADMIN' | 'NET_RAW' | 'SYS_PTRACE' | 'DAC_READ_SEARCH';

export function buildDockerRunArgs(config: SandboxConfig): string[] {
  const caps: string[] = [];

  // Drop ALL capabilities, then add only what policy allows
  caps.push('--cap-drop=ALL');
  for (const cap of config.allowedCapabilities) {
    caps.push(`--cap-add=${cap}`);
  }

  const networkArg = config.networkPolicy === 'none' ? '--network=none' :
                     config.networkPolicy === 'internal_only' ? '--network=mcp-internal' :
                     '--network=mcp-net';

  return [
    ...caps,
    networkArg,
    `--memory=${config.memoryLimitMb}m`,
    `--memory-swap=${config.memoryLimitMb}m`,
    `--cpus=${config.cpuQuota}`,
    `--stop-timeout=${config.timeoutSeconds}`,
    `--read-only`,
    `--security-opt=no-new-privileges`,
    `--label=mcp.session=${config.sessionId}`,
    `--label=mcp.tenant=${config.tenantId}`,
    `--label=mcp.agent=${config.agentId}`,
  ];
}

export async function getSessionCapabilities(
  agentId: string,
  tenantId: string,
  db: Pool
): Promise<LinuxCapability[]> {
  const r = await db.query(
    `SELECT allowed_capabilities FROM policies
     WHERE agent_id=$1 AND tenant_id=$2 AND active=true LIMIT 1`,
    [agentId, tenantId]
  );
  return r.rows[0]?.allowed_capabilities || [];
}

/**
 * Federated Multi-Org Policy Sharing
 * Organizations can share threat intelligence and policy patterns
 * without exposing their private data to each other.
 */

export interface FederatedThreatSignal {
  signalType: 'blocked_tool' | 'injection_pattern' | 'suspicious_server';
  data: unknown;
  reportedByTenantCount: number; // how many orgs reported this
  confidence: number;            // 0-100
  firstSeen: Date;
  lastSeen: Date;
}

export async function getFederatedThreats(db: Pool): Promise<FederatedThreatSignal[]> {
  const r = await db.query(`
    SELECT signal_type, data, reported_by_count, confidence, first_seen, last_seen
    FROM federated_threat_signals
    WHERE confidence >= 70 AND active = true
    ORDER BY confidence DESC, reported_by_count DESC
    LIMIT 100
  `);
  return r.rows;
}

export async function reportFederatedThreat(
  tenantId: string,
  signalType: FederatedThreatSignal['signalType'],
  data: unknown,
  db: Pool
): Promise<void> {
  const hash = require('crypto').createHash('sha256').update(JSON.stringify({ signalType, data })).digest('hex');

  await db.query(`
    INSERT INTO federated_threat_signals
      (signal_hash, signal_type, data, reported_by_count, confidence, first_seen, last_seen)
    VALUES ($1,$2,$3,1,30,NOW(),NOW())
    ON CONFLICT (signal_hash) DO UPDATE SET
      reported_by_count = federated_threat_signals.reported_by_count + 1,
      confidence = LEAST(100, federated_threat_signals.confidence + 10),
      last_seen = NOW()
  `, [hash, signalType, JSON.stringify(data)]);

  await db.query(`
    INSERT INTO tenant_threat_reports (tenant_id, signal_hash, reported_at)
    VALUES ($1,$2,NOW()) ON CONFLICT DO NOTHING
  `, [tenantId, hash]);
}

export async function syncFederatedPolicies(tenantId: string, db: Pool): Promise<number> {
  const threats = await getFederatedThreats(db);
  let synced = 0;

  for (const threat of threats) {
    if (threat.signalType === 'injection_pattern') {
      const pattern = (threat.data as any).pattern;
      if (pattern) {
        await db.query(`
          INSERT INTO tenant_injection_patterns (tenant_id, pattern, source, confidence)
          VALUES ($1,$2,'federated',$3)
          ON CONFLICT (tenant_id, pattern) DO UPDATE SET confidence=$3, updated_at=NOW()
        `, [tenantId, pattern, threat.confidence]);
        synced++;
      }
    }
  }

  return synced;
}
