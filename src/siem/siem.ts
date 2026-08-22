/**
 * SIEM Integration — NEW Enterprise Feature
 * Forwards audit events to Splunk, Datadog, Elastic, or generic HTTP.
 * Events are batched (5s windows) to reduce API calls.
 */
import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import axios from 'axios';
import { decryptValue, encryptValue } from '../security/secrets';

export interface AuditEvent {
  tenantId: string; agentId: string; toolName: string;
  decision: string; reason?: string; executionTimeMs?: number;
  authProvider?: string; sourceIp?: string; timestamp: string;
}

const queues = new Map<string, AuditEvent[]>();

export function queueSiemEvent(tenantId: string, event: AuditEvent) {
  if (!queues.has(tenantId)) queues.set(tenantId, []);
  queues.get(tenantId)!.push(event);
}

export async function siemPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;
  await ensureSiemSchema(db);
  startFlushLoop(db);

  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  fastify.get('/api/siem/config', async (req, reply) => {
    const tenant = await tenantFrom(req);
    if (tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SIEM forwarding requires Enterprise plan' });
    }
    const r = await db.query(`SELECT provider, endpoint, index_name, tags, batch_size, active FROM siem_configs WHERE tenant_id=$1`, [tenant.id]);
    return { configs: r.rows };
  });

  fastify.post('/api/siem/config', async (req, reply) => {
    const tenant = await tenantFrom(req);
    if (tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SIEM forwarding requires Enterprise plan' });
    }
    const { provider, endpoint, apiKey, index, tags, batchSize } = (req.body as any);
    const encryptedKey = encryptValue(apiKey || '');
    await db.query(
      `INSERT INTO siem_configs (tenant_id, provider, endpoint, api_key_encrypted, api_key_enc, index_name, tags, batch_size)
       VALUES ($1,$2,$3,$4,$4,$5,$6,$7)
       ON CONFLICT (tenant_id, provider) DO UPDATE SET endpoint=$3, api_key_encrypted=$4, api_key_enc=$4, index_name=$5, tags=$6, batch_size=$7, updated_at=NOW()`,
      [tenant.id, provider, endpoint, encryptedKey, index, JSON.stringify(tags||[]), batchSize||100]
    );
    return { configured: true };
  });

  fastify.post('/api/siem/test', async (req: any, reply) => {
    const tenant = await tenantFrom(req);
    if (tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SIEM forwarding requires Enterprise plan' });
    }
    const r = await db.query(`SELECT * FROM siem_configs WHERE tenant_id=$1 AND provider=$2`, [tenant.id, (req.body as any).provider]);
    if (!r.rows.length) return reply.code(404).send({ error: 'SIEM not configured' });
    const cfg = r.rows[0];
    await send(cfg.provider, [{
      tenantId: tenant.id, agentId: 'test', toolName: 'test_tool',
      decision: 'ALLOW', executionTimeMs: 1, timestamp: new Date().toISOString(),
    }], { ...cfg, apiKey: decryptValue(cfg.api_key_encrypted || cfg.api_key_enc || '') });
    return { sent: true };
  });

  fastify.delete('/api/siem/config/:provider', async (req, reply) => {
    const tenant = await tenantFrom(req);
    if (tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SIEM forwarding requires Enterprise plan' });
    }
    await db.query(`DELETE FROM siem_configs WHERE tenant_id=$1 AND provider=$2`, [tenant.id, (req.params as any).provider]);
    return { deleted: true };
  });
}

async function ensureSiemSchema(db: Pool) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS siem_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      provider TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      api_key_encrypted TEXT,
      api_key_enc TEXT,
      index_name TEXT,
      tags JSONB DEFAULT '[]',
      batch_size INTEGER DEFAULT 100,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(tenant_id, provider)
    )
  `);
  await db.query(`
    ALTER TABLE siem_configs
      ADD COLUMN IF NOT EXISTS api_key_encrypted TEXT,
      ADD COLUMN IF NOT EXISTS api_key_enc TEXT,
      ADD COLUMN IF NOT EXISTS index_name TEXT,
      ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]',
      ADD COLUMN IF NOT EXISTS batch_size INTEGER DEFAULT 100,
      ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()
  `);
  await db.query(`ALTER TABLE siem_configs ALTER COLUMN api_key_enc DROP NOT NULL`).catch(() => {});
  await db.query(`ALTER TABLE siem_configs ALTER COLUMN api_key_encrypted DROP NOT NULL`).catch(() => {});
  await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_siem_tenant_provider_unique ON siem_configs(tenant_id, provider)`);
}

function startFlushLoop(db: Pool) {
  setInterval(async () => {
    for (const [tenantId, events] of queues.entries()) {
      if (!events.length) continue;
      const batch = events.splice(0, events.length);
      try {
        const cfgs = await db.query(`SELECT * FROM siem_configs WHERE tenant_id=$1 AND active=true`, [tenantId]);
        for (const cfg of cfgs.rows) {
          await send(cfg.provider, batch, { ...cfg, apiKey: decryptValue(cfg.api_key_encrypted || cfg.api_key_enc || '') });
        }
      } catch (e) { console.error('[siem] flush error:', e); }
    }
  }, 5000);
}

async function send(provider: string, events: AuditEvent[], cfg: any) {
  switch (provider) {
    case 'splunk':
      await axios.post(cfg.endpoint, events.map(e => JSON.stringify({ time: Date.now()/1000, event: e })).join('\n'),
        { headers: { Authorization: `Splunk ${cfg.apiKey}`, 'Content-Type': 'application/x-ndjson' }, timeout: 10000 });
      break;
    case 'datadog':
      await axios.post(cfg.endpoint || 'https://http-intake.logs.datadoghq.com/api/v2/logs',
        events.map(e => ({ ddsource: 'mcp-security', service: 'mcp-gateway', message: JSON.stringify(e), ...e })),
        { headers: { 'DD-API-KEY': cfg.apiKey, 'Content-Type': 'application/json' }, timeout: 10000 });
      break;
    case 'elastic':
      const bulkBody = events.flatMap(e => [
        JSON.stringify({ index: { _index: cfg.index_name || 'mcp-security-audit' } }),
        JSON.stringify(e)
      ]).join('\n') + '\n';
      await axios.post(`${cfg.endpoint}/_bulk`, bulkBody,
        { headers: { Authorization: `ApiKey ${cfg.apiKey}`, 'Content-Type': 'application/x-ndjson' }, timeout: 10000 });
      break;
    default:
      await axios.post(cfg.endpoint, { events },
        { headers: { Authorization: `Bearer ${cfg.apiKey}`, 'Content-Type': 'application/json' }, timeout: 10000 });
  }
}
