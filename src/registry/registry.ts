/**
 * registry/registry.ts v2 — checkRegistryTrust() now exported for proxy
 */
import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';

export type TrustLevel = 'trusted' | 'unverified' | 'suspicious' | 'blocked';
export interface TrustCheckResult {
  allowed: boolean; trustLevel: TrustLevel; trustScore?: number; warning?: string; reason?: string;
}

function parseJsonArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
    } catch {
      return value.split(',').map(v => v.trim()).filter(Boolean);
    }
  }
  return [];
}

function allowBrowserRoleHeaders(): boolean {
  return process.env.NODE_ENV !== 'production' || process.env.ALLOW_DEV_ROLE_HEADERS === 'true';
}

function isRegistryAdmin(req: any): boolean {
  const sessionRole = req.user?.role;
  const role = String(sessionRole || (allowBrowserRoleHeaders() ? req.headers?.['x-admin-role'] : '') || 'viewer');
  return ['local_admin', 'super_admin', 'security_analyst'].includes(role);
}

async function ensureRegistryEnterpriseSchema(db: Pool): Promise<void> {
  await db.query(`
    ALTER TABLE registry_servers
      ADD COLUMN IF NOT EXISTS owner_email TEXT,
      ADD COLUMN IF NOT EXISTS owner_team TEXT,
      ADD COLUMN IF NOT EXISTS allowed_tenants JSONB DEFAULT '[]',
      ADD COLUMN IF NOT EXISTS allowed_agents JSONB DEFAULT '[]',
      ADD COLUMN IF NOT EXISTS schema_json JSONB DEFAULT '{}'::jsonb,
      ADD COLUMN IF NOT EXISTS schema_validation TEXT DEFAULT 'unknown',
      ADD COLUMN IF NOT EXISTS last_reviewed_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS last_reviewed_by TEXT,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS registry_trust_history (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      server_id UUID NOT NULL REFERENCES registry_servers(id),
      previous_trust_level TEXT,
      new_trust_level TEXT,
      previous_trust_score INTEGER,
      new_trust_score INTEGER,
      changed_by TEXT,
      reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_registry_history_server ON registry_trust_history(server_id, created_at DESC)`);
}

async function clearRegistryTrustCache(redis: Redis, serverName: string): Promise<void> {
  const keys = await redis.keys(`registry:trust:${serverName}:*`).catch(() => []);
  if (keys.length) await redis.del(...keys).catch(() => {});
}

// FIX: exported so proxy/server.ts Layer 4 can call it directly
export async function checkRegistryTrust(
  serverName: string,
  db: Pool,
  redis: Redis,
  context: { tenantId?: string; agentId?: string } = {}
): Promise<TrustCheckResult> {
  const key = `registry:trust:${serverName}:${context.tenantId || '*'}:${context.agentId || '*'}`;
  const cached = await redis.get(key);
  if (cached) return JSON.parse(cached);
  await ensureRegistryEnterpriseSchema(db).catch(() => {});
  const r = await db.query(`SELECT trust_level, trust_score, checksum, allowed_tenants, allowed_agents FROM registry_servers WHERE name=$1 AND active=true`, [serverName]);
  if (!r.rows.length) {
    const res: TrustCheckResult = { allowed: true, trustLevel: 'unverified', warning: 'Server not in registry' };
    await redis.setex(key, 120, JSON.stringify(res)); return res;
  }
  const s = r.rows[0];
  const allowedTenants = parseJsonArray(s.allowed_tenants);
  if (context.tenantId && allowedTenants.length && !allowedTenants.includes(context.tenantId)) {
    const res: TrustCheckResult = { allowed: false, trustLevel: s.trust_level, trustScore: s.trust_score, reason: 'Tenant is not allowed for this MCP server' };
    await redis.setex(key, 120, JSON.stringify(res)); return res;
  }
  const allowedAgents = parseJsonArray(s.allowed_agents);
  if (context.agentId && allowedAgents.length && !allowedAgents.includes(context.agentId)) {
    const res: TrustCheckResult = { allowed: false, trustLevel: s.trust_level, trustScore: s.trust_score, reason: 'Agent is not allowed for this MCP server' };
    await redis.setex(key, 120, JSON.stringify(res)); return res;
  }
  const res: TrustCheckResult = s.trust_level === 'blocked'
    ? { allowed: false, trustLevel: 'blocked', reason: 'Blocked in community registry' }
    : { allowed: true, trustLevel: s.trust_level, trustScore: s.trust_score,
        warning: s.trust_level === 'suspicious' ? 'Server has suspicious activity reports' : undefined };
  await redis.setex(key, 300, JSON.stringify(res));
  return res;
}

export async function registryPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;
  await ensureRegistryEnterpriseSchema(db);

  fastify.get('/api/registry/servers', async (req: any) => {
    const { trust, category, q } = req.query as any;
    let query = `SELECT rs.*,
      (SELECT COUNT(*)::int FROM registry_reports rr WHERE rr.server_id=rs.id) AS report_count,
      COALESCE(jsonb_array_length(rs.allowed_tenants),0) AS allowed_tenant_count,
      COALESCE(jsonb_array_length(rs.allowed_agents),0) AS allowed_agent_count
      FROM registry_servers rs WHERE active=true`;
    const params: unknown[] = [];
    if (trust) { params.push(trust); query += ` AND rs.trust_level=$${params.length}`; }
    if (q) { params.push(`%${q}%`); query += ` AND (rs.name ILIKE $${params.length} OR rs.description ILIKE $${params.length})`; }
    query += ` ORDER BY trust_score DESC LIMIT 100`;
    const r = await db.query(query, params);
    return { servers: r.rows, total: r.rowCount };
  });

  fastify.get('/api/registry/servers/:name', async (req: any, reply) => {
    const r = await db.query(`SELECT * FROM registry_servers WHERE name=$1 AND active=true`, [req.params.name]);
    if (!r.rows.length) return reply.code(404).send({ error: 'Server not found' });
    const history = await db.query(`SELECT * FROM registry_trust_history WHERE server_id=$1 ORDER BY created_at DESC LIMIT 20`, [r.rows[0].id]);
    return { server: r.rows[0], history: history.rows };
  });

  fastify.post('/api/registry/check', async (req: any, reply) => {
    const { serverName, checksum } = req.body;
    const result = await checkRegistryTrust(serverName, db, redis);
    if (!result.allowed) return reply.code(403).send(result);
    if (checksum) {
      const r = await db.query(`SELECT checksum FROM registry_servers WHERE name=$1`, [serverName]);
      if (r.rows[0]?.checksum && r.rows[0].checksum !== checksum)
        return reply.code(403).send({ allowed: false, reason: 'Checksum mismatch' });
    }
    return result;
  });

  fastify.post('/api/registry/servers', async (req: any, reply) => {
    const { name, version, description, author, repoUrl, categories, tools, ownerEmail, ownerTeam, schemaJson } = req.body;
    const ex = await db.query(`SELECT id FROM registry_servers WHERE name=$1`, [name]);
    if (ex.rows.length) return reply.code(409).send({ error: 'Already registered' });
    const r = await db.query(
      `INSERT INTO registry_servers (name,version,description,author,repo_url,categories,tools,trust_level,trust_score,owner_email,owner_team,schema_json,schema_validation,last_reviewed_at,last_reviewed_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'unverified',50,$8,$9,$10,$11,NOW(),$12) RETURNING *`,
      [
        name, version, description, author, repoUrl, JSON.stringify(categories || []), JSON.stringify(tools || []),
        ownerEmail || null, ownerTeam || null, JSON.stringify(schemaJson || {}), schemaJson ? 'available' : 'missing',
        req.headers?.['x-admin-email'] || req.tenant?.id || 'self-registered',
      ]
    );
    return { server: r.rows[0] };
  });

  fastify.put('/api/registry/servers/:id/metadata', async (req: any, reply) => {
    if (!isRegistryAdmin(req)) return reply.code(403).send({ error: 'Requires tenant security/admin role' });
    const { ownerEmail, ownerTeam, allowedTenants, allowedAgents, schemaJson, schemaValidation } = req.body || {};
    const r = await db.query(
      `UPDATE registry_servers SET
         owner_email=$2,
         owner_team=$3,
         allowed_tenants=$4,
         allowed_agents=$5,
         schema_json=$6,
         schema_validation=$7,
         updated_at=NOW()
       WHERE id=$1 RETURNING *`,
      [
        req.params.id,
        ownerEmail || null,
        ownerTeam || null,
        JSON.stringify(parseJsonArray(allowedTenants)),
        JSON.stringify(parseJsonArray(allowedAgents)),
        JSON.stringify(schemaJson || {}),
        schemaValidation || (schemaJson ? 'available' : 'missing'),
      ]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'Server not found' });
    await clearRegistryTrustCache(redis, r.rows[0].name);
    return { updated: true, server: r.rows[0] };
  });

  fastify.post('/api/registry/servers/:id/review', async (req: any, reply) => {
    if (!isRegistryAdmin(req)) return reply.code(403).send({ error: 'Requires tenant security/admin role' });
    const reviewer = String(req.headers?.['x-admin-email'] || 'security-admin');
    const r = await db.query(
      `UPDATE registry_servers SET last_reviewed_at=NOW(), last_reviewed_by=$2, updated_at=NOW()
       WHERE id=$1 RETURNING id, name, last_reviewed_at, last_reviewed_by`,
      [req.params.id, reviewer]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'Server not found' });
    return { reviewed: true, server: r.rows[0] };
  });

  fastify.put('/api/registry/servers/:id/trust', async (req: any, reply) => {
    if (!isRegistryAdmin(req)) return reply.code(403).send({ error: 'Requires tenant security/admin role' });
    const { trustLevel, trustScore, verified, reason } = req.body || {};
    if (!['trusted', 'unverified', 'suspicious', 'blocked'].includes(trustLevel)) return reply.code(400).send({ error: 'Invalid trustLevel' });
    const before = await db.query(`SELECT id, name, trust_level, trust_score FROM registry_servers WHERE id=$1`, [req.params.id]);
    if (!before.rows.length) return reply.code(404).send({ error: 'Server not found' });
    const score = Math.max(0, Math.min(100, parseInt(trustScore, 10) || 0));
    const after = await db.query(
      `UPDATE registry_servers SET trust_level=$2, trust_score=$3, verified=$4, last_reviewed_at=NOW(), last_reviewed_by=$5, updated_at=NOW()
       WHERE id=$1 RETURNING *`,
      [req.params.id, trustLevel, score, Boolean(verified), String(req.headers?.['x-admin-email'] || 'security-admin')]
    );
    await db.query(
      `INSERT INTO registry_trust_history (server_id, previous_trust_level, new_trust_level, previous_trust_score, new_trust_score, changed_by, reason)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [req.params.id, before.rows[0].trust_level, trustLevel, before.rows[0].trust_score, score, String(req.headers?.['x-admin-email'] || 'security-admin'), reason || 'trust update']
    );
    await clearRegistryTrustCache(redis, before.rows[0].name);
    return { updated: true, server: after.rows[0] };
  });

  fastify.post('/api/registry/reports', async (req: any) => {
    const { serverId, reportType, description, evidence } = req.body;
    await db.query(
      `INSERT INTO registry_reports (server_id,report_type,description,reported_by,evidence) VALUES ($1,$2,$3,$4,$5)`,
      [serverId, reportType, description, req.tenant?.id || 'anonymous', evidence]
    );
    const cnt = await db.query(`SELECT COUNT(*) FROM registry_reports WHERE server_id=$1 AND created_at>NOW()-INTERVAL '30d'`, [serverId]);
    if (parseInt(cnt.rows[0].count, 10) >= 3)
      await db.query(`UPDATE registry_servers SET trust_level='suspicious',trust_score=LEAST(30,trust_score) WHERE id=$1 AND trust_level!='blocked'`, [serverId]);
    return { reported: true };
  });

  fastify.get('/api/registry/stats', async () => {
    const r = await db.query(`SELECT COUNT(*) as total,
      COUNT(*) FILTER (WHERE trust_level='trusted') as trusted,
      COUNT(*) FILTER (WHERE trust_level='suspicious') as suspicious,
      COUNT(*) FILTER (WHERE trust_level='blocked') as blocked,
      AVG(trust_score)::numeric(5,1) as avg_score FROM registry_servers WHERE active=true`);
    return r.rows[0];
  });
}

export function computeServerChecksum(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
