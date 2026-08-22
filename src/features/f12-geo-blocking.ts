/**
 * F12 — Geo-Blocking / Country Allowlist
 *
 * Blocks or allows requests by country code.
 * Uses ip-api.com (free, no key) with Redis caching (1h TTL).
 * Operates in two modes per tenant:
 *   block-mode  — listed countries are DENIED (denylist)
 *   allow-mode  — only listed countries are ALLOWED (allowlist)
 *
 * source_country column already exists in audit_log from migration 003.
 *
 * Routes:
 *   GET  /api/geo-blocks          List tenant's geo rules
 *   POST /api/geo-blocks          Add a country rule
 *   DEL  /api/geo-blocks/:id      Remove a rule
 *   GET  /api/geo-blocks/lookup   Look up country for an IP
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import axios from 'axios';

export interface GeoCheckResult {
  allowed: boolean;
  country?: string;
  reason?: string;
}

// ── Country lookup with Redis cache ───────────────────────────────────

async function lookupCountry(ip: string, redis: Redis, db: Pool): Promise<string | null> {
  // Strip IPv6-mapped IPv4
  const cleanIp = ip.replace(/^::ffff:/, '');

  // localhost / private ranges → skip geo check
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(cleanIp) ||
      cleanIp === '::1') {
    return null; // no country = allow
  }

  const ipHash = crypto.createHash('sha256').update(cleanIp).digest('hex').slice(0, 16);
  const cacheKey = `geo:${ipHash}`;

  // Check Redis cache first
  const cached = await redis.get(cacheKey).catch(() => null);
  if (cached) return cached === 'XX' ? null : cached;

  // Check DB cache
  const dbCached = await db.query(
    `SELECT country_code FROM ip_country_cache WHERE ip_hash=$1
     AND cached_at > NOW() - INTERVAL '24 hours'`,
    [ipHash]
  ).then(r => r.rows[0]?.country_code).catch(() => null);

  if (dbCached) {
    await redis.setex(cacheKey, 3600, dbCached || 'XX');
    return dbCached || null;
  }

  // Call ip-api.com (free, 45 req/min)
  try {
    const resp = await axios.get(
      `http://ip-api.com/json/${cleanIp}?fields=countryCode,status`,
      { timeout: 2000 }
    );
    const country = resp.data?.status === 'success' ? resp.data.countryCode : null;
    const code = country || 'XX';

    // Cache in Redis (1 hour) and DB (24 hours)
    await redis.setex(cacheKey, 3600, code).catch(() => {});
    await db.query(
      `INSERT INTO ip_country_cache (ip_hash, country_code)
       VALUES ($1,$2) ON CONFLICT (ip_hash) DO UPDATE
       SET country_code=$2, cached_at=NOW()`,
      [ipHash, country]
    ).catch(() => {});

    return country;
  } catch {
    return null; // fail open — geo lookup failures never block requests
  }
}

// ── Core check (called from /mcp pipeline) ────────────────────────────

export async function checkGeoBlock(
  tenantId: string,
  sourceIp: string,
  db: Pool,
  redis: Redis
): Promise<GeoCheckResult> {
  // Get tenant's geo rules
  const rules = await db.query(
    `SELECT country_code, mode FROM tenant_geo_blocks
     WHERE tenant_id=$1 AND active=TRUE`,
    [tenantId]
  ).then(r => r.rows).catch(() => []);

  if (!rules.length) return { allowed: true }; // no rules = allow all

  const country = await lookupCountry(sourceIp, redis, db);
  if (!country) return { allowed: true }; // unknown country = allow (fail open)

  const hasAllowMode = rules.some((r: any) => r.mode === 'allow');

  if (hasAllowMode) {
    // Allowlist mode — only listed countries are permitted
    const inList = rules.some((r: any) => r.mode === 'allow' && r.country_code === country);
    if (!inList) {
      return {
        allowed: false,
        country,
        reason: `geo_not_in_allowlist:${country}`,
      };
    }
  } else {
    // Denylist mode — listed countries are blocked
    const blocked = rules.some((r: any) => r.mode === 'block' && r.country_code === country);
    if (blocked) {
      return {
        allowed: false,
        country,
        reason: `geo_blocked:${country}`,
      };
    }
  }

  return { allowed: true, country };
}

// ── Fastify plugin ────────────────────────────────────────────────────

async function hasGrowthOrEnterprisePlan(req: any, db: Pool): Promise<boolean> {
  if (['growth', 'enterprise'].includes(req.tenant?.plan)) return true;
  const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
  if (!tenantId) return false;
  const r = await db.query(`SELECT plan FROM tenants WHERE id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [] as any[] }));
  return ['growth', 'enterprise'].includes(r.rows[0]?.plan);
}
export async function geoBlockPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;

  // GET /api/geo-blocks
  fastify.get('/api/geo-blocks', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Geo-blocking requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, country_code, mode, description, created_at
       FROM tenant_geo_blocks WHERE tenant_id=$1 AND active=TRUE
       ORDER BY mode, country_code`,
      [tenantId]
    );
    return { rules: r.rows };
  });

  // POST /api/geo-blocks
  fastify.post('/api/geo-blocks', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Geo-blocking requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { countryCode, mode = 'block', description } = req.body as any;
    if (!countryCode) return reply.code(400).send({ error: 'countryCode required (ISO 3166-1 alpha-2)' });
    if (!/^[A-Z]{2}$/.test(countryCode.toUpperCase())) {
      return reply.code(400).send({ error: 'countryCode must be 2 uppercase letters (e.g. US, GB, CN)' });
    }
    if (!['block', 'allow'].includes(mode)) {
      return reply.code(400).send({ error: 'mode must be block or allow' });
    }

    const r = await db.query(
      `INSERT INTO tenant_geo_blocks (tenant_id, country_code, mode, description)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (tenant_id, country_code) DO UPDATE
         SET mode=$3, description=$4, active=TRUE
       RETURNING *`,
      [tenantId, countryCode.toUpperCase(), mode, description || null]
    );
    return { created: r.rows[0] };
  });

  // DELETE /api/geo-blocks/:id
  fastify.delete('/api/geo-blocks/:id', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Geo-blocking requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      'UPDATE tenant_geo_blocks SET active=FALSE WHERE id=$1 AND tenant_id=$2',
      [(req.params as any).id, tenantId]
    );
    return { removed: true };
  });

  // GET /api/geo-blocks/lookup?ip=1.2.3.4
  fastify.get('/api/geo-blocks/lookup', async (req: any, reply) => {
    if (!(await hasGrowthOrEnterprisePlan(req, db))) {
      return reply.code(402).send({ error: 'Geo-blocking requires Growth or Enterprise plan' });
    }
    const tenantId = req.tenant?.id || req.headers?.['x-tenant-id'];
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const { ip } = req.query as any;
    if (!ip) return reply.code(400).send({ error: 'ip query param required' });
    const country = await lookupCountry(ip, redis, db);
    return { ip, country: country || 'unknown' };
  });
}
