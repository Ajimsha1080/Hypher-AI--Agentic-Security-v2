/**
 * IP Allowlist — Per-Tenant Access Control
 *
 * Sprint 3 enterprise feature. Tenants on Enterprise plan can restrict
 * which IP addresses / CIDR ranges can call their gateway endpoint.
 *
 * - Allowlist stored in tenant_ip_allowlists table (audit/schema.sql)
 * - Checked BEFORE auth (fail fast on blocked IPs)
 * - Cached in Redis per tenant (60s TTL) to avoid DB hit every request
 * - If no allowlist configured → all IPs allowed (opt-in model)
 *
 * Routes added:
 *   GET  /api/ip-allowlist           List current tenant's allowlist
 *   POST /api/ip-allowlist           Add a CIDR entry
 *   DEL  /api/ip-allowlist/:id       Remove an entry
 */

import { FastifyInstance, FastifyRequest } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import { requestTenantId } from '../utils/request-context';

// ── CIDR check ────────────────────────────────────────────────────────

function ipToLong(ip: string): number {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = bits ? ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0 : 0xffffffff;
    return (ipToLong(ip) & mask) === (ipToLong(range) & mask);
  } catch { return false; }
}

// ── Check incoming IP against tenant's allowlist ───────────────────────

export async function checkIpAllowlist(
  tenantId: string,
  sourceIp: string,
  db: Pool,
  redis: Redis
): Promise<{ allowed: boolean; reason?: string }> {
  const cacheKey = `ip_allowlist:${tenantId}`;

  let cidrs: string[];
  const cached = await redis.get(cacheKey);
  if (cached) {
    cidrs = JSON.parse(cached);
  } else {
    const r = await db.query(
      `SELECT cidr::text FROM tenant_ip_allowlists WHERE tenant_id=$1 AND active=TRUE`,
      [tenantId]
    );
    cidrs = r.rows.map((row: any) => row.cidr);
    await redis.setex(cacheKey, 60, JSON.stringify(cidrs));
  }

  // No allowlist configured → allow all (opt-in)
  if (!cidrs.length) return { allowed: true };

  // Strip IPv6-mapped IPv4 prefix (::ffff:1.2.3.4 → 1.2.3.4)
  const cleanIp = sourceIp.replace(/^::ffff:/, '');

  const matched = cidrs.some(cidr => ipInCidr(cleanIp, cidr));
  if (!matched) {
    return {
      allowed: false,
      reason: `IP ${cleanIp} not in tenant allowlist`,
    };
  }
  return { allowed: true };
}

// ── Fastify plugin ────────────────────────────────────────────────────

export async function ipAllowlistPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;

  // GET /api/ip-allowlist
  fastify.get('/api/ip-allowlist', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, cidr::text, description, created_at
       FROM tenant_ip_allowlists WHERE tenant_id=$1 AND active=TRUE
       ORDER BY created_at DESC`,
      [tenantId]
    );
    return { entries: r.rows };
  });

  // POST /api/ip-allowlist
  fastify.post('/api/ip-allowlist', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    // Enterprise only
    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['growth','enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'IP allowlists require Enterprise plan' });
    }

    const { cidr, description } = req.body as any;
    if (!cidr) return reply.code(400).send({ error: 'cidr required' });

    // Validate CIDR format
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (!cidrPattern.test(cidr)) {
      return reply.code(400).send({ error: 'Invalid CIDR format. Use x.x.x.x or x.x.x.x/nn' });
    }

    try {
      const r = await db.query(
        `INSERT INTO tenant_ip_allowlists (tenant_id, cidr, description)
         VALUES ($1, $2::inet, $3) RETURNING id, cidr::text, description`,
        [tenantId, cidr, description || null]
      );
      // Invalidate cache
      await redis.del(`ip_allowlist:${tenantId}`);
      return { added: r.rows[0] };
    } catch (err: any) {
      if (err.code === '23505') return reply.code(409).send({ error: 'CIDR already in allowlist' });
      throw err;
    }
  });

  // DELETE /api/ip-allowlist/:id
  fastify.delete('/api/ip-allowlist/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      `UPDATE tenant_ip_allowlists SET active=FALSE WHERE id=$1 AND tenant_id=$2`,
      [req.params.id, tenantId]
    );
    await redis.del(`ip_allowlist:${tenantId}`);
    return { removed: true };
  });
}
