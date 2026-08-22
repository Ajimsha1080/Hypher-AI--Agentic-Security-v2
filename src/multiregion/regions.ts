/**
 * Multi-Region Deployment — M2-3
 *
 * Adds EU-West, US-East, APAC region support with data residency enforcement.
 * Each region has isolated Postgres + Redis.
 * Tenants are pinned to a region. EU tenants' data never leaves eu-west.
 *
 * Architecture:
 *   eu-west  → postgres-eu / redis-eu  (Frankfurt / Dublin)
 *   us-east  → postgres-us / redis-us  (Virginia / Ohio)
 *   apac     → postgres-ap / redis-ap  (Singapore / Tokyo)
 *
 * GDPR compliance: EU tenant data is physically isolated.
 * Runtime: env var REGION=eu-west routes all DB/Redis calls to EU infra.
 */

import { Pool } from 'pg';
import Redis from 'ioredis';

export type Region = 'us-east' | 'eu-west' | 'apac';

export interface RegionConfig {
  region: Region;
  databaseUrl: string;
  redisUrl: string;
  displayName: string;
  gdprCompliant: boolean;
  latencyZone: string;    // Cloud region label for latency routing
}

// ── Region registry ────────────────────────────────────────────────────

const REGION_CONFIGS: Record<Region, RegionConfig> = {
  'us-east': {
    region: 'us-east',
    databaseUrl: process.env.DATABASE_URL_US || process.env.DATABASE_URL || '',
    redisUrl: process.env.REDIS_URL_US || process.env.REDIS_URL || '',
    displayName: 'US East (Virginia)',
    gdprCompliant: false,
    latencyZone: 'us-east-1',
  },
  'eu-west': {
    region: 'eu-west',
    databaseUrl: process.env.DATABASE_URL_EU || '',
    redisUrl: process.env.REDIS_URL_EU || '',
    displayName: 'EU West (Frankfurt)',
    gdprCompliant: true,
    latencyZone: 'eu-central-1',
  },
  'apac': {
    region: 'apac',
    databaseUrl: process.env.DATABASE_URL_APAC || '',
    redisUrl: process.env.REDIS_URL_APAC || '',
    displayName: 'Asia-Pacific (Singapore)',
    gdprCompliant: false,
    latencyZone: 'ap-southeast-1',
  },
};

// ── Infrastructure factory ─────────────────────────────────────────────

export interface RegionalInfra {
  db: Pool;
  redis: Redis;
  region: Region;
  config: RegionConfig;
}

const _infraCache = new Map<Region, RegionalInfra>();

export function getRegionalInfra(region: Region): RegionalInfra {
  if (_infraCache.has(region)) return _infraCache.get(region)!;

  const config = REGION_CONFIGS[region];
  if (!config.databaseUrl) {
    throw new Error(
      `Region '${region}' is not configured. Set DATABASE_URL_${region.toUpperCase().replace('-', '_')} and REDIS_URL_${region.toUpperCase().replace('-', '_')} in .env`
    );
  }

  const db = new Pool({
    connectionString: config.databaseUrl,
    max: 20,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: `mcp-security-${region}`,
  });

  const redis = new Redis(config.redisUrl, {
    maxRetriesPerRequest: 3,
    lazyConnect: true,
    keyPrefix: `${region}:`,  // namespace keys by region to prevent collisions
  });

  const infra: RegionalInfra = { db, redis, region, config };
  _infraCache.set(region, infra);
  return infra;
}

// ── Active region ──────────────────────────────────────────────────────

export function getActiveRegion(): Region {
  const env = process.env.REGION as Region | undefined;
  const valid: Region[] = ['us-east', 'eu-west', 'apac'];
  if (env && valid.includes(env)) return env;
  return 'us-east'; // default
}

export function getActiveInfra(): RegionalInfra {
  return getRegionalInfra(getActiveRegion());
}

// ── Tenant region enforcement ──────────────────────────────────────────

export async function getTenantRegion(tenantId: string, db: Pool): Promise<Region> {
  const r = await db.query(
    `SELECT preferred_region FROM tenants WHERE id=$1`,
    [tenantId]
  );
  return (r.rows[0]?.preferred_region as Region) || getActiveRegion();
}

export async function setTenantRegion(tenantId: string, region: Region, db: Pool): Promise<void> {
  const config = REGION_CONFIGS[region];
  if (!config) throw new Error(`Unknown region: ${region}`);

  await db.query(
    `UPDATE tenants SET preferred_region=$1, data_residency=$2 WHERE id=$3`,
    [region, config.latencyZone, tenantId]
  );
}

export async function getInfraForTenant(tenantId: string, defaultDb: Pool): Promise<RegionalInfra> {
  const region = await getTenantRegion(tenantId, defaultDb);
  return getRegionalInfra(region);
}

// ── GDPR enforcement ──────────────────────────────────────────────────

export async function enforceDataResidency(
  tenantId: string,
  requestRegion: Region,
  db: Pool
): Promise<{ allowed: boolean; reason?: string; redirectTo?: Region }> {
  const tenantRegion = await getTenantRegion(tenantId, db);

  if (tenantRegion === requestRegion) {
    return { allowed: true };
  }

  const tenantConfig = REGION_CONFIGS[tenantRegion];

  // EU tenants can ONLY be served from EU — GDPR hard requirement
  if (tenantConfig.gdprCompliant && requestRegion !== 'eu-west') {
    return {
      allowed: false,
      reason: `GDPR data residency violation: tenant is pinned to ${tenantConfig.displayName}`,
      redirectTo: tenantRegion,
    };
  }

  // Non-EU tenants can be served from any region (for latency)
  return { allowed: true };
}

// ── Fastify plugin ────────────────────────────────────────────────────

export async function multiRegionPlugin(fastify: any, opts: { db: Pool }) {
  const { db } = opts;
  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  // List available regions
  fastify.get('/api/regions', async () => {
    return {
      regions: Object.values(REGION_CONFIGS).map(r => ({
        region: r.region,
        displayName: r.displayName,
        gdprCompliant: r.gdprCompliant,
        available: !!r.databaseUrl,
      })),
      current: getActiveRegion(),
    };
  });

  // Get tenant's region
  fastify.get('/api/regions/my', async (req, reply) => {
    const tenant = await tenantFrom(req);
    if (!['growth','enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Data residency requires Growth or Enterprise plan' });
    }
    const region = await getTenantRegion(tenant.id, db);
    const config = REGION_CONFIGS[region];
    return {
      region,
      displayName: config.displayName,
      gdprCompliant: config.gdprCompliant,
    };
  });

  // Set tenant's preferred region
  fastify.post('/api/regions/set', async (req: any, reply: any) => {
    const tenant = await tenantFrom(req);
    if (!['growth','enterprise'].includes(tenant?.plan)) {
      return reply.code(402).send({ error: 'Data residency requires Growth or Enterprise plan' });
    }
    const { region } = req.body;
    if (!REGION_CONFIGS[region as Region]) {
      return reply.code(400).send({ error: `Invalid region. Choose: ${Object.keys(REGION_CONFIGS).join(', ')}` });
    }

    if (!REGION_CONFIGS[region as Region].databaseUrl) {
      return reply.code(400).send({ error: `Region '${region}' is not yet available` });
    }

    await setTenantRegion(tenant.id, region as Region, db);
    return {
      set: true,
      region,
      message: `Your data will now be stored in ${REGION_CONFIGS[region as Region].displayName}. This takes effect immediately for new data.`,
    };
  });
}

// ── Migration 005: region columns ─────────────────────────────────────
// Run: psql $DATABASE_URL -c "$(cat src/multiregion/migration.sql)"
export const MIGRATION_SQL = `
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS preferred_region TEXT DEFAULT 'us-east'
    CHECK (preferred_region IN ('us-east', 'eu-west', 'apac')),
  ADD COLUMN IF NOT EXISTS data_residency   TEXT DEFAULT 'us-east-1';

CREATE INDEX IF NOT EXISTS idx_tenants_region ON tenants(preferred_region);

-- Set EU tenants based on billing email domain (retroactive)
-- UPDATE tenants SET preferred_region='eu-west', data_residency='eu-central-1'
-- WHERE billing_email LIKE '%.eu' OR billing_email LIKE '%.de' OR billing_email LIKE '%.fr';
`;
