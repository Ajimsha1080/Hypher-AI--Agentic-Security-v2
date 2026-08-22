import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';

const START = Date.now();
const VERSION = process.env.npm_package_version || '0.2.0';

async function pgCheck(db: Pool) {
  const t = Date.now();
  try { await db.query('SELECT 1'); return { status: 'ok', latencyMs: Date.now() - t }; }
  catch (e: any) { return { status: 'fail', error: e.message }; }
}
async function redisCheck(redis: Redis) {
  const t = Date.now();
  try { await redis.ping(); return { status: 'ok', latencyMs: Date.now() - t }; }
  catch (e: any) { return { status: 'fail', error: e.message }; }
}
async function policyCheck(db: Pool) {
  const t = Date.now();
  try {
    const r = await db.query('SELECT COUNT(*) FROM policies WHERE active=true');
    if (parseInt(r.rows[0].count, 10) === 0) return { status: 'fail', error: 'No active policies — fail-closed blocks all' };
    return { status: 'ok', latencyMs: Date.now() - t };
  } catch (e: any) { return { status: 'fail', error: e.message }; }
}
function runtimeCheck() {
  const production = process.env.NODE_ENV === 'production';
  if (production && !process.env.MCP_SERVER_URL) {
    return { status: 'fail', error: 'MCP_SERVER_URL is required in production' };
  }
  return {
    status: 'ok',
    production,
    upstreamConfigured: Boolean(process.env.MCP_SERVER_URL),
  };
}

export async function healthPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;

  fastify.get('/health/live', async () => ({ status: 'ok', uptime: Math.floor((Date.now() - START) / 1000) }));

  fastify.get('/health/ready', async (req, reply) => {
    const [pg, rd, pol] = await Promise.all([pgCheck(db), redisCheck(redis), policyCheck(db)]);
    const runtime = runtimeCheck();
    const ok = pg.status === 'ok' && rd.status === 'ok';
    const runtimeOk = runtime.status === 'ok';
    const health = {
      status: ok && runtimeOk ? (pol.status === 'ok' ? 'healthy' : 'degraded') : 'unhealthy',
      version: VERSION,
      uptime: Math.floor((Date.now() - START) / 1000),
      checks: { postgres: pg, redis: rd, policy: pol, runtime },
    };
    reply.code(ok && runtimeOk ? 200 : 503).send(health);
  });

  fastify.get('/health/diagnostics', async () => {
    const [pg, rd, pol] = await Promise.all([pgCheck(db), redisCheck(redis), policyCheck(db)]);
    const runtime = runtimeCheck();
    const mem = process.memoryUsage();
    return {
      status: pg.status === 'ok' && rd.status === 'ok' && runtime.status === 'ok' ? 'healthy' : 'unhealthy',
      version: VERSION,
      uptime: Math.floor((Date.now() - START) / 1000),
      checks: { postgres: pg, redis: rd, policy: pol, runtime },
      memory: { heapUsedMB: Math.round(mem.heapUsed / 1e6), rssMB: Math.round(mem.rss / 1e6) },
      node: process.version,
    };
  });
}

export function registerGracefulShutdown(fastify: FastifyInstance, db: Pool, redis: Redis) {
  const shutdown = async (sig: string) => {
    fastify.log.warn(`${sig} received — shutting down`);
    try {
      await fastify.close();
      await redis.quit();
      await db.end();
      process.exit(0);
    } catch (e) { process.exit(1); }
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('uncaughtException', (e) => { fastify.log.fatal(e); shutdown('uncaughtException'); });
  process.on('unhandledRejection', (r) => { fastify.log.fatal(r); shutdown('unhandledRejection'); });
}
