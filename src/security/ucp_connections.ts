import { Pool } from 'pg';
import { FastifyInstance } from 'fastify';
import crypto from 'crypto';
import https from 'https';
import http from 'http';
import { requestTenantId } from '../utils/request-context';

// ── Encryption helpers for API keys ────────────────────────────────
const ENC_KEY = process.env.UCP_ENCRYPTION_KEY || process.env.JWT_SECRET || 'default-32-char-key-change-this!';
const ENC_ALGO = 'aes-256-gcm';

function encrypt(text: string): string {
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(ENC_KEY, 'ucp-salt', 32);
  const cipher = crypto.createCipheriv(ENC_ALGO, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function decrypt(data: string): string {
  const [ivHex, tagHex, enc] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const key = crypto.scryptSync(ENC_KEY, 'ucp-salt', 32);
  const decipher = crypto.createDecipheriv(ENC_ALGO, key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(enc, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ── Health check helper ─────────────────────────────────────────────
async function probeEndpoint(url: string, timeoutMs = 8000): Promise<{ status: string; latencyMs: number; tls: boolean; error?: string }> {
  const start = Date.now();
  const isHttps = url.startsWith('https');

  return new Promise((resolve) => {
    const mod = isHttps ? https : http;
    const req = mod.get(url, { timeout: timeoutMs, rejectUnauthorized: true }, (res) => {
      const latencyMs = Date.now() - start;
      const code = res.statusCode || 0;
      let status = 'healthy';
      if (code >= 500) status = 'down';
      else if (code >= 400) status = 'degraded';
      res.resume();
      resolve({ status, latencyMs, tls: isHttps });
    });
    req.on('error', (err: any) => {
      resolve({ status: 'down', latencyMs: Date.now() - start, tls: false, error: err.message });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 'down', latencyMs: timeoutMs, tls: false, error: 'Connection timed out' });
    });
  });
}

// ── Log connection event ────────────────────────────────────────────
async function logConnectionEvent(db: Pool, connectionId: string, tenantId: string, eventType: string, details: any = {}) {
  await db.query(
    'INSERT INTO ucp_connection_events (connection_id, tenant_id, event_type, details) VALUES ($1, $2, $3, $4)',
    [connectionId, tenantId, eventType, JSON.stringify(details)]
  );
}

// ── Fastify Plugin ──────────────────────────────────────────────────
export async function ucpConnectionPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;

  // GET /api/ucp/connections — list all connections for tenant
  fastify.get('/api/ucp/connections', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, name, provider, endpoint_url, auth_type, status, last_health_check,
              last_health_status, health_latency_ms, tls_verified, allowed_methods, metadata, created_at, updated_at
       FROM ucp_connections WHERE tenant_id = $1 ORDER BY created_at DESC`,
      [tenantId]
    );
    return { connections: r.rows };
  });

  // POST /api/ucp/connections — create a new connection
  fastify.post('/api/ucp/connections', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { name, provider, endpointUrl, apiKey, authType, webhookSecret, allowedMethods, metadata } = req.body as any;
    if (!name || !endpointUrl) {
      return reply.code(400).send({ error: 'name and endpointUrl are required' });
    }

    const encKey = apiKey ? encrypt(apiKey) : null;
    const encWebhook = webhookSecret ? encrypt(webhookSecret) : null;

    const r = await db.query(
      `INSERT INTO ucp_connections (tenant_id, name, provider, endpoint_url, api_key_encrypted, auth_type, webhook_secret, allowed_methods, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, name, provider, endpoint_url, auth_type, status, allowed_methods, metadata, created_at`,
      [tenantId, name, provider || 'custom', endpointUrl, encKey, authType || 'bearer', encWebhook,
       allowedMethods || ['cart/add', 'cart/update', 'checkout', 'payment', 'identity', 'loyalty'],
       JSON.stringify(metadata || {})]
    );

    await logConnectionEvent(db, r.rows[0].id, tenantId, 'created', { name, provider, endpointUrl });
    return { connection: r.rows[0] };
  });

  // PUT /api/ucp/connections/:id — update a connection
  fastify.put('/api/ucp/connections/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const { name, provider, endpointUrl, apiKey, authType, webhookSecret, allowedMethods, metadata } = req.body as any;

    // Build dynamic SET clause
    const sets: string[] = [];
    const vals: any[] = [];
    let idx = 1;

    if (name !== undefined) { sets.push(`name = $${idx++}`); vals.push(name); }
    if (provider !== undefined) { sets.push(`provider = $${idx++}`); vals.push(provider); }
    if (endpointUrl !== undefined) { sets.push(`endpoint_url = $${idx++}`); vals.push(endpointUrl); }
    if (apiKey !== undefined) { sets.push(`api_key_encrypted = $${idx++}`); vals.push(encrypt(apiKey)); }
    if (authType !== undefined) { sets.push(`auth_type = $${idx++}`); vals.push(authType); }
    if (webhookSecret !== undefined) { sets.push(`webhook_secret = $${idx++}`); vals.push(encrypt(webhookSecret)); }
    if (allowedMethods !== undefined) { sets.push(`allowed_methods = $${idx++}`); vals.push(allowedMethods); }
    if (metadata !== undefined) { sets.push(`metadata = $${idx++}`); vals.push(JSON.stringify(metadata)); }
    sets.push(`updated_at = NOW()`);

    if (sets.length <= 1) return reply.code(400).send({ error: 'No fields to update' });

    vals.push(id, tenantId);
    const r = await db.query(
      `UPDATE ucp_connections SET ${sets.join(', ')} WHERE id = $${idx++} AND tenant_id = $${idx}
       RETURNING id, name, provider, endpoint_url, auth_type, status, allowed_methods, metadata, updated_at`,
      vals
    );
    if (r.rows.length === 0) return reply.code(404).send({ error: 'Connection not found' });

    await logConnectionEvent(db, id, tenantId, 'updated', { fields: Object.keys(req.body as any) });
    return { connection: r.rows[0] };
  });

  // DELETE /api/ucp/connections/:id — remove a connection
  fastify.delete('/api/ucp/connections/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const existing = await db.query('SELECT name FROM ucp_connections WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
    if (existing.rows.length === 0) return reply.code(404).send({ error: 'Connection not found' });

    await db.query('DELETE FROM ucp_connections WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
    return { removed: true, name: existing.rows[0].name };
  });

  // POST /api/ucp/connections/:id/activate — toggle active
  fastify.post('/api/ucp/connections/:id/activate', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const r = await db.query(
      `UPDATE ucp_connections SET status = 'active', updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING id, name, status`,
      [id, tenantId]
    );
    if (r.rows.length === 0) return reply.code(404).send({ error: 'Connection not found' });

    await logConnectionEvent(db, id, tenantId, 'activated', {});
    return { connection: r.rows[0] };
  });

  // POST /api/ucp/connections/:id/deactivate — toggle inactive
  fastify.post('/api/ucp/connections/:id/deactivate', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const r = await db.query(
      `UPDATE ucp_connections SET status = 'inactive', updated_at = NOW() WHERE id = $1 AND tenant_id = $2 RETURNING id, name, status`,
      [id, tenantId]
    );
    if (r.rows.length === 0) return reply.code(404).send({ error: 'Connection not found' });

    await logConnectionEvent(db, id, tenantId, 'deactivated', {});
    return { connection: r.rows[0] };
  });

  // POST /api/ucp/connections/:id/test — run health check
  fastify.post('/api/ucp/connections/:id/test', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const conn = await db.query('SELECT endpoint_url FROM ucp_connections WHERE id = $1 AND tenant_id = $2', [id, tenantId]);
    if (conn.rows.length === 0) return reply.code(404).send({ error: 'Connection not found' });

    const probe = await probeEndpoint(conn.rows[0].endpoint_url);

    await db.query(
      `UPDATE ucp_connections SET last_health_check = NOW(), last_health_status = $1, health_latency_ms = $2, tls_verified = $3, updated_at = NOW()
       WHERE id = $4 AND tenant_id = $5`,
      [probe.status, probe.latencyMs, probe.tls, id, tenantId]
    );

    const eventType = probe.status === 'healthy' ? 'test_success' : 'test_fail';
    await logConnectionEvent(db, id, tenantId, eventType, probe);

    return { result: probe };
  });

  // GET /api/ucp/connections/:id/events — get event log for a connection
  fastify.get('/api/ucp/connections/:id/events', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { id } = req.params as any;
    const r = await db.query(
      `SELECT id, event_type, details, created_at FROM ucp_connection_events WHERE connection_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT 50`,
      [id, tenantId]
    );
    return { events: r.rows };
  });

  // GET /api/ucp/connections/summary — aggregate stats
  fastify.get('/api/ucp/connections/summary', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT
         COUNT(*)::int AS total,
         COUNT(*) FILTER (WHERE status = 'active')::int AS active,
         COUNT(*) FILTER (WHERE status = 'inactive')::int AS inactive,
         COUNT(*) FILTER (WHERE status = 'error')::int AS errored,
         COUNT(*) FILTER (WHERE tls_verified = true)::int AS tls_secured,
         COUNT(*) FILTER (WHERE last_health_status = 'healthy')::int AS healthy,
         COUNT(*) FILTER (WHERE last_health_status = 'down')::int AS down
       FROM ucp_connections WHERE tenant_id = $1`,
      [tenantId]
    );
    return { summary: r.rows[0] };
  });
}
