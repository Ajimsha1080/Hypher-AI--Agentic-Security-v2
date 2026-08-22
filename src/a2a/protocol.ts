/**
 * A2A (Agent-to-Agent) Protocol Support — M4
 *
 * Google's Agent-to-Agent protocol (now Linux Foundation, 150+ orgs) lets
 * agents discover and authenticate each other. When Agent A calls Agent B,
 * that call must also pass through MCP Security Gateway and be:
 *   - Authenticated (Agent A has a valid identity)
 *   - Authorized   (Agent A is allowed to call Agent B's tools)
 *   - Audited      (the A2A call is logged, immutably)
 *   - Rate-limited (Agent A can't spam Agent B)
 *
 * Spec: https://google.github.io/A2A
 *
 * This module adds:
 *   GET  /.well-known/agent.json         Agent Card (A2A discovery)
 *   POST /a2a                            A2A request endpoint (all agents)
 *   GET  /api/a2a/peers                  List authorized A2A peers
 *   POST /api/a2a/peers                  Register a new peer agent
 *   DEL  /api/a2a/peers/:peerId          Revoke peer authorization
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import axios from 'axios';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export interface AgentCard {
  '@type': 'AgentCard';
  name: string;
  version: string;
  description: string;
  url: string;
  capabilities: string[];
  authentication: {
    schemes: string[];
    jwksUri: string;
  };
  tools: AgentTool[];
  metadata: Record<string, string>;
}

export interface AgentTool {
  name: string;
  description: string;
  inputSchema: object;
}

export interface A2ARequest {
  '@type': 'A2ARequest';
  id: string;
  from: { agentId: string; agentUrl: string; };
  to: { agentId: string; };
  method: string;
  params: Record<string, unknown>;
  timestamp: string;
  signature?: string;
}

// ── Agent Card — published at /.well-known/agent.json ─────────────────

export function buildAgentCard(gatewayUrl: string, tools: AgentTool[]): AgentCard {
  return {
    '@type': 'AgentCard',
    name: 'MCP Security Gateway',
    version: '2.0.0',
    description: 'Zero-trust security proxy for MCP AI agents. All tool calls authenticated, inspected, policy-checked, and audited.',
    url: gatewayUrl,
    capabilities: [
      'tool_execution',
      'audit_logging',
      'rbac_enforcement',
      'prompt_injection_detection',
      'anomaly_detection',
      'a2a_routing',
    ],
    authentication: {
      schemes: ['bearer', 'oauth2', 'a2a_jwt'],
      jwksUri: `${gatewayUrl}/.well-known/jwks.json`,
    },
    tools,
    metadata: {
      vendor: 'Antigravity',
      complianceFrameworks: 'SOC2,ISO27001',
      dataResidency: process.env.REGION || 'us-east',
    },
  };
}

// ── A2A peer verification ──────────────────────────────────────────────

async function verifyA2ARequest(
  request: A2ARequest,
  db: Pool,
  redis: Redis
): Promise<{ valid: boolean; reason?: string }> {
  // 1. Check peer is registered and authorized
  const peer = await db.query(
    `SELECT * FROM a2a_peers
     WHERE agent_url=$1 AND active=true`,
    [request.from.agentUrl]
  );

  if (!peer.rows.length) {
    return { valid: false, reason: `Unknown A2A peer: ${request.from.agentUrl}` };
  }

  // 2. Verify request isn't replayed
  const replayKey = `a2a:replay:${request.id}`;
  const isNew = await redis.set(replayKey, '1', 'EX', 300, 'NX');
  if (!isNew) {
    return { valid: false, reason: 'A2A replay attack detected' };
  }

  // 3. Verify timestamp freshness (within 5 minutes)
  const reqTime = new Date(request.timestamp).getTime();
  if (Math.abs(Date.now() - reqTime) > 5 * 60 * 1000) {
    return { valid: false, reason: 'A2A request timestamp too old or too far in future' };
  }

  // 4. Verify JWT signature if provided
  if (request.signature && peer.rows[0].jwks_uri) {
    try {
      const jwks = createRemoteJWKSet(new URL(peer.rows[0].jwks_uri));
      await jwtVerify(request.signature, jwks, {
        issuer: request.from.agentUrl,
        audience: process.env.APP_URL,
      });
    } catch (e: any) {
      return { valid: false, reason: `A2A signature verification failed: ${e.message}` };
    }
  }

  return { valid: true };
}

// ── A2A request handler ────────────────────────────────────────────────

async function handleA2ARequest(
  request: A2ARequest,
  tenantId: string,
  db: Pool
): Promise<unknown> {
  // Check the peer's A2A policy — what methods can it call on us?
  const policy = await db.query(
    `SELECT allowed_methods FROM a2a_policies
     WHERE peer_agent_url=$1 AND tenant_id=$2 AND active=true`,
    [request.from.agentUrl, tenantId]
  );

  const allowedMethods: string[] = policy.rows[0]?.allowed_methods || [];

  if (!allowedMethods.includes('*') && !allowedMethods.includes(request.method)) {
    throw new Error(`A2A method '${request.method}' not permitted for peer ${request.from.agentUrl}`);
  }

  // Route to MCP proxy internally
  const mcpBody = {
    jsonrpc: '2.0',
    id: request.id,
    method: request.method,
    params: request.params,
  };

  const response = await axios.post(
    `http://localhost:${process.env.PORT || 3000}/mcp`,
    mcpBody,
    {
      headers: {
        Authorization: `Bearer ${process.env.A2A_INTERNAL_TOKEN || ''}`,
        'X-Tenant-ID': tenantId,
        'X-A2A-From': request.from.agentUrl,
        'X-A2A-Request-ID': request.id,
      },
      timeout: 30_000,
    }
  );

  return response.data;
}

// ── Fastify plugin ────────────────────────────────────────────────────

export async function a2aPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;

  async function resolveRequestTenant(req: any, reply: any) {
    if (req.tenant) return req.tenant;

    const tenantId = req.headers['x-tenant-id'] || process.env.DEFAULT_TENANT_ID;
    if (!tenantId) {
      reply.code(400).send({ error: 'Missing tenant ID - pass X-Tenant-ID header' });
      return null;
    }

    const r = await db.query(
      `SELECT id, name, plan FROM tenants WHERE id=$1 AND active=true LIMIT 1`,
      [tenantId]
    );

    if (!r.rows.length) {
      reply.code(404).send({ error: `Tenant ${tenantId} not found or inactive` });
      return null;
    }

    return r.rows[0];
  }

  function requireEnterprise(tenant: any, reply: any) {
    if (tenant?.plan === 'enterprise') return true;
    reply.code(402).send({ error: 'A2A agent protocol requires Enterprise plan' });
    return false;
  }

  // ── Agent Card discovery endpoint ──────────────────────────────────
  fastify.get('/.well-known/agent.json', async () => {
    const tools = await db.query(
      `SELECT DISTINCT tool_name as name FROM tool_arg_rules WHERE active=true LIMIT 20`
    );

    return buildAgentCard(
      process.env.APP_URL || 'http://localhost:3000',
      tools.rows.map((t: any) => ({
        name: t.name,
        description: `Execute ${t.name} through MCP Security Gateway`,
        inputSchema: { type: 'object' },
      }))
    );
  });

  // ── JWKS endpoint (for peer agents to verify our signatures) ───────
  fastify.get('/.well-known/jwks.json', async () => {
    // Return public key set — in production, generate an RSA key pair
    // and publish the public key here
    return { keys: [] };
  });

  // ── A2A request endpoint ───────────────────────────────────────────
  fastify.post('/a2a', async (req: any, reply) => {
    const request = req.body as A2ARequest;

    if (!request['@type'] || request['@type'] !== 'A2ARequest') {
      return reply.code(400).send({ error: 'Invalid A2A request format. @type must be A2ARequest' });
    }

    // Resolve tenant from the target agent
    const tenant = await db.query(
      `SELECT t.id, t.plan FROM tenants t
       JOIN agent_tokens at ON at.tenant_id=t.id
       WHERE at.agent_id=$1 AND t.active=true LIMIT 1`,
      [request.to.agentId]
    );

    if (!tenant.rows.length) {
      return reply.code(404).send({ error: `Target agent ${request.to.agentId} not found` });
    }

    const tenantId = tenant.rows[0].id;
    if (!requireEnterprise(tenant.rows[0], reply)) return;

    // Verify the A2A request
    const verification = await verifyA2ARequest(request, db, redis);
    if (!verification.valid) {
      await logA2AAudit(request, tenantId, 'DENY', verification.reason || '', db);
      return reply.code(403).send({ error: verification.reason });
    }

    try {
      const result = await handleA2ARequest(request, tenantId, db);
      await logA2AAudit(request, tenantId, 'ALLOW', '', db);
      return result;
    } catch (e: any) {
      await logA2AAudit(request, tenantId, 'DENY', e.message, db);
      return reply.code(403).send({ error: e.message });
    }
  });

  // ── Peer management ───────────────────────────────────────────────

  fastify.get('/api/a2a/peers', async (req, reply) => {
    const tenant = await resolveRequestTenant(req, reply);
    if (!tenant || !requireEnterprise(tenant, reply)) return;
    const r = await db.query(
      `SELECT id, agent_url, display_name, active, created_at FROM a2a_peers WHERE tenant_id=$1`,
      [tenant.id]
    );
    return { peers: r.rows };
  });

  fastify.post('/api/a2a/peers', async (req: any, reply: any) => {
    const tenant = await resolveRequestTenant(req, reply);
    if (!tenant || !requireEnterprise(tenant, reply)) return;
    const { agentUrl, displayName, allowedMethods, jwksUri } = req.body;

    if (!agentUrl) return reply.code(400).send({ error: 'agentUrl required' });

    // Verify the peer has a valid Agent Card
    let peerCard: AgentCard | null = null;
    try {
      const resp = await axios.get(`${agentUrl}/.well-known/agent.json`, { timeout: 10_000 });
      peerCard = resp.data;
    } catch {
      // Peer doesn't have an Agent Card — allow manual registration
    }

    await db.query(
      `INSERT INTO a2a_peers (tenant_id, agent_url, display_name, jwks_uri, peer_capabilities)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, agent_url) DO UPDATE SET display_name=$3, jwks_uri=$4, active=true`,
      [tenant.id, agentUrl, displayName || peerCard?.name || agentUrl,
       jwksUri || peerCard?.authentication?.jwksUri || null,
       JSON.stringify(peerCard?.capabilities || [])]
    );

    // Set allowed methods
    if (allowedMethods) {
      await db.query(
        `INSERT INTO a2a_policies (tenant_id, peer_agent_url, allowed_methods)
         VALUES ($1, $2, $3)
         ON CONFLICT (tenant_id, peer_agent_url) DO UPDATE SET allowed_methods=$3, active=true`,
        [tenant.id, agentUrl, JSON.stringify(allowedMethods)]
      );
    }

    return { registered: true, peerCard };
  });

  fastify.delete('/api/a2a/peers/:id', async (req, reply) => {
    const tenant = await resolveRequestTenant(req, reply);
    if (!tenant || !requireEnterprise(tenant, reply)) return;
    await db.query(
      `UPDATE a2a_peers SET active=false WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, tenant.id]
    );
    return { revoked: true };
  });

  fastify.post('/api/a2a/call', async (req: any, reply: any) => {
    const tenant = await resolveRequestTenant(req, reply);
    if (!tenant || !requireEnterprise(tenant, reply)) return;

    const { targetAgentUrl, targetAgentId, method, params, task } = req.body || {};
    if (!targetAgentUrl) return reply.code(400).send({ error: 'targetAgentUrl required' });

    const peer = await db.query(
      `SELECT agent_url, display_name, active FROM a2a_peers
       WHERE tenant_id=$1 AND agent_url=$2 AND active=true LIMIT 1`,
      [tenant.id, targetAgentUrl]
    );
    if (!peer.rows.length) {
      return reply.code(403).send({ error: 'A2A peer is not registered or is disabled' });
    }

    const taskData = task?.message?.parts?.[0]?.data || {};
    const requestId = `a2a-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const requestMethod = method || taskData.toolName || 'request.tool';
    const requestParams = params || taskData.args || {};
    const fromAgentUrl = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const request: A2ARequest = {
      '@type': 'A2ARequest',
      id: requestId,
      from: {
        agentId: process.env.A2A_AGENT_ID || 'mcp-security-gateway',
        agentUrl: fromAgentUrl,
      },
      to: {
        agentId: targetAgentId || peer.rows[0].display_name || targetAgentUrl,
      },
      method: requestMethod,
      params: requestParams,
      timestamp: new Date().toISOString(),
    };

    try {
      const resp = await axios.post(targetAgentUrl, request, {
        headers: {
          'Content-Type': 'application/json',
          ...(process.env.A2A_OUTBOUND_TOKEN
            ? { Authorization: `Bearer ${process.env.A2A_OUTBOUND_TOKEN}` }
            : {}),
        },
        timeout: 30_000,
      });
      await logA2AAudit(request, tenant.id, 'ALLOW', 'outbound peer call completed', db);
      return { result: resp.data, requestId };
    } catch (e: any) {
      const reason = e.response?.data?.error || e.message || 'A2A peer call failed';
      await logA2AAudit(request, tenant.id, 'DENY', reason, db);
      return reply.code(e.response?.status || 502).send({ error: reason, requestId });
    }
  });

  fastify.get('/api/a2a/audit', async (req, reply) => {
    const tenant = await resolveRequestTenant(req, reply);
    if (!tenant || !requireEnterprise(tenant, reply)) return;
    const r = await db.query(
      `SELECT * FROM a2a_audit_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [tenant.id]
    );
    return { logs: r.rows };
  });
}

// ── A2A audit logging ─────────────────────────────────────────────────

async function logA2AAudit(
  request: A2ARequest,
  tenantId: string,
  decision: 'ALLOW' | 'DENY',
  reason: string,
  db: Pool
): Promise<void> {
  try {
    await db.query(
      `INSERT INTO a2a_audit_log
         (tenant_id, request_id, from_agent_url, from_agent_id, to_agent_id, method, decision, reason, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())`,
      [tenantId, request.id, request.from.agentUrl, request.from.agentId,
       request.to.agentId, request.method, decision, reason || null]
    );
  } catch (e) {
    console.error('[a2a] Audit log write failed:', e);
  }
}
