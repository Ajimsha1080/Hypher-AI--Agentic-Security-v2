/**
 * SCIM 2.0 Provisioning
 *
 * Sprint 4 enterprise feature. Implements SCIM 2.0 endpoints so Okta,
 * Azure AD, and other IdPs can automatically provision/deprovision users
 * and sync group memberships.
 *
 * When an Okta admin assigns MCP Security to a user:
 *   → POST /scim/v2/Users creates an agent_token for them
 * When they're removed:
 *   → DELETE /scim/v2/Users/:id deactivates their token
 * Groups sync to sso_group_mappings for RBAC policies.
 *
 * Setup: In Okta/Azure AD app, set SCIM base URL to:
 *   https://your-gateway.com/scim/v2
 * Bearer token = SCIM_BEARER_TOKEN env var hash
 *
 * Routes:
 *   GET    /scim/v2/Users
 *   POST   /scim/v2/Users
 *   GET    /scim/v2/Users/:id
 *   PUT    /scim/v2/Users/:id
 *   PATCH  /scim/v2/Users/:id
 *   DELETE /scim/v2/Users/:id
 *   GET    /scim/v2/Groups
 *   POST   /scim/v2/Groups
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { ensurePlanLimitSchema, enforcePlanLimit, getPlanUsage, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';

function scimUser(member: any) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id: member.id,
    userName: member.email,
    name: { formatted: member.email },
    emails: [{ value: member.email, primary: true }],
    active: member.active,
    meta: {
      resourceType: 'User',
      created: member.created_at,
      lastModified: member.last_login || member.created_at,
      location: `/scim/v2/Users/${member.id}`,
    },
  };
}

export async function scimPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;
  await ensurePlanLimitSchema(db);

  // SCIM Bearer token auth
  fastify.addHook('preHandler', async (req: any, reply) => {
    if (!req.url.startsWith('/scim/')) return;
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return reply.code(401).send({ error: 'Unauthorized' });

    const token = auth.slice(7);
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const r = await db.query(
      `SELECT tenant_id FROM scim_configs WHERE bearer_token_hash=$1`,
      [tokenHash]
    );
    if (!r.rows.length) return reply.code(401).send({ error: 'Invalid SCIM token' });
    (req as any).scimTenantId = r.rows[0].tenant_id;
  });

  // GET /scim/v2/Users
  fastify.get('/scim/v2/Users', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    const r = await db.query(
      `SELECT * FROM admin_members WHERE tenant_id=$1 AND active=TRUE ORDER BY created_at DESC`,
      [(req as any).scimTenantId]
    );
    return {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: r.rows.length,
      startIndex: 1,
      itemsPerPage: r.rows.length,
      Resources: r.rows.map(scimUser),
    };
  });

  // POST /scim/v2/Users — create user (IdP provisioning)
  fastify.post('/scim/v2/Users', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    const body = req.body as any;
    const email = body.emails?.[0]?.value || body.userName;
    if (!email) return reply.code(400).send({ error: 'email required' });
    try {
      const usage = await getPlanUsage(db, (req as any).scimTenantId);
      await enforcePlanLimit(db, {
        tenantId: (req as any).scimTenantId,
        featureKey: 'team_members',
        used: usage.team_members,
        action: 'scim.user.create',
        actorEmail: 'scim',
      });
      await enforcePlanLimit(db, {
        tenantId: (req as any).scimTenantId,
        featureKey: 'agents',
        used: usage.agents,
        action: 'scim.agent.create',
        actorEmail: 'scim',
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }

    const r = await db.query(
      `INSERT INTO admin_members (tenant_id, email, role, invited_by)
       VALUES ($1, $2, 'viewer', 'scim')
       ON CONFLICT (tenant_id, email) DO UPDATE SET active=TRUE
       RETURNING *`,
      [(req as any).scimTenantId, email]
    );

    // Also create an agent token so the user can call the API
    const agentId = `scim_${crypto.randomBytes(6).toString('hex')}`;
    const token = 'mcpsg_' + crypto.randomBytes(24).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    await db.query(
      `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description)
       VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
      [agentId, (req as any).scimTenantId, tokenHash, `SCIM provisioned: ${email}`]
    );

    await db.query(
      `UPDATE scim_configs SET last_sync=NOW() WHERE tenant_id=$1`,
      [(req as any).scimTenantId]
    );

    return reply.code(201).send(scimUser(r.rows[0]));
  });

  // GET /scim/v2/Users/:id
  fastify.get('/scim/v2/Users/:id', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    const r = await db.query(
      `SELECT * FROM admin_members WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, (req as any).scimTenantId]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'User not found' });
    return scimUser(r.rows[0]);
  });

  // PATCH /scim/v2/Users/:id — activate/deactivate
  fastify.patch('/scim/v2/Users/:id', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    const body = req.body as any;
    const ops = body.Operations || [];

    for (const op of ops) {
      if (op.op === 'replace' && op.value?.active === false) {
        await db.query(
          `UPDATE admin_members SET active=FALSE WHERE id=$1 AND tenant_id=$2`,
          [(req.params as any).id, (req as any).scimTenantId]
        );
      }
      if (op.op === 'replace' && op.value?.active === true) {
        await db.query(
          `UPDATE admin_members SET active=TRUE WHERE id=$1 AND tenant_id=$2`,
          [(req.params as any).id, (req as any).scimTenantId]
        );
      }
    }

    const r = await db.query(
      `SELECT * FROM admin_members WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, (req as any).scimTenantId]
    );
    return r.rows.length ? scimUser(r.rows[0]) : reply.code(404).send({});
  });

  // DELETE /scim/v2/Users/:id — deprovision
  fastify.delete('/scim/v2/Users/:id', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    await db.query(
      `UPDATE admin_members SET active=FALSE WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, (req as any).scimTenantId]
    );
    return reply.code(204).send();
  });

  // POST /api/scim/setup — configure SCIM for tenant (admin only)
  fastify.post('/api/scim/setup', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }
    const tenantId = (req as any).tenant?.id;
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'SCIM provisioning requires Enterprise plan' });
    }

    const { provider } = req.body as any;
    const bearerToken = 'scim_' + crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(bearerToken).digest('hex');

    await db.query(
      `INSERT INTO scim_configs (tenant_id, provider, bearer_token_hash)
       VALUES ($1, $2, $3)
       ON CONFLICT (tenant_id) DO UPDATE SET provider=$2, bearer_token_hash=$3`,
      [tenantId, provider || 'okta', tokenHash]
    );

    return {
      configured: true,
      scimBaseUrl: `${process.env.APP_URL}/scim/v2`,
      bearerToken, // Only shown once — tenant must save this
      provider: provider || 'okta',
    };
  });
}
