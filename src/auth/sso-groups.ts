/**
 * SSO Group → RBAC Mapping
 *
 * Sprint 3 enterprise feature. When a user authenticates via Okta/Azure AD,
 * their IdP groups are mapped to agent policies automatically.
 *
 * Flow:
 *   1. User SSO authenticates (OAuth 2.1 / OIDC via auth/routes.ts)
 *   2. Auth module fetches user's group memberships from IdP
 *   3. This module checks sso_group_mappings table for matching rules
 *   4. Matching rules create/update policies for the agent
 *
 * Example mapping:
 *   Okta group "security-team" → agent policy: allow [read_file, query_database]
 *   Okta group "devops"        → agent policy: allow [run_command, http_request]
 *
 * Routes:
 *   GET  /api/sso/groups          List configured group mappings
 *   POST /api/sso/groups          Add a mapping
 *   DEL  /api/sso/groups/:id      Remove a mapping
 *   POST /api/sso/sync            Trigger group sync for current user
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { requestTenantId } from '../utils/request-context';
import { encryptValue } from '../security/secrets';

// ── Apply group mappings when user SSO authenticates ──────────────────

export async function applyGroupMappings(
  tenantId: string,
  agentId: string,
  provider: string,
  groups: string[],
  db: Pool
): Promise<{ policiesApplied: number; groups: string[] }> {
  if (!groups.length) return { policiesApplied: 0, groups: [] };

  const mappings = await db.query(
    `SELECT group_name, tools, policy_action
     FROM sso_group_mappings
     WHERE tenant_id=$1 AND provider=$2 AND group_name = ANY($3)`,
    [tenantId, provider, groups]
  );

  let applied = 0;
  for (const mapping of mappings.rows) {
    const tools: string[] = mapping.tools || [];

    for (const tool of tools) {
      await db.query(
        `INSERT INTO policies (agent_id, tool_name, action, priority, tenant_id, description)
         VALUES ($1, $2, $3, 100, $4, 'Auto-applied from SSO group: ' || $5)
         ON CONFLICT (agent_id, tool_name) WHERE tenant_id=$4
         DO UPDATE SET action=$3, updated_at=NOW()`,
        [agentId, tool, mapping.policy_action, tenantId, mapping.group_name]
      ).catch(() => {
        // Fallback if unique constraint differs — upsert
        return db.query(
          `INSERT INTO policies (agent_id, tool_name, action, priority, tenant_id, description)
           VALUES ($1, $2, $3, 100, $4, $5)
           ON CONFLICT DO NOTHING`,
          [agentId, tool, mapping.policy_action, tenantId, `SSO group: ${mapping.group_name}`]
        );
      });
      applied++;
    }
  }

  return { policiesApplied: applied, groups: mappings.rows.map((m: any) => m.group_name) };
}

// ── Fastify plugin ────────────────────────────────────────────────────

export async function ssoGroupPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  fastify.get('/api/sso/oidc-config', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const r = await db.query(`SELECT plan, metadata->'ssoOidc' AS config FROM tenants WHERE id=$1`, [tenantId]);
    if (r.rows[0]?.plan !== 'enterprise') return reply.code(402).send({ error: 'SSO/OIDC requires Enterprise plan' });
    const config = r.rows[0]?.config || null;
    if (!config?.configured) return { configured: false };
    return {
      configured: true,
      provider: config.provider || '',
      issuerUrl: config.issuerUrl || '',
      clientId: config.clientId || '',
      jwksUri: config.jwksUri || '',
      enabled: config.enabled !== false,
      hasClientSecret: Boolean(config.clientSecretEnc),
      updatedAt: config.updatedAt || null,
    };
  });

  fastify.put('/api/sso/oidc-config', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const planR = await db.query(`SELECT plan, metadata->'ssoOidc' AS config FROM tenants WHERE id=$1`, [tenantId]);
    if (planR.rows[0]?.plan !== 'enterprise') return reply.code(402).send({ error: 'SSO/OIDC requires Enterprise plan' });
    const body = req.body as any;
    const provider = String(body.provider || '').trim().toLowerCase();
    const issuerUrl = String(body.issuerUrl || '').trim();
    const clientId = String(body.clientId || '').trim();
    const clientSecret = String(body.clientSecret || '').trim();
    const jwksUri = String(body.jwksUri || '').trim();
    const enabled = body.enabled !== false;
    if (!['okta', 'azure', 'google', 'custom'].includes(provider)) return reply.code(400).send({ error: 'Unsupported OIDC provider' });
    let issuer: URL;
    try {
      issuer = new URL(issuerUrl);
      if (!['https:', 'http:'].includes(issuer.protocol)) throw new Error('bad protocol');
    } catch {
      return reply.code(400).send({ error: 'Enter a valid issuer URL' });
    }
    let jwks = jwksUri;
    if (jwks) {
      try {
        const parsed = new URL(jwks);
        if (!['https:', 'http:'].includes(parsed.protocol)) throw new Error('bad protocol');
        jwks = parsed.toString();
      } catch {
        return reply.code(400).send({ error: 'Enter a valid JWKS URL or leave blank' });
      }
    } else {
      const normalizedIssuer = issuer.toString().replace(/\/$/, '');
      if (provider === 'okta') jwks = `${normalizedIssuer}/v1/keys`;
      else if (provider === 'azure') jwks = `${normalizedIssuer}/discovery/v2.0/keys`;
      else if (provider === 'google') jwks = 'https://www.googleapis.com/oauth2/v3/certs';
      else jwks = `${normalizedIssuer}/.well-known/jwks.json`;
    }
    if (!clientId) return reply.code(400).send({ error: 'clientId required' });

    const existing = planR.rows[0]?.config || {};
    const config = {
      provider,
      issuerUrl: issuer.toString().replace(/\/$/, ''),
      clientId,
      clientSecretEnc: clientSecret ? encryptValue(clientSecret) : existing.clientSecretEnc || null,
      jwksUri: jwks,
      enabled,
      configured: true,
      updatedAt: new Date().toISOString(),
    };
    await db.query(
      `UPDATE tenants SET metadata = jsonb_set(COALESCE(metadata,'{}'), '{ssoOidc}', $1::jsonb) WHERE id=$2`,
      [JSON.stringify(config), tenantId]
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'sso.oidc_config.save','sso_oidc',$4,NOW())`,
      [
        tenantId,
        String(req.headers['x-admin-email'] || 'local-admin'),
        String(req.headers['x-admin-role'] || 'local_admin'),
        JSON.stringify({ provider, issuerUrl: config.issuerUrl, jwksUri: config.jwksUri, enabled }),
      ]
    ).catch(() => {});
    return {
      configured: true,
      provider,
      issuerUrl: config.issuerUrl,
      clientId,
      jwksUri: config.jwksUri,
      enabled,
      hasClientSecret: Boolean(config.clientSecretEnc),
    };
  });

  // GET /api/sso/groups
  fastify.get('/api/sso/groups', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, provider, group_name, agent_id, policy_action, tools, created_at
       FROM sso_group_mappings WHERE tenant_id=$1 ORDER BY created_at DESC`,
      [tenantId]
    );
    return { mappings: r.rows };
  });

  // POST /api/sso/groups
  fastify.post('/api/sso/groups', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'SSO group mapping requires Enterprise plan' });
    }

    const { provider, groupName, agentId, tools, policyAction = 'allow' } = req.body as any;
    if (!provider || !groupName || !agentId || !tools?.length) {
      return reply.code(400).send({ error: 'provider, groupName, agentId, tools[] required' });
    }

    const r = await db.query(
      `INSERT INTO sso_group_mappings (tenant_id, provider, group_name, agent_id, policy_action, tools)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tenant_id, provider, group_name, agent_id) DO UPDATE
         SET tools=$6, policy_action=$5
       RETURNING *`,
      [tenantId, provider, groupName, agentId, policyAction, tools]
    );
    return { created: r.rows[0] };
  });

  // DELETE /api/sso/groups/:id
  fastify.delete('/api/sso/groups/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      `DELETE FROM sso_group_mappings WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, tenantId]
    );
    return { removed: true };
  });

  // POST /api/sso/sync — manually re-apply group mappings for an agent
  fastify.post('/api/sso/sync', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId, provider, groups } = req.body as any;
    if (!agentId || !provider || !groups?.length) {
      return reply.code(400).send({ error: 'agentId, provider, groups[] required' });
    }

    const result = await applyGroupMappings(tenantId, agentId, provider, groups, db);
    return { synced: true, ...result };
  });
}
