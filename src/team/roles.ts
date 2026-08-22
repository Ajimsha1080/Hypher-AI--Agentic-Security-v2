/**
 * Multi-Admin Role System
 *
 * Sprint 3 enterprise feature. Tenants can invite multiple team members
 * with scoped permissions instead of sharing one admin secret.
 *
 * Roles:
 *   super_admin      — full access, can invite/remove members
 *   security_analyst — read audit logs, manage policies, run shadow scans
 *   billing_admin    — view/manage billing, invoices, plan changes
 *   viewer           — read-only dashboard access
 *
 * Stored in admin_members table (audit/schema.sql).
 *
 * Routes:
 *   GET  /api/team                  List team members
 *   POST /api/team/invite           Invite a member (email + role)
 *   PUT  /api/team/:id/role         Change member role
 *   DEL  /api/team/:id              Remove member
 */

import { FastifyInstance, FastifyRequest } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { ensurePlanLimitSchema, enforcePlanLimit, getPlanUsage, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';
import { requestTenantId } from '../utils/request-context';

export type AdminRole = 'super_admin' | 'security_analyst' | 'billing_admin' | 'viewer';

const ROLE_PERMISSIONS: Record<AdminRole, string[]> = {
  super_admin:       ['*'],
  security_analyst:  ['audit:read','policy:write','shadow:run','dlp:read','hitl:decide','siem:write','soc2:read'],
  billing_admin:     ['billing:read','billing:write','usage:read'],
  viewer:            ['audit:read','metrics:read','usage:read'],
};

export function hasPermission(role: AdminRole, permission: string): boolean {
  const perms = ROLE_PERMISSIONS[role] || [];
  return perms.includes('*') || perms.includes(permission);
}

// ── Fastify plugin ────────────────────────────────────────────────────

export async function teamPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;
  await ensurePlanLimitSchema(db);

  // GET /api/team
  fastify.get('/api/team', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT id, email, role, invited_by, last_login, created_at
       FROM admin_members WHERE tenant_id=$1 AND active=TRUE ORDER BY created_at DESC`,
      [tenantId]
    );
    return { members: r.rows };
  });

  // POST /api/team/invite
  fastify.post('/api/team/invite', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    // Enterprise only
    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['growth','enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'Team management requires Growth or Enterprise plan' });
    }

    const { email, role } = req.body as any;
    if (!email || !role) return reply.code(400).send({ error: 'email and role required' });
    if (!Object.keys(ROLE_PERMISSIONS).includes(role)) {
      return reply.code(400).send({ error: `Invalid role. Must be: ${Object.keys(ROLE_PERMISSIONS).join(', ')}` });
    }

    try {
      const usage = await getPlanUsage(db, tenantId);
      await enforcePlanLimit(db, {
        tenantId,
        featureKey: 'team_members',
        used: usage.team_members,
        action: 'team.invite',
        actorEmail: String(req.headers['x-admin-email'] || req.user?.email || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }

    // Generate invite token (emailed to invitee)
    const inviteToken = crypto.randomBytes(32).toString('hex');
    const inviteTokenHash = crypto.createHash('sha256').update(inviteToken).digest('hex');

    try {
      const r = await db.query(
        `INSERT INTO admin_members (tenant_id, email, role, invited_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (tenant_id, email) DO UPDATE SET role=$3, active=TRUE
         RETURNING id, email, role`,
        [tenantId, email, role, req.user?.agentId || 'system']
      );

      // Store invite token in DB for verification
      await db.query(
        `UPDATE admin_members SET invite_token_hash=$1 WHERE tenant_id=$2 AND email=$3`,
        [inviteTokenHash, tenantId, email]
      ).catch(() => {}); // Column may not exist yet — graceful fallback

      return { invited: r.rows[0], inviteToken };
    } catch (err: any) {
      if (err.code === '23505') return reply.code(409).send({ error: 'Member already exists' });
      throw err;
    }
  });

  // PUT /api/team/:id/role
  fastify.put('/api/team/:id/role', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { role } = req.body as any;
    if (!Object.keys(ROLE_PERMISSIONS).includes(role)) {
      return reply.code(400).send({ error: 'Invalid role' });
    }

    await db.query(
      `UPDATE admin_members SET role=$1 WHERE id=$2 AND tenant_id=$3`,
      [role, (req.params as any).id, tenantId]
    );
    return { updated: true };
  });

  // DELETE /api/team/:id
  fastify.delete('/api/team/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    await db.query(
      `UPDATE admin_members SET active=FALSE WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).id, tenantId]
    );
    return { removed: true };
  });

  // GET /api/team/permissions — return role permission matrix
  fastify.get('/api/team/permissions', async () => {
    return { roles: ROLE_PERMISSIONS };
  });
}
