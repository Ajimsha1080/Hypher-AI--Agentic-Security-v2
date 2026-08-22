/**
 * GDPR & Compliance Routes
 *
 * Sprint 3 enterprise feature.
 *
 * Routes:
 *   DELETE /api/gdpr/erase          Erase all data for a specific agent (GDPR Art. 17)
 *   GET    /api/audit/verify-chain  Verify hash-chain integrity of audit log
 *   GET    /api/scim/status         Check if SCIM is configured for tenant
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import { verifyHashChain } from '../audit/hash-chain';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

export async function complianceExtPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // DELETE /api/gdpr/erase — GDPR Article 17 right to erasure
  fastify.delete('/api/gdpr/erase', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'GDPR erase requires Enterprise plan' });
    }

    const { agentId } = req.body as any;
    if (!agentId) return reply.code(400).send({ error: 'agentId required' });

    // Perform erasure across all tables
    const counts: Record<string, number> = {};

    const auditR = await db.query(
      `DELETE FROM audit_log WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.audit_log = auditR.rowCount || 0;

    const dlpR = await db.query(
      `DELETE FROM dlp_events WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.dlp_events = dlpR.rowCount || 0;

    const hitlR = await db.query(
      `DELETE FROM hitl_approvals WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.hitl_approvals = hitlR.rowCount || 0;

    const shadowR = await db.query(
      `DELETE FROM shadow_mcp_findings WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.shadow_findings = shadowR.rowCount || 0;

    const tokenR = await db.query(
      `UPDATE agent_tokens SET active=FALSE WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.tokens_revoked = tokenR.rowCount || 0;

    const policyR = await db.query(
      `DELETE FROM policies WHERE tenant_id=$1 AND agent_id=$2`,
      [tenantId, agentId]
    );
    counts.policies = policyR.rowCount || 0;

    // Log the erasure itself (ironic but required by most privacy frameworks)
    await db.query(
      `INSERT INTO audit_log (tenant_id, agent_id, tool_name, decision, reason)
       VALUES ($1, 'SYSTEM', 'gdpr_erase', 'ALLOW', 'GDPR Art. 17 erasure of agent: ' || $2)`,
      [tenantId, agentId]
    );

    return { erased: true, agentId, counts };
  });

  // GET /api/audit/verify-chain — verify hash chain integrity
  fastify.get('/api/audit/verify-chain', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Compliance extensions requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'Audit chain verification requires Enterprise plan' });
    }

    const result = await verifyHashChain(db, tenantId, 50000);
    return result;
  });

  // GET /api/scim/status — check SCIM configuration
  fastify.get('/api/scim/status', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Compliance extensions requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT provider, last_sync, sync_status FROM scim_configs WHERE tenant_id=$1`,
      [tenantId]
    );
    if (!r.rows.length) return { configured: false };
    return { configured: true, provider: r.rows[0].provider, lastSync: r.rows[0].last_sync };
  });

  // PUT /api/tenant/region — region selection (already partial in server, completing here)
  fastify.put('/api/tenant/region', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Compliance extensions requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'Multi-region requires Enterprise plan' });
    }

    const { region } = req.body as any;
    const validRegions = ['us-east', 'eu-west', 'apac'];
    if (!validRegions.includes(region)) {
      return reply.code(400).send({ error: `Invalid region. Must be: ${validRegions.join(', ')}` });
    }

    await db.query(
      `UPDATE tenants SET metadata = jsonb_set(COALESCE(metadata,'{}'), '{region}', $1::jsonb)
       WHERE id=$2`,
      [JSON.stringify(region), tenantId]
    );

    const residencyMap: Record<string, string> = {
      'us-east': 'United States', 'eu-west': 'European Union', 'apac': 'Asia Pacific',
    };

    return {
      region,
      dataResidency: residencyMap[region],
      gdprCompliant: region === 'eu-west',
      message: `Region change to ${region} initiated. Data migration completes within 24 hours. You will receive an email confirmation.`,
    };
  });

  // GET /api/tenant/region
  fastify.get('/api/tenant/region', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Compliance extensions requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT metadata->>'region' AS region FROM tenants WHERE id=$1`,
      [tenantId]
    );
    const region = r.rows[0]?.region || 'us-east';
    const residencyMap: Record<string, string> = {
      'us-east': 'United States', 'eu-west': 'European Union', 'apac': 'Asia Pacific',
    };
    return {
      region,
      dataResidency: residencyMap[region] || 'United States',
      gdprCompliant: region === 'eu-west',
    };
  });
}
