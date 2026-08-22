/**
 * Data Retention Policies + White-Label Branding
 *
 * Sprint 3: Tenants configure how long each data type is retained.
 * Sprint 4: Enterprise+ tenants can customise the dashboard branding.
 *
 * Retention routes:
 *   GET  /api/retention          Get current policy
 *   PUT  /api/retention          Update policy
 *
 * Branding routes:
 *   GET  /api/branding           Get current branding config
 *   PUT  /api/branding           Update branding (logo URL, company name, colours)
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import { ensurePlanLimitSchema, enforceMaxValue, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

// ── Data Retention ────────────────────────────────────────────────────

export async function retentionPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;
  await ensurePlanLimitSchema(db);

  // GET /api/retention
  fastify.get('/api/retention', async (req: any, reply) => {
    const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });

    const r = await db.query(
      `SELECT rp.audit_log_days, rp.dlp_events_days, rp.hitl_days, rp.shadow_days,
              COALESCE(pas.retention_days, 7) AS prompt_detail_days,
              rp.updated_at
       FROM retention_policies rp
       LEFT JOIN prompt_audit_settings pas ON pas.tenant_id=rp.tenant_id
       WHERE rp.tenant_id=$1`,
      [tenantId]
    );

    // Defaults if no policy set
    return r.rows[0] || {
      audit_log_days: 90,
      dlp_events_days: 30,
      hitl_days: 90,
      shadow_days: 30,
      prompt_detail_days: 7,
      ml_profile_retention: 'long_term_aggregated',
    };
  });

  // PUT /api/retention
  fastify.put('/api/retention', async (req: any, reply) => {
    const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'Custom retention policies require Enterprise plan' });
    }

    const {
      auditLogDays = 90,
      dlpEventsDays = 30,
      hitlDays = 90,
      shadowDays = 30,
      promptDetailDays = 7,
    } = req.body as any;

    // Minimum 7 days, maximum 365 days
    const clamp = (v: number) => Math.max(7, Math.min(365, v));
    const requestedMax = Math.max(clamp(auditLogDays), clamp(dlpEventsDays), clamp(hitlDays), clamp(shadowDays), clamp(promptDetailDays));
    try {
      await enforceMaxValue(db, {
        tenantId,
        featureKey: 'retention_days',
        requested: requestedMax,
        action: 'retention.update',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }

    await db.query(
      `INSERT INTO retention_policies (tenant_id, audit_log_days, dlp_events_days, hitl_days, shadow_days)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id) DO UPDATE
         SET audit_log_days=$2, dlp_events_days=$3, hitl_days=$4, shadow_days=$5, updated_at=NOW()`,
      [tenantId, clamp(auditLogDays), clamp(dlpEventsDays), clamp(hitlDays), clamp(shadowDays)]
    );

    await db.query(
      `INSERT INTO prompt_audit_settings (tenant_id, mode, retention_days, updated_at)
       VALUES ($1, 'SUMMARY_ONLY', $2, NOW())
       ON CONFLICT (tenant_id)
       DO UPDATE SET retention_days=$2, updated_at=NOW()`,
      [tenantId, clamp(promptDetailDays)]
    );

    return {
      updated: true,
      policy: {
        promptDetailDays: clamp(promptDetailDays),
        auditLogDays: clamp(auditLogDays),
        dlpEventsDays: clamp(dlpEventsDays),
        hitlDays: clamp(hitlDays),
        shadowDays: clamp(shadowDays),
        mlProfileRetention: 'long_term_aggregated',
      },
    };
  });
}

// ── White-Label Branding ──────────────────────────────────────────────

interface BrandingConfig {
  companyName: string;
  logoUrl?: string;
  primaryColor?: string;    // hex e.g. #00e5a0
  faviconUrl?: string;
  supportEmail?: string;
  customDomain?: string;    // custom gateway domain e.g. ai-security.yourco.com
}

export async function brandingPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/branding
  fastify.get('/api/branding', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Custom retention and branding requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT branding FROM tenants WHERE id=$1`,
      [tenantId]
    );
    return r.rows[0]?.branding || {};
  });

  // PUT /api/branding
  fastify.put('/api/branding', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'Custom retention and branding requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const planR = await db.query('SELECT plan FROM tenants WHERE id=$1', [tenantId]);
    if (!['enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(403).send({ error: 'White-label branding requires Enterprise plan' });
    }

    const branding = req.body as BrandingConfig;

    // Validate colour format
    if (branding.primaryColor && !/^#[0-9a-fA-F]{6}$/.test(branding.primaryColor)) {
      return reply.code(400).send({ error: 'primaryColor must be a 6-digit hex colour e.g. #00e5a0' });
    }

    await db.query(
      `UPDATE tenants SET branding=$1::jsonb WHERE id=$2`,
      [JSON.stringify(branding), tenantId]
    );

    return { updated: true, branding };
  });
}
