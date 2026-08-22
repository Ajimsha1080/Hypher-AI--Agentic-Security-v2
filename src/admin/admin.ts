/**
 * Admin Panel — Super-admin for MCP Security Gateway SaaS
 * Used by YOU (the product owner) to manage all tenants, billing, and system.
 * Protected by ADMIN_SECRET env var — never expose publicly.
 *
 * Features:
 * - All tenants overview with MRR / usage
 * - Suspend / unsuspend tenants
 * - Manually upgrade/downgrade plans
 * - View any tenant's audit log
 * - System-wide metrics
 * - Registry moderation (approve/block servers)
 * - Alert rule templates
 * - Billing reconciliation
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import { ensurePlanLimitSchema, getPlanLimits, getPlanUsage } from '../billing/plan-limits';
import { hasProductionSecretEncryption } from '../security/secrets';

// Admin auth middleware
const ADMIN_COOKIE = 'mcpsg_admin_session';
const ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60;

function adminSigningSecret(): string {
  return process.env.ADMIN_SESSION_SECRET || process.env.ADMIN_SECRET || 'local-admin-session-secret';
}

function parseCookies(header: unknown): Record<string, string> {
  return String(header || '').split(';').reduce((acc: Record<string, string>, part) => {
    const [k, ...rest] = part.trim().split('=');
    if (k) acc[k] = decodeURIComponent(rest.join('=') || '');
    return acc;
  }, {});
}

function signAdminSession(payload: { email: string; role: string; exp: number }): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', adminSigningSecret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyAdminSession(token: string | undefined): { email: string; role: string } | null {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', adminSigningSecret()).update(body).digest('base64url');
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload?.email || !payload?.role || Date.now() > Number(payload.exp || 0)) return null;
    return { email: payload.email, role: payload.role };
  } catch {
    return null;
  }
}

function setAdminCookie(reply: FastifyReply, token: string): void {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  reply.header('Set-Cookie', `${ADMIN_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_SESSION_TTL_SECONDS}${secure}`);
}

function clearAdminCookie(reply: FastifyReply): void {
  reply.header('Set-Cookie', `${ADMIN_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

function adminLoginHtml(error = ''): string {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MCP Security Admin Login</title>
  <style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#060809;color:#e8f0f7;font-family:Arial,sans-serif}.box{width:min(420px,calc(100vw - 32px));background:#0b0f12;border:1px solid #1e262d;border-radius:10px;padding:24px}h1{margin:0 0 6px;font-size:24px}p{color:#7a9ab0;font-size:13px;line-height:1.5}input{width:100%;box-sizing:border-box;margin:8px 0;padding:11px;border-radius:6px;border:1px solid #2a343d;background:#111619;color:#e8f0f7}button{width:100%;margin-top:10px;padding:11px;border:0;border-radius:6px;background:#00e5a0;color:#06100c;font-weight:700}.err{color:#ff4757;font-size:12px;margin-top:8px}.mono{font-family:monospace;color:#7a9ab0;font-size:11px}</style></head>
  <body><form class="box" method="post" action="/admin/login"><h1>Admin Login</h1><p>Use your bootstrap admin secret or an SSO-backed admin session. The URL secret is no longer required.</p><input name="email" placeholder="admin email" value="${process.env.ADMIN_EMAIL || 'admin@local'}"><input name="adminSecret" type="password" placeholder="admin secret"><button>Sign in</button>${error ? `<div class="err">${error}</div>` : ''}<p class="mono">Session: HttpOnly, SameSite=Strict, 8h expiry.</p></form></body></html>`;
}

function adminFromRequest(request: FastifyRequest): { email: string; role: string } | null {
  const session = verifyAdminSession(parseCookies(request.headers.cookie)[ADMIN_COOKIE]);
  if (session) return session;
  const secret = request.headers['x-admin-secret'] as string;
  if (secret && secret === process.env.ADMIN_SECRET) {
    return { email: String(request.headers['x-admin-email'] || process.env.ADMIN_EMAIL || 'bootstrap-admin'), role: 'super_admin' };
  }
  return null;
}

function requireAdmin(request: FastifyRequest, reply: FastifyReply): boolean {
  const admin = adminFromRequest(request);
  if (!admin) {
    reply.code(401).send({ error: 'Admin login required' });
    return false;
  }
  (request as any).admin = admin;
  return true;
}

function envNumber(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

const LOCAL_DEMO_TENANT_ID = 'c71bee1e-5d56-4f65-9495-b580dafb90f6';
const DEFAULT_PLAN_PRICES_USD: Record<string, number> = {
  starter: 49,
  growth: 199,
  enterprise: 999,
};

function configuredPlanPrices(): Record<string, number> {
  return {
    starter: envNumber('PRICE_STARTER_USD', DEFAULT_PLAN_PRICES_USD.starter),
    growth: envNumber('PRICE_GROWTH_USD', DEFAULT_PLAN_PRICES_USD.growth),
    enterprise: envNumber('PRICE_ENTERPRISE_USD', DEFAULT_PLAN_PRICES_USD.enterprise),
  };
}

function pricingSource(): 'env' | 'defaults' {
  return ['PRICE_STARTER_USD', 'PRICE_GROWTH_USD', 'PRICE_ENTERPRISE_USD'].some((key) => process.env[key])
    ? 'env'
    : 'defaults';
}

function csvEscape(value: unknown): string {
  const text = value == null ? '' : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

async function auditSuperAdminAction(
  db: Pool,
  request: FastifyRequest,
  action: string,
  targetId: string,
  reason: string,
  details: Record<string, unknown> = {}
): Promise<void> {
  const actor = String((request as any).admin?.email || request.headers['x-admin-email'] || 'super-admin');
  await db.query(
    `INSERT INTO admin_actions (action, target_id, reason, performed_by, created_at)
     VALUES ($1,$2,$3,$4,NOW())`,
    [action, targetId, reason, actor]
  ).catch(() => {});
  await db.query(
    `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
     SELECT $1,$2,'super_admin',$3,$4,$5,NOW()
     WHERE EXISTS (SELECT 1 FROM tenants WHERE id=$1)`,
    [targetId, actor, action, targetId, JSON.stringify(details)]
  ).catch(() => {});
}

export async function adminPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db, redis } = opts;
  await ensurePlanLimitSchema(db);
  try {
    fastify.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
      const params = new URLSearchParams(String(body || ''));
      done(null, Object.fromEntries(params.entries()));
    });
  } catch {
    // Parser may already be registered by another plugin in tests.
  }

  fastify.get('/admin/session', async (req, reply) => {
    const admin = adminFromRequest(req);
    if (!admin) return reply.code(401).send({ authenticated: false });
    return { authenticated: true, admin };
  });

  fastify.post('/admin/login', async (req: any, reply) => {
    const { email, adminSecret } = req.body || {};
    if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
      return reply.code(401).type('text/html').send(adminLoginHtml('Invalid admin secret'));
    }
    const adminEmail = String(email || process.env.ADMIN_EMAIL || 'admin@local');
    const token = signAdminSession({ email: adminEmail, role: 'super_admin', exp: Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000 });
    setAdminCookie(reply, token);
    await db.query(
      `INSERT INTO admin_actions (action, target_id, reason, performed_by, created_at)
       VALUES ('admin.login','admin','session_login',$1,NOW())`,
      [adminEmail]
    ).catch(() => {});
    return reply.redirect('/admin');
  });

  fastify.post('/admin/logout', async (req, reply) => {
    clearAdminCookie(reply);
    return { loggedOut: true };
  });

  // ── Admin dashboard stats ──────────────────────────────────────────

  fastify.get('/admin/stats', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;

    const [tenants, tenantTotals, overage, calls, topTenants, alerts] = await Promise.all([
      db.query(`SELECT plan, COUNT(*) as cnt, COUNT(*) FILTER (WHERE active) as active FROM tenants GROUP BY plan`),
      db.query(`
        SELECT
          COUNT(*) as total_tenants,
          COUNT(*) FILTER (WHERE active) as active_tenants
        FROM tenants`),
      db.query(`
        SELECT COALESCE(SUM(amount_usd),0)::numeric AS overage_usd
        FROM billing_invoices
        WHERE paid_at >= DATE_TRUNC('month', NOW())
          AND COALESCE(stripe_invoice_id,'') LIKE 'overage_%'`).catch(() => ({ rows: [{ overage_usd: 0 }] })),
      db.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE decision='DENY') as denied,
                       AVG(execution_time_ms) as avg_ms FROM audit_log WHERE created_at > NOW()-INTERVAL '24h'`),
      db.query(`SELECT t.id, t.name, t.plan,
                       COALESCE(um.api_calls, 0) as api_calls_this_month,
                       t.api_calls_limit
                FROM tenants t
                LEFT JOIN usage_metrics um ON um.tenant_id=t.id AND um.month=TO_CHAR(NOW(),'YYYY-MM')
                WHERE t.active=true ORDER BY um.api_calls DESC NULLS LAST LIMIT 10`),
      db.query(`SELECT COUNT(*) as cnt FROM alert_log WHERE sent_at > NOW()-INTERVAL '24h'`),
    ]);
    const planPrices = configuredPlanPrices();
    const source = pricingSource();
    const mrrUsd = tenants.rows.reduce((sum: number, row: any) => {
      const plan = String(row.plan || 'starter');
      return sum + (Number(row.active || 0) * Number(planPrices[plan] || 0));
    }, 0);

    return {
      tenants: tenants.rows,
      planPrices,
      pricingSource: source,
      revenue: {
        ...tenantTotals.rows[0],
        mrr_usd: mrrUsd,
        overage_usd: Number(overage.rows[0]?.overage_usd || 0),
        pricing_source: source,
        estimated: source === 'defaults',
      },
      calls24h: calls.rows[0],
      topTenants: topTenants.rows,
      alertsSent24h: alerts.rows[0].cnt,
    };
  });

  fastify.get('/admin/unit-economics', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;

    const planPrices = configuredPlanPrices();
    const assumptions = {
      baseInfraUsd: envNumber('UNIT_BASE_INFRA_USD', 800),
      costPer1kCallsUsd: envNumber('UNIT_COST_PER_1K_CALLS_USD', 0.03),
      supportCostPerTenantUsd: envNumber('UNIT_SUPPORT_COST_PER_TENANT_USD', 4),
      paymentFeeRate: envNumber('UNIT_PAYMENT_FEE_RATE', 0.029),
      paymentFixedFeeUsd: envNumber('UNIT_PAYMENT_FIXED_USD', 0.3),
      prices: planPrices,
    };

    const [usageByPlan, overageByPlan] = await Promise.all([
      db.query(`
        SELECT
          COALESCE(NULLIF(t.plan,''),'starter') AS plan,
          COUNT(*)::int AS tenants,
          COUNT(*) FILTER (WHERE t.active)::int AS active_tenants,
          COALESCE(SUM(um.api_calls),0)::bigint AS api_calls_month,
          COALESCE(SUM(t.api_calls_limit),0)::bigint AS included_call_limit
        FROM tenants t
        LEFT JOIN usage_metrics um ON um.tenant_id=t.id AND um.month=TO_CHAR(NOW(),'YYYY-MM')
        GROUP BY COALESCE(NULLIF(t.plan,''),'starter')
      `),
      db.query(`
        SELECT
          COALESCE(NULLIF(t.plan,''),'starter') AS plan,
          COALESCE(SUM(bi.amount_usd),0)::numeric AS overage_usd
        FROM billing_invoices bi
        JOIN tenants t ON t.id=bi.tenant_id
        WHERE bi.paid_at >= DATE_TRUNC('month', NOW())
          AND COALESCE(bi.stripe_invoice_id,'') LIKE 'overage_%'
        GROUP BY COALESCE(NULLIF(t.plan,''),'starter')
      `).catch(() => ({ rows: [] as any[] })),
    ]);

    const overageMap = new Map<string, number>(
      overageByPlan.rows.map((r: any) => [String(r.plan), Number(r.overage_usd || 0)])
    );
    const rowsSource = ['starter', 'growth', 'enterprise']
      .map(plan => usageByPlan.rows.find((r: any) => String(r.plan) === plan) || { plan, tenants: 0, active_tenants: 0, api_calls_month: 0, included_call_limit: 0 })
      .concat(usageByPlan.rows.filter((r: any) => !['starter', 'growth', 'enterprise'].includes(String(r.plan))));
    const totalCalls = rowsSource.reduce((sum: number, r: any) => sum + Number(r.api_calls_month || 0), 0);
    const totalTenants = rowsSource.reduce((sum: number, r: any) => sum + Number(r.tenants || 0), 0);

    const rows = rowsSource.map((r: any) => {
      const plan = String(r.plan || 'starter');
      const tenantsCount = Number(r.tenants || 0);
      const activeTenants = Number(r.active_tenants || 0);
      const calls = Number(r.api_calls_month || 0);
      const baseMrr = tenantsCount * (planPrices[plan] || 0);
      const overageUsd = overageMap.get(plan) || 0;
      const revenue = baseMrr + overageUsd;
      const infraShare = totalCalls > 0
        ? calls / totalCalls
        : (totalTenants > 0 ? tenantsCount / totalTenants : 0);
      const allocatedInfraUsd = assumptions.baseInfraUsd * infraShare;
      const variableCogsUsd = (calls / 1000) * assumptions.costPer1kCallsUsd;
      const supportCogsUsd = tenantsCount * assumptions.supportCostPerTenantUsd;
      const paymentFeesUsd = revenue > 0 ? (revenue * assumptions.paymentFeeRate) + (tenantsCount * assumptions.paymentFixedFeeUsd) : 0;
      const totalCogsUsd = allocatedInfraUsd + variableCogsUsd + supportCogsUsd + paymentFeesUsd;
      const grossProfitUsd = revenue - totalCogsUsd;
      const marginPct = revenue > 0 ? (grossProfitUsd / revenue) * 100 : 0;
      return {
        plan,
        tenants: tenantsCount,
        activeTenants,
        priceUsd: planPrices[plan] || 0,
        baseMrrUsd: baseMrr,
        overageUsd,
        revenueUsd: revenue,
        apiCallsMonth: calls,
        includedCallLimit: Number(r.included_call_limit || 0),
        allocatedInfraUsd,
        variableCogsUsd,
        supportCogsUsd,
        paymentFeesUsd,
        totalCogsUsd,
        grossProfitUsd,
        marginPct,
      };
    });

    const totals = rows.reduce((acc: any, r: any) => {
      for (const key of ['tenants','activeTenants','baseMrrUsd','overageUsd','revenueUsd','apiCallsMonth','includedCallLimit','allocatedInfraUsd','variableCogsUsd','supportCogsUsd','paymentFeesUsd','totalCogsUsd','grossProfitUsd']) {
        acc[key] = (acc[key] || 0) + Number(r[key] || 0);
      }
      return acc;
    }, {});
    totals.marginPct = totals.revenueUsd > 0 ? (totals.grossProfitUsd / totals.revenueUsd) * 100 : 0;

    return { rows, totals, assumptions, currency: 'USD', visibility: 'super_admin_only', pricingSource: pricingSource() };
  });

  // ── All tenants list ───────────────────────────────────────────────

  fastify.get('/admin/tenants', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { plan, active, search } = req.query as any;
    let q = `SELECT t.*,
               COALESCE(um.api_calls,0) as api_calls_this_month
             FROM tenants t
             LEFT JOIN usage_metrics um ON um.tenant_id=t.id AND um.month=TO_CHAR(NOW(),'YYYY-MM')
             WHERE 1=1`;
    const params: unknown[] = [];
    if (plan) { params.push(plan); q += ` AND t.plan=$${params.length}`; }
    if (active !== undefined) { params.push(active === 'true'); q += ` AND t.active=$${params.length}`; }
    if (search) { params.push(`%${search}%`); q += ` AND (t.name ILIKE $${params.length} OR t.billing_email ILIKE $${params.length})`; }
    q += ` ORDER BY t.created_at DESC`;
    const r = await db.query(q, params);
    return { tenants: r.rows };
  });

  // ── Single tenant detail ───────────────────────────────────────────

  fastify.get<{ Params: { id: string } }>('/admin/tenants/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [tenant, usage, agents, recentLogs, alertRules] = await Promise.all([
      db.query(`SELECT * FROM tenants WHERE id=$1`, [req.params.id]),
      db.query(`SELECT * FROM usage_metrics WHERE tenant_id=$1 ORDER BY month DESC LIMIT 12`, [req.params.id]),
      db.query(`SELECT DISTINCT agent_id, COUNT(*) as calls, MAX(created_at) as last_seen
                FROM audit_log WHERE tenant_id=$1 GROUP BY agent_id ORDER BY calls DESC`, [req.params.id]),
      db.query(`SELECT * FROM audit_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, [req.params.id]),
      db.query(`SELECT * FROM alert_rules WHERE tenant_id=$1`, [req.params.id]),
    ]);
    if (!tenant.rows.length) return reply.code(404).send({ error: 'Tenant not found' });
    return { tenant: tenant.rows[0], usage: usage.rows, agents: agents.rows, recentLogs: recentLogs.rows, alertRules: alertRules.rows };
  });

  // ── Suspend / unsuspend ────────────────────────────────────────────

  fastify.post<{ Params: { id: string } }>('/admin/tenants/:id/suspend', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { reason } = req.body as any;
    await db.query(`UPDATE tenants SET active=false, suspension_reason=$1 WHERE id=$2`, [reason || 'Admin action', req.params.id]);
    await redis.del(`tenant:${req.params.id}`);
    await auditSuperAdminAction(db, req, 'tenant.suspend', req.params.id, reason || 'Admin action');
    return { suspended: true };
  });

  fastify.post<{ Params: { id: string } }>('/admin/tenants/:id/unsuspend', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    await db.query(`UPDATE tenants SET active=true, suspension_reason=NULL WHERE id=$2`, [req.params.id]);
    await redis.del(`tenant:${req.params.id}`);
    await auditSuperAdminAction(db, req, 'tenant.unsuspend', req.params.id, 'Admin action');
    return { unsuspended: true };
  });

  // ── Plan management ────────────────────────────────────────────────

  fastify.put<{ Params: { id: string } }>('/admin/tenants/:id/plan', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { plan, apiCallsLimit, agentsLimit } = req.body as any;
    const DEFAULTS: Record<string, { api: number; agents: number }> = {
      starter: { api: 10000, agents: 5 },
      growth: { api: 100000, agents: 25 },
      enterprise: { api: 1000000, agents: 200 },
    };
    const limits = DEFAULTS[plan] || DEFAULTS.starter;
    await db.query(
      `UPDATE tenants SET plan=$1, api_calls_limit=$2, agents_limit=$3 WHERE id=$4`,
      [plan, apiCallsLimit || limits.api, agentsLimit || limits.agents, req.params.id]
    );
    await redis.del(`tenant:${req.params.id}`);
    await auditSuperAdminAction(db, req, 'tenant.plan.update', req.params.id, `plan=${plan}`, {
      plan,
      apiCallsLimit: apiCallsLimit || limits.api,
      agentsLimit: agentsLimit || limits.agents,
    });
    return { updated: true };
  });

  // Plan limits: default plan limits + custom tenant contract overrides
  fastify.get('/admin/plan-limits', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [plans, recentBlocks] = await Promise.all([
      db.query(`SELECT * FROM plan_limits ORDER BY CASE plan WHEN 'starter' THEN 1 WHEN 'growth' THEN 2 WHEN 'enterprise' THEN 3 ELSE 4 END`),
      db.query(`
        SELECT pla.*, t.name AS tenant_name
        FROM plan_limit_audit pla
        LEFT JOIN tenants t ON t.id=pla.tenant_id
        ORDER BY pla.created_at DESC LIMIT 100`),
    ]);
    return { plans: plans.rows, recentBlocks: recentBlocks.rows };
  });

  fastify.get('/admin/enterprise-readiness', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const appUrl = String(process.env.APP_URL || '');
    const checks = await Promise.all([
      db.query(`SELECT to_regclass('public.plan_limits') IS NOT NULL AS ok`).then(r => ({ key: 'central_plan_limits', ok: r.rows[0].ok, detail: 'plan_limits table' })),
      db.query(`SELECT to_regclass('public.tenant_limit_overrides') IS NOT NULL AS ok`).then(r => ({ key: 'contract_overrides', ok: r.rows[0].ok, detail: 'tenant_limit_overrides table' })),
      db.query(`SELECT to_regclass('public.plan_limit_audit') IS NOT NULL AS ok`).then(r => ({ key: 'limit_block_audit', ok: r.rows[0].ok, detail: 'plan_limit_audit table' })),
      db.query(`SELECT to_regclass('public.admin_action_log') IS NOT NULL AS ok`).then(r => ({ key: 'admin_action_audit', ok: r.rows[0].ok, detail: 'admin_action_log table' })),
      db.query(`SELECT COUNT(*)::int AS count FROM plan_limits`).then(r => ({ key: 'default_plan_rows', ok: Number(r.rows[0].count) >= 3, detail: `${r.rows[0].count} plans configured` })),
      db.query(`SELECT COUNT(*)::int AS count FROM tenants WHERE active=true`).then(r => ({ key: 'active_tenants', ok: true, detail: `${r.rows[0].count} active tenants` })),
      db.query(`SELECT COUNT(*)::int AS count FROM tenants WHERE id=$1`, [LOCAL_DEMO_TENANT_ID]).then(r => ({
        key: 'local_demo_tenant_absent',
        ok: process.env.NODE_ENV !== 'production' || Number(r.rows[0].count) === 0,
        detail: process.env.NODE_ENV === 'production'
          ? `${r.rows[0].count} local demo tenants found`
          : 'local demo tenant allowed outside production',
      })),
      Promise.resolve({ key: 'secret_encryption_key', ok: hasProductionSecretEncryption(), detail: 'SECRET_ENCRYPTION_KEY configured for saved integration credentials' }),
      Promise.resolve({ key: 'https_public_url', ok: process.env.NODE_ENV !== 'production' || appUrl.startsWith('https://'), detail: appUrl || 'APP_URL not set' }),
      Promise.resolve({ key: 'sso_oidc_configured', ok: Boolean(process.env.OIDC_ISSUER || process.env.SSO_ISSUER || process.env.SAML_ENTRY_POINT), detail: 'OIDC/SAML issuer configured for production admin access' }),
      Promise.resolve({ key: 'admin_mfa_required', ok: process.env.ADMIN_MFA_REQUIRED === 'true' || process.env.NODE_ENV !== 'production', detail: process.env.ADMIN_MFA_REQUIRED === 'true' ? 'MFA required' : 'set ADMIN_MFA_REQUIRED=true before production' }),
      Promise.resolve({ key: 'admin_dual_control', ok: process.env.ADMIN_DUAL_CONTROL === 'true' || process.env.NODE_ENV !== 'production', detail: 'dual-control approvals for destructive admin actions' }),
    ]);
    const ready = checks.every(c => c.ok);
    return { ready, checks };
  });

  fastify.put<{ Params: { plan: string } }>('/admin/plan-limits/:plan', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const plan = req.params.plan;
    if (!['starter', 'growth', 'enterprise'].includes(plan)) return reply.code(400).send({ error: 'Invalid plan' });
    const body = req.body as any;
    const asLimit = (key: string, fallback: number) => Math.max(0, parseInt(body[key] ?? fallback, 10) || 0);
    await db.query(
      `UPDATE plan_limits SET
         max_alert_channels=$2,
         max_alert_rules=$3,
         max_agents=$4,
         max_integrations=$5,
         max_audit_export_days=$6,
         max_analytics_export_days=$7,
         max_retention_days=$8,
         max_team_members=$9,
         max_ml_profiles=$10,
         max_hitl_policies=$11,
         updated_at=NOW()
       WHERE plan=$1`,
      [
        plan,
        asLimit('alert_channels', 0),
        asLimit('alert_rules', 0),
        asLimit('agents', 0),
        asLimit('integrations', 0),
        asLimit('audit_export_days', 0),
        asLimit('analytics_export_days', 0),
        asLimit('retention_days', 0),
        asLimit('team_members', 0),
        asLimit('ml_profiles', 0),
        asLimit('hitl_policies', 0),
      ]
    );
    await auditSuperAdminAction(db, req, 'plan_limits.default.update', '00000000-0000-0000-0000-000000000000', `plan=${plan}`, { plan, limits: body });
    return { updated: true, plan };
  });

  fastify.get<{ Params: { id: string } }>('/admin/tenant-limits/:id', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const tenantId = req.params.id;
    const [tenant, effective, usage, overrides, blocks] = await Promise.all([
      db.query(`SELECT id, name, plan, billing_email, active FROM tenants WHERE id=$1`, [tenantId]),
      getPlanLimits(db, tenantId),
      getPlanUsage(db, tenantId),
      db.query(`SELECT feature_key, limit_value, updated_by, updated_at FROM tenant_limit_overrides WHERE tenant_id=$1 ORDER BY feature_key`, [tenantId]),
      db.query(`SELECT feature_key, action, message, used, limit_value, actor_email, created_at FROM plan_limit_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, [tenantId]),
    ]);
    if (!tenant.rows.length) return reply.code(404).send({ error: 'Tenant not found' });
    return { tenant: tenant.rows[0], plan: effective.plan, limits: effective.limits, usage, overrides: overrides.rows, blocks: blocks.rows };
  });

  fastify.put<{ Params: { id: string } }>('/admin/tenant-limits/:id/overrides', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const tenantId = req.params.id;
    const { featureKey, limitValue } = req.body as any;
    const allowed = ['alert_channels','alert_rules','agents','integrations','audit_export_days','analytics_export_days','retention_days','team_members','ml_profiles','hitl_policies'];
    const value = parseInt(limitValue, 10);
    if (!allowed.includes(featureKey) || !Number.isFinite(value) || value < 0) {
      return reply.code(400).send({ error: 'Valid featureKey and non-negative limitValue required' });
    }
    await db.query(
      `INSERT INTO tenant_limit_overrides (tenant_id, feature_key, limit_value, updated_by, updated_at)
       VALUES ($1,$2,$3,'super-admin',NOW())
       ON CONFLICT (tenant_id, feature_key)
       DO UPDATE SET limit_value=$3, updated_by='super-admin', updated_at=NOW()`,
      [tenantId, featureKey, value]
    );
    await auditSuperAdminAction(db, req, 'plan_limits.tenant_override.set', tenantId, `${featureKey}=${value}`, { featureKey, limitValue: value });
    return { saved: true, tenantId, featureKey, limitValue: value };
  });

  fastify.delete<{ Params: { id: string; featureKey: string } }>('/admin/tenant-limits/:id/overrides/:featureKey', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    await db.query(
      `DELETE FROM tenant_limit_overrides WHERE tenant_id=$1 AND feature_key=$2`,
      [req.params.id, req.params.featureKey]
    );
    await auditSuperAdminAction(db, req, 'plan_limits.tenant_override.reset', req.params.id, req.params.featureKey, { featureKey: req.params.featureKey });
    return { deleted: true, tenantId: req.params.id, featureKey: req.params.featureKey };
  });

  // ── Registry moderation ────────────────────────────────────────────

  fastify.get('/admin/tenant-usage', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const tenants = await db.query(`
      SELECT t.id, t.name, t.plan, t.active, t.billing_email,
             COALESCE(um.api_calls,0)::bigint AS api_calls_this_month,
             COALESCE(t.api_calls_limit,0)::bigint AS api_calls_limit,
             COALESCE(t.agents_limit,0)::int AS agents_limit,
             COUNT(DISTINCT at.agent_id)::int FILTER (WHERE at.active=true) AS active_agents,
             COUNT(DISTINCT ar.id)::int FILTER (WHERE ar.active=true) AS alert_rules,
             COUNT(DISTINCT ac.id)::int FILTER (WHERE ac.active=true) AS alert_channels,
             COUNT(DISTINCT amp.agent_id)::int AS ml_profiles,
             COUNT(DISTINCT am.id)::int FILTER (WHERE am.active=true) AS team_members
      FROM tenants t
      LEFT JOIN usage_metrics um ON um.tenant_id=t.id AND um.month=TO_CHAR(NOW(),'YYYY-MM')
      LEFT JOIN agent_tokens at ON at.tenant_id=t.id
      LEFT JOIN alert_rules ar ON ar.tenant_id=t.id
      LEFT JOIN alert_channels ac ON ac.tenant_id=t.id
      LEFT JOIN agent_ml_profiles amp ON amp.tenant_id=t.id
      LEFT JOIN admin_members am ON am.tenant_id=t.id
      GROUP BY t.id, um.api_calls
      ORDER BY api_calls_this_month DESC NULLS LAST, t.created_at DESC
      LIMIT 200
    `).catch(() => ({ rows: [] as any[] }));
    const rows = await Promise.all(tenants.rows.map(async (t: any) => {
      const effective = await getPlanLimits(db, t.id).catch(() => ({ limits: {} as any }));
      const usage = await getPlanUsage(db, t.id).catch(() => ({} as any));
      return { ...t, limits: effective.limits, usage };
    }));
    return { tenants: rows };
  });

  fastify.get('/admin/admin-audit', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [tenantActions, legacyActions] = await Promise.all([
      db.query(`
        SELECT aal.*, t.name AS tenant_name
        FROM admin_action_log aal
        LEFT JOIN tenants t ON t.id=aal.tenant_id
        ORDER BY aal.created_at DESC LIMIT 150
      `).catch(() => ({ rows: [] as any[] })),
      db.query(`SELECT * FROM admin_actions ORDER BY created_at DESC LIMIT 50`).catch(() => ({ rows: [] as any[] })),
    ]);
    return { actions: tenantActions.rows, legacyActions: legacyActions.rows };
  });

  fastify.get('/admin/admin-audit/export', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const rows = await db.query(`
      SELECT aal.created_at, aal.actor_email, aal.actor_role, aal.action,
             aal.target, aal.tenant_id, t.name AS tenant_name, aal.details_json
      FROM admin_action_log aal
      LEFT JOIN tenants t ON t.id=aal.tenant_id
      ORDER BY aal.created_at DESC
      LIMIT 5000
    `).catch(() => ({ rows: [] as any[] }));
    const header = ['created_at','actor_email','actor_role','action','target','tenant_id','tenant_name','details_json'];
    const csv = [
      header.join(','),
      ...rows.rows.map((r: any) => header.map(k => csvEscape(k === 'details_json' ? JSON.stringify(r[k] || {}) : r[k])).join(',')),
    ].join('\n');
    await auditSuperAdminAction(db, req, 'admin_audit.export', '00000000-0000-0000-0000-000000000000', 'csv_export', { rows: rows.rows.length });
    return reply
      .header('Content-Type', 'text/csv; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="admin-audit-${new Date().toISOString().slice(0, 10)}.csv"`)
      .send(csv);
  });

  fastify.get('/admin/integrations-health', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [channels, deliveries] = await Promise.all([
      db.query(`
        SELECT c.*, t.name AS tenant_name,
               COUNT(wd.id)::int AS delivery_count,
               COUNT(wd.id) FILTER (WHERE wd.success=true)::int AS success_count,
               COUNT(wd.id) FILTER (WHERE wd.success=false)::int AS failure_count,
               MAX(wd.created_at) AS last_delivery_at,
               MAX(wd.error_message) FILTER (WHERE wd.success=false) AS last_error
        FROM alert_channels c
        LEFT JOIN tenants t ON t.id=c.tenant_id
        LEFT JOIN webhook_deliveries wd ON wd.tenant_id=c.tenant_id AND wd.channel LIKE (c.type || ':%')
        GROUP BY c.id, t.name
        ORDER BY c.updated_at DESC NULLS LAST, c.created_at DESC
        LIMIT 200
      `).catch(() => ({ rows: [] as any[] })),
      db.query(`
        SELECT wd.*, t.name AS tenant_name
        FROM webhook_deliveries wd
        LEFT JOIN tenants t ON t.id=wd.tenant_id
        ORDER BY wd.created_at DESC LIMIT 100
      `).catch(() => ({ rows: [] as any[] })),
    ]);
    return { channels: channels.rows, deliveries: deliveries.rows };
  });

  fastify.get('/admin/compliance', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [retention, exports, immutable, hash, soc2] = await Promise.all([
      db.query(`SELECT rp.*, t.name AS tenant_name FROM retention_policies rp LEFT JOIN tenants t ON t.id=rp.tenant_id ORDER BY rp.updated_at DESC NULLS LAST LIMIT 100`).catch(() => ({ rows: [] as any[] })),
      db.query(`SELECT aej.*, t.name AS tenant_name FROM audit_export_jobs aej LEFT JOIN tenants t ON t.id=aej.tenant_id ORDER BY aej.created_at DESC LIMIT 100`).catch(() => ({ rows: [] as any[] })),
      db.query(`SELECT COUNT(*)::int AS rows FROM audit.immutable_log`).catch(() => ({ rows: [{ rows: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS rows FROM audit_log WHERE prev_hash IS NOT NULL OR row_hash IS NOT NULL`).catch(() => ({ rows: [{ rows: 0 }] })),
      db.query(`SELECT ser.*, t.name AS tenant_name FROM soc2_evidence_runs ser LEFT JOIN tenants t ON t.id=ser.tenant_id ORDER BY ser.created_at DESC LIMIT 50`).catch(() => ({ rows: [] as any[] })),
    ]);
    return { retention: retention.rows, exports: exports.rows, immutableRows: immutable.rows[0]?.rows || 0, hashChainedRows: hash.rows[0]?.rows || 0, soc2Runs: soc2.rows };
  });

  fastify.get('/admin/deployment-regions', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const tenants = await db.query(`
      SELECT preferred_region AS region, COUNT(*)::int AS tenants,
             COUNT(*) FILTER (WHERE active=true)::int AS active_tenants
      FROM tenants
      GROUP BY preferred_region
      ORDER BY tenants DESC
    `).catch(() => ({ rows: [] as any[] }));
    const sla = await db.query(`
      SELECT region, metric_type, AVG(value)::numeric(12,2) AS avg_value, MAX(recorded_at) AS last_seen
      FROM sla_metrics
      WHERE recorded_at > NOW()-INTERVAL '24 hours'
      GROUP BY region, metric_type
      ORDER BY region, metric_type
    `).catch(() => ({ rows: [] as any[] }));
    return { regions: tenants.rows, sla: sla.rows, deployment: { activeRegion: process.env.REGION || process.env.AWS_REGION || 'local', dataResidencyMode: process.env.DATA_RESIDENCY_MODE || 'tenant_preferred_region', failoverMode: process.env.FAILOVER_MODE || 'manual' } };
  });

  fastify.get('/admin/incidents', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [events, hitl, deliveries, tenants] = await Promise.all([
      db.query(`
        SELECT ae.*, t.name AS tenant_name
        FROM anomaly_events ae
        LEFT JOIN tenants t ON t.id=ae.tenant_id
        WHERE ae.score >= 40 AND ae.created_at > NOW()-INTERVAL '24 hours'
        ORDER BY ae.score DESC, ae.created_at DESC LIMIT 100
      `).catch(() => ({ rows: [] as any[] })),
      db.query(`SELECT COUNT(*)::int AS pending FROM hitl_approvals WHERE decision IS NULL`).catch(() => ({ rows: [{ pending: 0 }] })),
      db.query(`SELECT COUNT(*)::int AS failed FROM webhook_deliveries WHERE success=false AND created_at > NOW()-INTERVAL '24 hours'`).catch(() => ({ rows: [{ failed: 0 }] })),
      db.query(`
        SELECT t.id, t.name, COUNT(al.id)::int AS denials_24h
        FROM tenants t
        JOIN audit_log al ON al.tenant_id=t.id AND al.decision='DENY' AND al.created_at > NOW()-INTERVAL '24 hours'
        GROUP BY t.id
        ORDER BY denials_24h DESC LIMIT 20
      `).catch(() => ({ rows: [] as any[] })),
    ]);
    return { anomalies: events.rows, pendingHitl: hitl.rows[0]?.pending || 0, failedDeliveries: deliveries.rows[0]?.failed || 0, highDenialTenants: tenants.rows };
  });

  fastify.get('/admin/rbac-admin', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [members, groups] = await Promise.all([
      db.query(`
        SELECT am.*, t.name AS tenant_name
        FROM admin_members am
        LEFT JOIN tenants t ON t.id=am.tenant_id
        ORDER BY am.created_at DESC LIMIT 200
      `).catch(() => ({ rows: [] as any[] })),
      db.query(`
        SELECT sgm.*, t.name AS tenant_name
        FROM sso_group_mappings sgm
        LEFT JOIN tenants t ON t.id=sgm.tenant_id
        ORDER BY sgm.created_at DESC LIMIT 200
      `).catch(() => ({ rows: [] as any[] })),
    ]);
    return {
      members: members.rows,
      groups: groups.rows,
      roles: {
        super_admin: ['all platform controls'],
        security_analyst: ['security events', 'HITL', 'audit export', 'policies', 'ML'],
        billing_admin: ['billing', 'usage', 'invoices'],
        viewer: ['read-only dashboards'],
      },
    };
  });

  fastify.get('/admin/registry', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`SELECT rs.*, COUNT(rr.id) as report_count,
        COALESCE(jsonb_array_length(rs.allowed_tenants),0) AS allowed_tenant_count,
        COALESCE(jsonb_array_length(rs.allowed_agents),0) AS allowed_agent_count
      FROM registry_servers rs
      LEFT JOIN registry_reports rr ON rr.server_id=rs.id
      GROUP BY rs.id ORDER BY report_count DESC, rs.created_at DESC`);
    return { servers: r.rows };
  });

  fastify.put<{ Params: { id: string } }>('/admin/registry/:id/trust', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { trustLevel, trustScore, verified, reason } = req.body as any;
    const before = await db.query(`SELECT trust_level, trust_score FROM registry_servers WHERE id=$1`, [req.params.id]);
    await db.query(
      `UPDATE registry_servers SET trust_level=$1, trust_score=$2, verified=$3, last_reviewed_at=NOW(), last_reviewed_by=$4, updated_at=NOW() WHERE id=$5`,
      [trustLevel, trustScore, verified, String((req as any).admin?.email || 'super-admin'), req.params.id]
    );
    if (before.rows.length) await db.query(
      `INSERT INTO registry_trust_history (server_id, previous_trust_level, new_trust_level, previous_trust_score, new_trust_score, changed_by, reason)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [req.params.id, before.rows[0].trust_level, trustLevel, before.rows[0].trust_score, trustScore, String((req as any).admin?.email || 'super-admin'), reason || 'admin trust update']
    ).catch(() => {});
    await auditSuperAdminAction(db, req, 'registry.trust.update', req.params.id, `trust=${trustLevel}`, {
      trustLevel,
      trustScore,
      verified,
      reason: reason || null,
    });
    const server = await db.query(`SELECT name FROM registry_servers WHERE id=$1`, [req.params.id]);
    if (server.rows[0]?.name) {
      const keys = await redis.keys(`registry:trust:${server.rows[0].name}:*`).catch(() => []);
      if (keys.length) await redis.del(...keys).catch(() => {});
    }
    return { updated: true };
  });

  fastify.put<{ Params: { id: string } }>('/admin/registry/:id/metadata', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { ownerEmail, ownerTeam, allowedTenants, allowedAgents, schemaValidation } = req.body as any;
    const list = (v: unknown) => Array.isArray(v) ? v.map(String).filter(Boolean) : String(v || '').split(',').map(s => s.trim()).filter(Boolean);
    const r = await db.query(
      `UPDATE registry_servers SET owner_email=$2, owner_team=$3, allowed_tenants=$4, allowed_agents=$5, schema_validation=$6, updated_at=NOW()
       WHERE id=$1 RETURNING *`,
      [req.params.id, ownerEmail || null, ownerTeam || null, JSON.stringify(list(allowedTenants)), JSON.stringify(list(allowedAgents)), schemaValidation || 'available']
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'Server not found' });
    await auditSuperAdminAction(db, req, 'registry.metadata.update', req.params.id, 'metadata update', {
      ownerEmail,
      ownerTeam,
      allowedTenants: list(allowedTenants),
      allowedAgents: list(allowedAgents),
      schemaValidation: schemaValidation || 'available',
    });
    return { updated: true, server: r.rows[0] };
  });

  // ── System-wide metrics ────────────────────────────────────────────

  fastify.get('/admin/system', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const [db_size, top_tools, error_rate, redis_info] = await Promise.all([
      db.query(`SELECT pg_size_pretty(pg_database_size(current_database())) as db_size`),
      db.query(`SELECT tool_name, COUNT(*) as calls FROM audit_log
                WHERE created_at > NOW()-INTERVAL '7d' GROUP BY tool_name ORDER BY calls DESC LIMIT 20`),
      db.query(`SELECT COUNT(*) FILTER (WHERE decision='DENY') as denied, COUNT(*) as total
                FROM audit_log WHERE created_at > NOW()-INTERVAL '1h'`),
      redis.info('memory'),
    ]);
    return {
      dbSize: db_size.rows[0].db_size,
      topTools7d: top_tools.rows,
      errorRate1h: error_rate.rows[0],
      redisMemory: redis_info,
      nodeVersion: process.version,
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
    };
  });

  // ── Admin action log ───────────────────────────────────────────────

  fastify.get('/admin/actions', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`SELECT * FROM admin_actions ORDER BY created_at DESC LIMIT 100`);
    return { actions: r.rows };
  });

  // ── Security events (cross-tenant) ────────────────────────────────
  fastify.get('/admin/security-events', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const hours = parseInt(((req.query as any).hours || '24'), 10);
    const [anomalies, injections, dlp, hitl] = await Promise.all([
      db.query(`SELECT ae.*, t.name as tenant_name FROM anomaly_events ae
                LEFT JOIN tenants t ON t.id=ae.tenant_id
                WHERE ae.created_at > NOW()-INTERVAL '${hours} hours'
                ORDER BY ae.created_at DESC LIMIT 100`),
      db.query(`SELECT il.*, t.name as tenant_name FROM injection_debug_log il
                LEFT JOIN tenants t ON t.id=il.tenant_id
                WHERE il.created_at > NOW()-INTERVAL '${hours} hours'
                ORDER BY il.created_at DESC LIMIT 100`),
      db.query(`SELECT COUNT(*) as cnt FROM audit_log
                WHERE reason LIKE 'dlp_blocked%' AND created_at > NOW()-INTERVAL '${hours} hours'`),
      db.query(`SELECT COUNT(*) as cnt FROM hitl_approvals
                WHERE created_at > NOW()-INTERVAL '${hours} hours'`),
    ]);
    const anomalyMessage = (payload: any): string => {
      if (!payload) return 'anomaly';
      let parsed = payload;
      if (typeof payload === 'string') {
        try { parsed = JSON.parse(payload); } catch { return payload || 'anomaly'; }
      }
      const first = Array.isArray(parsed) ? parsed[0] : parsed;
      if (typeof first === 'string') return first;
      return first?.description || first?.reason || first?.message || 'anomaly';
    };
    const events = [
      ...anomalies.rows.map((r: any) => ({ ...r, event_type: 'anomaly_detected', severity: r.score >= 80 ? 'critical' : 'high', message: anomalyMessage(r.reasons_json), tool_name: r.tool_name, triggered_at: r.created_at })),
      ...injections.rows.map((r: any) => ({ ...r, event_type: 'injection_detected', severity: 'high', message: r.pattern_name, triggered_at: r.created_at })),
    ].sort((a: any, b: any) => new Date(b.triggered_at).getTime() - new Date(a.triggered_at).getTime());
    return { events, dlpCount: dlp.rows[0].cnt, hitlCount: hitl.rows[0].cnt };
  });

  // ── Invoices (cross-tenant) ────────────────────────────────────────
  fastify.get('/admin/invoices', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`
      SELECT bi.*, t.name as tenant_name
      FROM billing_invoices bi
      LEFT JOIN tenants t ON t.id=bi.tenant_id
      ORDER BY bi.created_at DESC LIMIT 200`);
    return { invoices: r.rows };
  });

  // ── Global anomaly events ──────────────────────────────────────────
  fastify.get('/admin/anomalies', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const hours = parseInt(((req.query as any).hours || '24'), 10);
    const r = await db.query(`
      SELECT ae.*, t.name as tenant_name
      FROM anomaly_events ae
      LEFT JOIN tenants t ON t.id=ae.tenant_id
      WHERE ae.created_at > NOW()-INTERVAL '${hours} hours'
      ORDER BY ae.created_at DESC LIMIT 200`);
    return { events: r.rows };
  });

  // ── Global injection log ───────────────────────────────────────────
  fastify.get('/admin/injection-log', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const hours = parseInt(((req.query as any).hours || '24'), 10);
    const r = await db.query(`
      SELECT il.*, t.name as tenant_name
      FROM injection_debug_log il
      LEFT JOIN tenants t ON t.id=il.tenant_id
      WHERE il.created_at > NOW()-INTERVAL '${hours} hours'
      ORDER BY il.created_at DESC LIMIT 200`);
    return { events: r.rows };
  });

  // ── HITL queue (cross-tenant) ──────────────────────────────────────
  fastify.get('/admin/hitl-queue', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`
      SELECT
        hr.approval_id AS id,
        hr.approval_id,
        hr.tenant_id,
        hr.agent_id,
        hr.tool_name,
        hr.args_json,
        hr.risk_level AS risk,
        hr.risk_reason AS reason,
        hr.decision,
        hr.decided_at,
        hr.decided_by,
        hr.created_at,
        hr.expires_at,
        t.name as tenant_name,
        EXTRACT(EPOCH FROM (NOW()-hr.created_at))*1000 AS decision_ms
      FROM hitl_approvals hr
      LEFT JOIN tenants t ON t.id=hr.tenant_id
      ORDER BY hr.created_at DESC LIMIT 200`);
    return { requests: r.rows };
  });

  fastify.post<{ Params: { id: string } }>('/api/hitl/:id/decide', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const { decision, decidedBy } = req.body as any;
    await db.query(
      `UPDATE hitl_approvals SET decision=$1, decided_by=$2, decided_at=NOW() WHERE approval_id=$3`,
      [decision, decidedBy || 'admin', req.params.id]
    );
    return { decided: true };
  });

  // ── ML profiles (cross-tenant) ────────────────────────────────────
  fastify.get('/admin/ml-profiles', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`
      SELECT ab.*, t.name as tenant_name
      FROM agent_baselines ab
      LEFT JOIN tenants t ON t.id=ab.tenant_id
      ORDER BY ab.baseline_sample_size DESC LIMIT 200`);
    return { profiles: r.rows };
  });

  fastify.post('/admin/ml-profiles/rebuild', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    // Trigger rebuild by setting a Redis key the cron picks up
    await redis.set('admin:trigger_ml_rebuild', '1', 'EX', 300);
    return { triggered: true };
  });

  // ── Geo blocks (cross-tenant admin view) ──────────────────────────
  fastify.get('/admin/geo-blocks', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`
      SELECT gb.*, t.name as tenant_name,
        (SELECT COUNT(*) FROM audit_log al
         WHERE al.tenant_id=gb.tenant_id
           AND al.reason LIKE '%geo_blocked%'
           AND al.created_at > NOW()-INTERVAL '24h') as blocked_24h
      FROM tenant_geo_blocks gb
      LEFT JOIN tenants t ON t.id=gb.tenant_id
      WHERE gb.active=true
      ORDER BY gb.created_at DESC`);
    return { rules: r.rows };
  });

  // ── Tool rate limits (cross-tenant admin view) ────────────────────
  fastify.get('/admin/tool-rate-limits', async (req, reply) => {
    if (!requireAdmin(req, reply)) return;
    const r = await db.query(`
      SELECT trl.*, t.name as tenant_name,
        0 as throttled_1h, 0 as blocked_1h
      FROM tool_rate_limits trl
      LEFT JOIN tenants t ON t.id=trl.tenant_id
      WHERE trl.active=true
      ORDER BY trl.created_at DESC`);
    return { limits: r.rows };
  });

  // ── Serve admin UI ─────────────────────────────────────────────────

  fastify.get('/admin', async (req, reply) => {
    const secret = (req.query as any).secret;
    if (secret && secret === process.env.ADMIN_SECRET) {
      const email = String(process.env.ADMIN_EMAIL || 'admin@local');
      const token = signAdminSession({ email, role: 'super_admin', exp: Date.now() + ADMIN_SESSION_TTL_SECONDS * 1000 });
      setAdminCookie(reply, token);
      return reply.redirect('/admin');
    }
    if (!adminFromRequest(req)) {
      return reply.type('text/html').send(adminLoginHtml());
    }
    try {
      const { readFileSync } = require('fs');
      const { join } = require('path');
      const html = readFileSync(join(__dirname, 'admin.html'), 'utf-8');
      reply.type('text/html').send(html);
    } catch {
      reply.type('text/html').send('<h2>Admin UI not found.</h2>');
    }
  });
}
