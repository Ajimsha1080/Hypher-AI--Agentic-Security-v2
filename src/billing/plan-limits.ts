import { Pool } from 'pg';

export type PlanFeatureKey =
  | 'alert_channels'
  | 'alert_rules'
  | 'agents'
  | 'integrations'
  | 'audit_export_days'
  | 'analytics_export_days'
  | 'retention_days'
  | 'team_members'
  | 'ml_profiles'
  | 'hitl_policies';

export type PlanLimits = Record<PlanFeatureKey, number>;

const FEATURE_KEYS: PlanFeatureKey[] = [
  'alert_channels',
  'alert_rules',
  'agents',
  'integrations',
  'audit_export_days',
  'analytics_export_days',
  'retention_days',
  'team_members',
  'ml_profiles',
  'hitl_policies',
];

const DEFAULT_LIMITS: Record<string, PlanLimits> = {
  starter: {
    alert_channels: 2,
    alert_rules: 5,
    agents: 5,
    integrations: 1,
    audit_export_days: 0,
    analytics_export_days: 7,
    retention_days: 7,
    team_members: 2,
    ml_profiles: 1,
    hitl_policies: 1,
  },
  growth: {
    alert_channels: 10,
    alert_rules: 25,
    agents: 25,
    integrations: 5,
    audit_export_days: 30,
    analytics_export_days: 30,
    retention_days: 30,
    team_members: 10,
    ml_profiles: 25,
    hitl_policies: 10,
  },
  enterprise: {
    alert_channels: 1000,
    alert_rules: 1000,
    agents: 200,
    integrations: 100,
    audit_export_days: 365,
    analytics_export_days: 365,
    retention_days: 365,
    team_members: 200,
    ml_profiles: 200,
    hitl_policies: 100,
  },
};

export class PlanLimitError extends Error {
  code = 'PLAN_LIMIT_EXCEEDED';
  statusCode = 403;
  details: Record<string, unknown>;

  constructor(message: string, details: Record<string, unknown>) {
    super(message);
    this.details = details;
  }
}

export async function ensurePlanLimitSchema(db: Pool): Promise<void> {
  await db.query(`
    CREATE TABLE IF NOT EXISTS plan_limits (
      plan TEXT PRIMARY KEY,
      max_alert_channels INTEGER NOT NULL,
      max_alert_rules INTEGER NOT NULL,
      max_agents INTEGER NOT NULL,
      max_integrations INTEGER NOT NULL,
      max_audit_export_days INTEGER NOT NULL,
      max_analytics_export_days INTEGER NOT NULL,
      max_retention_days INTEGER NOT NULL,
      max_team_members INTEGER NOT NULL,
      max_ml_profiles INTEGER NOT NULL,
      max_hitl_policies INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS tenant_limit_overrides (
      tenant_id UUID NOT NULL,
      feature_key TEXT NOT NULL,
      limit_value INTEGER NOT NULL,
      updated_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (tenant_id, feature_key)
    )
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS plan_limit_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      plan TEXT,
      feature_key TEXT NOT NULL,
      used INTEGER NOT NULL,
      limit_value INTEGER NOT NULL,
      allowed BOOLEAN NOT NULL DEFAULT FALSE,
      action TEXT NOT NULL,
      message TEXT,
      actor_email TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_plan_limit_audit_tenant ON plan_limit_audit(tenant_id, created_at DESC)`);

  for (const [plan, limits] of Object.entries(DEFAULT_LIMITS)) {
    await db.query(
      `INSERT INTO plan_limits (
         plan, max_alert_channels, max_alert_rules, max_agents, max_integrations,
         max_audit_export_days, max_analytics_export_days, max_retention_days,
         max_team_members, max_ml_profiles, max_hitl_policies, updated_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
       ON CONFLICT (plan) DO UPDATE SET
         max_alert_channels=$2, max_alert_rules=$3, max_agents=$4, max_integrations=$5,
         max_audit_export_days=$6, max_analytics_export_days=$7, max_retention_days=$8,
         max_team_members=$9, max_ml_profiles=$10, max_hitl_policies=$11, updated_at=NOW()`,
      [
        plan,
        limits.alert_channels,
        limits.alert_rules,
        limits.agents,
        limits.integrations,
        limits.audit_export_days,
        limits.analytics_export_days,
        limits.retention_days,
        limits.team_members,
        limits.ml_profiles,
        limits.hitl_policies,
      ]
    );
  }
}

export async function getPlanLimits(db: Pool, tenantId: string): Promise<{ plan: string; limits: PlanLimits }> {
  await ensurePlanLimitSchema(db);
  const tenant = await db.query(`SELECT COALESCE(plan, 'starter') AS plan FROM tenants WHERE id=$1`, [tenantId]);
  const plan = tenant.rows[0]?.plan || 'starter';
  const base = await db.query(`SELECT * FROM plan_limits WHERE plan=$1`, [plan]);
  const row = base.rows[0] || {};
  const limits: PlanLimits = {
    alert_channels: Number(row.max_alert_channels ?? DEFAULT_LIMITS.starter.alert_channels),
    alert_rules: Number(row.max_alert_rules ?? DEFAULT_LIMITS.starter.alert_rules),
    agents: Number(row.max_agents ?? DEFAULT_LIMITS.starter.agents),
    integrations: Number(row.max_integrations ?? DEFAULT_LIMITS.starter.integrations),
    audit_export_days: Number(row.max_audit_export_days ?? DEFAULT_LIMITS.starter.audit_export_days),
    analytics_export_days: Number(row.max_analytics_export_days ?? DEFAULT_LIMITS.starter.analytics_export_days),
    retention_days: Number(row.max_retention_days ?? DEFAULT_LIMITS.starter.retention_days),
    team_members: Number(row.max_team_members ?? DEFAULT_LIMITS.starter.team_members),
    ml_profiles: Number(row.max_ml_profiles ?? DEFAULT_LIMITS.starter.ml_profiles),
    hitl_policies: Number(row.max_hitl_policies ?? DEFAULT_LIMITS.starter.hitl_policies),
  };
  const overrides = await db.query(
    `SELECT feature_key, limit_value FROM tenant_limit_overrides WHERE tenant_id=$1`,
    [tenantId]
  );
  for (const override of overrides.rows) {
    if (FEATURE_KEYS.includes(override.feature_key)) {
      limits[override.feature_key as PlanFeatureKey] = Number(override.limit_value);
    }
  }
  return { plan, limits };
}

export async function getPlanUsage(db: Pool, tenantId: string): Promise<Record<PlanFeatureKey, number>> {
  await ensurePlanLimitSchema(db);
  const [
    channels,
    rules,
    agents,
    integrations,
    members,
    profiles,
    hitlPolicies,
  ] = await Promise.all([
    db.query(`SELECT COUNT(*)::int AS count FROM alert_channels WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(`SELECT COUNT(*)::int AS count FROM alert_rules WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(`SELECT COUNT(DISTINCT agent_id)::int AS count FROM agent_tokens WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(
      `SELECT COUNT(*)::int AS count
       FROM alert_channels
       WHERE tenant_id=$1 AND active=true AND type IN ('slack','pagerduty','teams','siem')`,
      [tenantId]
    ).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(`SELECT COUNT(*)::int AS count FROM admin_members WHERE tenant_id=$1 AND active=true`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(`SELECT COUNT(*)::int AS count FROM agent_ml_profiles WHERE tenant_id=$1`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
    db.query(`SELECT COUNT(*)::int AS count FROM hitl_rules WHERE tenant_id=$1`, [tenantId]).catch(() => ({ rows: [{ count: 0 }] })),
  ]);

  return {
    alert_channels: Number(channels.rows[0]?.count || 0),
    alert_rules: Number(rules.rows[0]?.count || 0),
    agents: Number(agents.rows[0]?.count || 0),
    integrations: Number(integrations.rows[0]?.count || 0),
    audit_export_days: 0,
    analytics_export_days: 0,
    retention_days: 0,
    team_members: Number(members.rows[0]?.count || 0),
    ml_profiles: Number(profiles.rows[0]?.count || 0),
    hitl_policies: Number(hitlPolicies.rows[0]?.count || 0),
  };
}

export async function auditPlanLimitBlock(
  db: Pool,
  params: {
    tenantId: string;
    plan: string;
    featureKey: PlanFeatureKey;
    used: number;
    limitValue: number;
    action: string;
    message: string;
    actorEmail?: string;
  }
): Promise<void> {
  await db.query(
    `INSERT INTO plan_limit_audit
       (tenant_id, plan, feature_key, used, limit_value, allowed, action, message, actor_email, created_at)
     VALUES ($1,$2,$3,$4,$5,false,$6,$7,$8,NOW())`,
    [
      params.tenantId,
      params.plan,
      params.featureKey,
      params.used,
      params.limitValue,
      params.action,
      params.message,
      params.actorEmail || null,
    ]
  ).catch(() => {});
}

export async function enforcePlanLimit(
  db: Pool,
  params: {
    tenantId: string;
    featureKey: PlanFeatureKey;
    used: number;
    action: string;
    actorEmail?: string;
    increment?: number;
  }
): Promise<void> {
  const { plan, limits } = await getPlanLimits(db, params.tenantId);
  const limitValue = limits[params.featureKey];
  const nextUsed = params.used + (params.increment ?? 1);
  if (limitValue < 0 || nextUsed <= limitValue) return;
  const message = `${params.featureKey} plan limit reached (${params.used}/${limitValue}). Upgrade plan or request a tenant override.`;
  await auditPlanLimitBlock(db, {
    tenantId: params.tenantId,
    plan,
    featureKey: params.featureKey,
    used: params.used,
    limitValue,
    action: params.action,
    message,
    actorEmail: params.actorEmail,
  });
  throw new PlanLimitError(message, {
    featureKey: params.featureKey,
    used: params.used,
    limit: limitValue,
    plan,
    action: params.action,
  });
}

export async function enforceMaxValue(
  db: Pool,
  params: {
    tenantId: string;
    featureKey: PlanFeatureKey;
    requested: number;
    action: string;
    actorEmail?: string;
  }
): Promise<void> {
  const { plan, limits } = await getPlanLimits(db, params.tenantId);
  const limitValue = limits[params.featureKey];
  if (limitValue < 0 || params.requested <= limitValue) return;
  const message = `${params.featureKey} plan limit is ${limitValue}; requested ${params.requested}. Upgrade plan or request a tenant override.`;
  await auditPlanLimitBlock(db, {
    tenantId: params.tenantId,
    plan,
    featureKey: params.featureKey,
    used: params.requested,
    limitValue,
    action: params.action,
    message,
    actorEmail: params.actorEmail,
  });
  throw new PlanLimitError(message, {
    featureKey: params.featureKey,
    requested: params.requested,
    limit: limitValue,
    plan,
    action: params.action,
  });
}

export function planLimitErrorPayload(err: any): { error: string; code: string; details?: unknown } {
  return {
    error: err?.message || 'Plan limit exceeded',
    code: err?.code || 'PLAN_LIMIT_EXCEEDED',
    details: err?.details,
  };
}

