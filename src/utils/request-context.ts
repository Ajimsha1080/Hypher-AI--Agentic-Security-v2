import { Pool } from 'pg';

export function requestTenantId(req: any): string | undefined {
  const headerTenant = req.headers?.['x-tenant-id'];
  const tenantId = req.tenant?.id || (Array.isArray(headerTenant) ? headerTenant[0] : headerTenant);
  return tenantId ? String(tenantId) : undefined;
}

export async function requestTenantPlan(req: any, db: Pool): Promise<string | undefined> {
  if (req.tenant?.plan) return String(req.tenant.plan);
  const tenantId = requestTenantId(req);
  if (!tenantId) return undefined;
  const r = await db.query('SELECT plan FROM tenants WHERE id=$1 AND active=TRUE', [tenantId]);
  return r.rows[0]?.plan;
}

export async function requestHasPlan(req: any, db: Pool, allowedPlans: string[]): Promise<boolean> {
  const plan = await requestTenantPlan(req, db);
  return !!plan && allowedPlans.includes(plan);
}
