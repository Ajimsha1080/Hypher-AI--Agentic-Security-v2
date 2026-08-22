import fs from 'fs';
import path from 'path';

const repoRoot = path.join(__dirname, '..', '..');
const tenantId = process.env.E2E_TENANT_ID || 'c71bee1e-5d56-4f65-9495-b580dafb90f6';
const baseUrl = process.env.E2E_BASE_URL || 'http://127.0.0.1:3000';

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf-8');
}

function envValue(name: string): string {
  const envPath = path.join(repoRoot, '.env');
  if (!fs.existsSync(envPath)) return process.env[name] || '';
  const line = fs.readFileSync(envPath, 'utf-8')
    .split(/\r?\n/)
    .find((row) => row.startsWith(`${name}=`));
  return process.env[name] || (line ? line.replace(`${name}=`, '').replace(/^"|"$/g, '') : '');
}

async function request(pathname: string, init: RequestInit = {}) {
  const res = await fetch(`${baseUrl}${pathname}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  const text = await res.text();
  let body: any = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // Keep non-JSON body for HTML endpoints.
  }
  return { res, body };
}

function tenantHeaders(role = 'local_admin') {
  return {
    'X-Tenant-ID': tenantId,
    'X-Admin-Role': role,
    'X-Admin-Email': `${role}@example.com`,
  };
}

describe('enterprise boundary guardrails', () => {
  it('hides the admin switch for non-admin dashboard users', () => {
    const html = readSource('src/dashboard/combined.html');
    expect(html).toContain("adminBtn.style.display=canOpenAdmin?'':'none'");
    expect(html).not.toContain("localStorage.setItem('mcpsg_user_role','local_admin')");
  });

  it('does not hardcode security_analyst into alert requests', () => {
    const html = readSource('src/dashboard/combined.html');
    expect(html).toContain("function alertHeaders(){return {...H,'X-Tenant-ID':tenantHeader(),'X-Admin-Role':currentUserRole()");
    expect(html).not.toContain("'X-Admin-Role':'security_analyst'");
  });

  it('ignores browser-spoofed role headers in production-sensitive helpers', () => {
    const dashboardPlugin = readSource('src/dashboard/plugin.ts');
    const alerting = readSource('src/webhooks/alerting.ts');
    const registry = readSource('src/registry/registry.ts');

    for (const src of [dashboardPlugin, alerting, registry]) {
      expect(src).toContain('function allowBrowserRoleHeaders()');
      expect(src).toContain("process.env.NODE_ENV !== 'production'");
    }

    expect(dashboardPlugin).toContain("if (allowBrowserRoleHeaders()) return String(req.headers['x-admin-role'] || 'viewer')");
    expect(alerting).toContain("if (allowBrowserRoleHeaders()) return String(req?.headers?.['x-admin-role'] || 'local_admin')");
    expect(registry).toContain("allowBrowserRoleHeaders() ? req.headers?.['x-admin-role'] : ''");
  });

  it('gates the local demo tenant fallback outside production', () => {
    const html = readSource('src/dashboard/combined.html');
    const plugin = readSource('src/dashboard/plugin.ts');

    expect(html).toContain("const ALLOW_LOCAL_TENANT_FALLBACK=isLocalDevDashboard()");
    expect(html).toContain("return ALLOW_LOCAL_TENANT_FALLBACK?LOCAL_DEV_TENANT_ID:''");
    expect(plugin).toContain("'__ALLOW_LOCAL_TENANT_FALLBACK__'");
    expect(plugin).toContain("process.env.NODE_ENV === 'production' ? 'false' : 'true'");
  });

  it('keeps admin revenue pricing backend-configured instead of browser hardcoded', () => {
    const admin = readSource('src/admin/admin.ts');
    const dashboard = readSource('src/dashboard/combined.html');
    const standaloneAdmin = readSource('src/admin/admin.html');

    expect(admin).toContain('function configuredPlanPrices()');
    expect(admin).toContain("PRICE_STARTER_USD");
    expect(admin).toContain('pricingSource');
    expect(admin).not.toContain("SUM(CASE WHEN plan='starter' THEN 49");
    expect(dashboard).toContain('window.ADMIN_PLAN_PRICES=stats.planPrices');
    expect(dashboard).toContain("pricing_source==='defaults'");
    expect(standaloneAdmin).toContain('window.ADMIN_PLAN_PRICES=stats.planPrices');
    expect(standaloneAdmin).toContain("pricing_source==='defaults'");
  });

  it('warns production admins when local demo tenant data is still present', () => {
    const admin = readSource('src/admin/admin.ts');
    expect(admin).toContain('LOCAL_DEMO_TENANT_ID');
    expect(admin).toContain('local_demo_tenant_absent');
    expect(admin).toContain("process.env.NODE_ENV !== 'production'");
  });

  it('tenant HITL decisions do not trust browser role headers in production', () => {
    const hitl = readSource('src/hitl/approval.ts');
    expect(hitl).toContain('function allowBrowserRoleHeaders()');
    expect(hitl).toContain("process.env.NODE_ENV !== 'production'");
    expect(hitl).toContain('canDecideTenantApproval');
    expect(hitl).toContain('Approval belongs to a different tenant');
    expect(hitl).not.toContain("req?.headers?.['x-admin-role'] || req?.user?.role || 'local_admin'");
    expect(hitl).not.toContain("req.headers['x-admin-role'] || req.user?.role || 'local_admin'");
  });

  it('Shadow MCP review does not auto-grant wildcard tool access', () => {
    const shadow = readSource('src/shadow/discovery.ts');
    const dashboard = readSource('src/dashboard/combined.html');

    expect(shadow).toContain("fastify.get('/api/shadow/summary'");
    expect(shadow).toContain("policyCreated: false");
    expect(shadow).toContain('wildcard access is not auto-granted');
    expect(shadow).not.toContain("ARRAY['*']");
    expect(dashboard).toContain('This does not grant tool access');
  });

  it('keeps dashboard read routes reachable for anomaly and HITL panels', () => {
    const hitl = readSource('src/hitl/approval.ts');
    const anomaly = readSource('src/anomaly/ml-engine.ts');

    expect(hitl).toContain("fastify.get('/api/hitl/requests'");
    expect(hitl.indexOf("fastify.get('/api/hitl/requests'")).toBeLessThan(
      hitl.indexOf("fastify.get('/api/hitl/:approvalId'")
    );
    expect(anomaly).toContain("fastify.get('/api/anomaly/events'");
  });
});

const runLive = process.env.RUN_LIVE_E2E === 'true';
const liveDescribe = runLive ? describe : describe.skip;

liveDescribe('live local enterprise E2E', () => {
  jest.setTimeout(30000);

  it('serves user and admin entry points', async () => {
    const dashboard = await request('/dashboard');
    const admin = await request('/admin');
    expect(dashboard.res.status).toBe(200);
    expect(admin.res.status).toBe(200);
  });

  it('serves tenant-scoped dashboard APIs', async () => {
    for (const endpoint of ['/api/connect/status', '/api/agents', '/api/alerts', '/api/alerts/channels', '/api/enterprise/readiness', '/api/anomaly/events?limit=5', '/api/hitl/requests?limit=5']) {
      const { res } = await request(endpoint, { headers: tenantHeaders() });
      expect(res.status).toBe(200);
    }
  });

  it('blocks non-admin tenant mutations and allows admin-created agent token lifecycle', async () => {
    const agentId = `agent_e2e_${Date.now()}`;
    const viewer = await request('/api/agents', {
      method: 'POST',
      headers: tenantHeaders('viewer'),
      body: JSON.stringify({ agentId, description: 'E2E blocked viewer attempt' }),
    });
    expect(viewer.res.status).toBe(403);

    const created = await request('/api/agents', {
      method: 'POST',
      headers: tenantHeaders(),
      body: JSON.stringify({ agentId, description: 'E2E temporary agent' }),
    });
    expect(created.res.status).toBe(201);
    expect(created.body.token).toMatch(/^mcpsg_/);
    expect(created.body.agent.agentId).toBe(agentId);

    const revoked = await request(`/api/agents/${encodeURIComponent(agentId)}`, {
      method: 'DELETE',
      headers: tenantHeaders(),
    });
    expect([200, 204]).toContain(revoked.res.status);
  });

  it('blocks non-admin alert channel mutation and supports admin channel lifecycle', async () => {
    const name = `E2E webhook ${Date.now()}`;
    const payload = {
      type: 'webhook',
      name,
      ownerEmail: 'security@example.com',
      scope: 'e2e',
      active: false,
      config: { url: 'http://127.0.0.1:9/e2e', name },
    };

    const viewer = await request('/api/alerts/channels', {
      method: 'POST',
      headers: tenantHeaders('viewer'),
      body: JSON.stringify(payload),
    });
    expect(viewer.res.status).toBe(403);

    const created = await request('/api/alerts/channels', {
      method: 'POST',
      headers: tenantHeaders(),
      body: JSON.stringify(payload),
    });
    expect([200, 201]).toContain(created.res.status);
    const id = created.body.channel?.id || created.body.id;
    expect(id).toBeTruthy();

    const removed = await request(`/api/alerts/channels/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: tenantHeaders(),
    });
    expect([200, 204]).toContain(removed.res.status);
  });

  it('protects admin APIs with the admin secret', async () => {
    const blocked = await request('/admin/stats');
    expect(blocked.res.status).toBe(401);

    const secret = envValue('ADMIN_SECRET');
    expect(secret).toBeTruthy();
    const allowed = await request('/admin/stats', {
      headers: { 'X-Admin-Secret': secret },
    });
    expect(allowed.res.status).toBe(200);
    expect(allowed.body).toHaveProperty('tenants');
  });
});
