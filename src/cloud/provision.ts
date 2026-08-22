/**
 * Managed Cloud Tier — $29/month
 *
 * One-click provisioned gateway. Customer signs up, gets:
 *   https://{slug}.mcpsecurity.dev  — their dedicated gateway URL
 *   Managed Postgres (isolated schema per tenant)
 *   Managed Redis namespace (key-prefixed per tenant)
 *   Auto-migrations on deploy
 *   Auto-SSL via Let's Encrypt / Cloudflare
 *   Zero DevOps — no Docker, no DB setup, no Redis config
 *
 * Architecture:
 *   - Shared Postgres with row-level tenant isolation (existing pattern)
 *   - Shared Redis with tenant-prefixed keys (existing pattern)
 *   - Nginx/Caddy routing slug.mcpsecurity.dev → main gateway + X-Tenant-ID header
 *   - Stripe subscription creates cloud tenant on webhook
 *
 * This module handles:
 *   1. Cloud tenant provisioning (POST /api/cloud/provision)
 *   2. Subdomain slug generation + uniqueness
 *   3. Onboarding flow (credentials page after signup)
 *   4. Cloud tenant status + health
 *   5. Upgrade path from cloud → self-hosted
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';

export interface CloudTenant {
  tenantId: string;
  name: string;
  slug: string;           // e.g. "acme-corp"
  gatewayUrl: string;     // https://acme-corp.mcpsecurity.dev
  plan: 'cloud';
  apiKey: string;         // first agent's bearer token
  agentId: string;
  billingEmail: string;
  provisionedAt: Date;
  status: 'active' | 'suspended' | 'deprovisioning';
}

// ── Slug generation ────────────────────────────────────────────────────

function generateSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32) + '-' + crypto.randomBytes(3).toString('hex');
}

async function ensureUniqueSlug(base: string, db: Pool): Promise<string> {
  let slug = base;
  let attempts = 0;
  while (attempts < 10) {
    const r = await db.query(`SELECT id FROM tenants WHERE cloud_subdomain=$1`, [slug]);
    if (!r.rows.length) return slug;
    slug = base.slice(0, 28) + '-' + crypto.randomBytes(3).toString('hex');
    attempts++;
  }
  return crypto.randomBytes(8).toString('hex');
}

// ── Cloud provisioning ─────────────────────────────────────────────────

export async function provisionCloudTenant(
  name: string,
  billingEmail: string,
  db: Pool
): Promise<CloudTenant> {
  const tenantId = crypto.randomUUID();
  const slug = await ensureUniqueSlug(generateSlug(name), db);
  const gatewayUrl = `https://${slug}.${process.env.CLOUD_DOMAIN || 'mcpsecurity.dev'}`;

  // Generate first agent credentials
  const agentId = `agent_${crypto.randomBytes(8).toString('hex')}`;
  const apiKey = 'mcpsg_' + crypto.randomBytes(32).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

  // Create tenant
  await db.query('BEGIN');
  try {
    await db.query(
      `INSERT INTO tenants
         (id, name, plan, billing_email, api_key_hash, api_calls_limit, agents_limit,
          deployment_type, cloud_subdomain, cloud_provisioned_at)
       VALUES ($1,$2,'cloud',$3,$4,5000,3,'managed_cloud',$5,NOW())`,
      [tenantId, name, billingEmail, apiKeyHash, slug]
    );

    // Create first agent token
    await db.query(
      `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description)
       VALUES ($1,$2,$3,'Default agent — created on provisioning')`,
      [agentId, tenantId, crypto.createHash('sha256').update(apiKey).digest('hex')]
    );

    // Create default policy (allow read-only tools)
    await db.query(
      `INSERT INTO policies (agent_id, tenant_id, allowed_tools, active)
       VALUES ($1,$2,ARRAY['read_file','query_database','web_search','http_request'],true)`,
      [agentId, tenantId]
    );

    // Run default alert rules
    const defaults = [
      { name: 'High denial rate', eventType: 'denial_rate_spike', threshold: 20, windowSeconds: 300, severity: 'high', channels: ['slack'], cooldown: 600 },
      { name: 'Injection attempt', eventType: 'injection_detected', threshold: 1, windowSeconds: 60, severity: 'critical', channels: ['slack'], cooldown: 60 },
    ];
    for (const r of defaults) {
      await db.query(
        `INSERT INTO alert_rules (tenant_id, name, event_type, threshold, window_seconds, severity, channels, cooldown_seconds)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
        [tenantId, r.name, r.eventType, r.threshold, r.windowSeconds, r.severity, JSON.stringify(r.channels), r.cooldown]
      );
    }

    await db.query('COMMIT');
  } catch (e) {
    await db.query('ROLLBACK');
    throw e;
  }

  return {
    tenantId, name, slug, gatewayUrl,
    plan: 'cloud', apiKey, agentId, billingEmail,
    provisionedAt: new Date(), status: 'active',
  };
}

// ── Cloud management plugin ────────────────────────────────────────────

export async function cloudPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db } = opts;

  // ── Self-serve signup (called from landing page) ───────────────────
  fastify.post('/api/cloud/provision', async (req: any, reply: any) => {
    const { name, billingEmail, stripeSessionId } = req.body || {};
    if (!name || !billingEmail) {
      return reply.code(400).send({ error: 'name and billingEmail required' });
    }

    // In production: verify stripeSessionId is paid before provisioning
    // For now: provision and handle billing async via webhook

    try {
      const tenant = await provisionCloudTenant(name, billingEmail, db);
      return {
        success: true,
        tenant: {
          gatewayUrl: tenant.gatewayUrl,
          agentId: tenant.agentId,
          apiKey: tenant.apiKey,
          tenantId: tenant.tenantId,
          slug: tenant.slug,
          dashboardUrl: `${tenant.gatewayUrl}/dashboard`,
          message: 'Your gateway is ready. Store your API key — it will not be shown again.',
        },
      };
    } catch (err: any) {
      fastify.log.error({ err }, 'Cloud provisioning failed');
      return reply.code(500).send({ error: 'Provisioning failed', details: err.message });
    }
  });

  // ── Get cloud tenant status ────────────────────────────────────────
  fastify.get('/api/cloud/status', async (req: any) => {
    const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
    const r = await db.query(
      `SELECT t.id, t.name, t.cloud_subdomain, t.cloud_provisioned_at,
              t.api_calls_limit, t.subscription_status, t.deployment_type, t.plan,
              COALESCE(um.api_calls, 0) as api_calls_this_month
       FROM tenants t
       LEFT JOIN usage_metrics um ON um.tenant_id=t.id AND um.month=TO_CHAR(NOW(),'YYYY-MM')
       WHERE t.id=$1`,
      [tenantId]
    );
    if (!r.rows.length) return { status: 'not_found' };
    const t = r.rows[0];
    const isManagedCloud = Boolean(t.cloud_subdomain);
    return {
      status: isManagedCloud ? 'active' : 'not_managed_cloud',
      deploymentType: t.deployment_type || 'self_hosted',
      gatewayUrl: isManagedCloud
        ? `https://${t.cloud_subdomain}.${process.env.CLOUD_DOMAIN || 'mcpsecurity.dev'}`
        : `${req.protocol || 'http'}://${req.headers.host || 'localhost:3000'}/mcp`,
      slug: t.cloud_subdomain || null,
      provisionedAt: t.cloud_provisioned_at,
      plan: isManagedCloud ? 'cloud' : t.plan,
      apiCallsUsed: parseInt(t.api_calls_this_month, 10),
      apiCallsLimit: parseInt(t.api_calls_limit, 10),
      usagePercent: Math.round((t.api_calls_this_month / t.api_calls_limit) * 100),
      subscriptionStatus: t.subscription_status,
      productionReadiness: {
        cloudDomainConfigured: Boolean(process.env.CLOUD_DOMAIN),
        stripeConfigured: Boolean(process.env.STRIPE_SECRET_KEY),
        emailConfigured: Boolean(process.env.RESEND_API_KEY || process.env.SMTP_HOST),
        managedCloud: isManagedCloud,
      },
    };
  });

  // ── List all cloud tenants (admin only) ────────────────────────────
  fastify.get('/admin/cloud/tenants', async (req: any, reply: any) => {
    const secret = req.headers['x-admin-secret'];
    if (!secret || secret !== process.env.ADMIN_SECRET) {
      return reply.code(403).send({ error: 'Forbidden' });
    }
    const r = await db.query(`
      SELECT id, name, billing_email, cloud_subdomain, cloud_provisioned_at,
             subscription_status, api_calls_limit
      FROM tenants WHERE deployment_type='managed_cloud'
      ORDER BY cloud_provisioned_at DESC`
    );
    return { cloudTenants: r.rows, total: r.rowCount };
  });

  // ── Upgrade from cloud → self-hosted (export config) ──────────────
  fastify.get('/api/cloud/export-config', async (req: any) => {
    const [policies, agents, alertRules] = await Promise.all([
      db.query(`SELECT * FROM policies WHERE tenant_id=$1 AND active=true`, [req.tenant.id]),
      db.query(`SELECT agent_id, description FROM agent_tokens WHERE tenant_id=$1 AND active=true`, [req.tenant.id]),
      db.query(`SELECT * FROM alert_rules WHERE tenant_id=$1 AND active=true`, [req.tenant.id]),
    ]);

    // Generate .env for self-hosted
    const envContent = `# MCP Security Gateway — Exported from Cloud Tier
NODE_ENV=production
DATABASE_URL=postgresql://user:pass@your-db:5432/mcp_security
REDIS_URL=redis://your-redis:6379
JWT_SECRET=${crypto.randomBytes(32).toString('hex')}
FAIL_MODE=fail_closed
ENABLE_DASHBOARD=true
ADMIN_SECRET=${crypto.randomBytes(16).toString('hex')}
MCP_SERVER_URL=http://your-mcp-server:8080
PORT=3000
`;

    return {
      config: {
        policies: policies.rows,
        agents: agents.rows,
        alertRules: alertRules.rows,
      },
      envTemplate: envContent,
      instructions: [
        '1. Download and install MCP Security Gateway: git clone https://github.com/Ajimsha1080/mcpsecurity',
        '2. Copy the .env template and fill in your DB + Redis URLs',
        '3. Run: npm install && npm run db:migrate && npm start',
        '4. Import your config via the admin API or run the seed script',
        '5. Update your agent SDK configs to point at your new self-hosted URL',
      ],
    };
  });

  // ── Public onboarding page (served at /cloud/start) ───────────────
  fastify.get('/cloud/start', async (req: any, reply: any) => {
    const html = ONBOARDING_HTML;
    reply.type('text/html').send(html);
  });

  // ── Onboarding completion page (after Stripe checkout) ────────────
  fastify.get('/cloud/welcome', async (req: any, reply: any) => {
    const { name, email } = req.query as any;
    if (!name || !email) return reply.redirect('/cloud/start');
    try {
      const tenant = await provisionCloudTenant(decodeURIComponent(name), decodeURIComponent(email), db);
      reply.type('text/html').send(buildWelcomePage(tenant));
    } catch (err: any) {
      reply.type('text/html').send(`<html><body><h1>Provisioning failed</h1><p>${err.message}</p></body></html>`);
    }
  });
}

// ── Onboarding HTML (public signup page) ──────────────────────────────

const ONBOARDING_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Gateway — Start Free</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#060809;color:#e8f0f7;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#0b0f12;border:1px solid #1e262d;border-radius:16px;padding:40px;max-width:440px;width:100%}
h1{font-size:24px;font-weight:700;margin-bottom:6px;color:#fff}
.sub{font-size:14px;color:#7a9ab0;margin-bottom:32px;line-height:1.5}
.features{display:grid;gap:10px;margin-bottom:28px}
.feat{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:#7a9ab0}
.feat-dot{width:6px;height:6px;border-radius:50%;background:#00e5a0;flex-shrink:0;margin-top:5px}
label{display:block;font-size:12px;color:#7a9ab0;margin-bottom:5px;font-weight:500}
input{width:100%;padding:10px 14px;background:#111619;border:1px solid #1e262d;border-radius:8px;color:#e8f0f7;font-size:14px;margin-bottom:14px}
input:focus{outline:none;border-color:rgba(0,229,160,.4)}
button{width:100%;padding:12px;background:rgba(0,229,160,.1);border:1px solid rgba(0,229,160,.3);border-radius:8px;color:#00e5a0;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s}
button:hover{background:rgba(0,229,160,.18)}
.price{text-align:center;font-size:13px;color:#3a5060;margin-top:16px}
.price strong{color:#7a9ab0}
</style>
</head>
<body>
<div class="card">
  <h1>Secure your AI agents in 2 minutes</h1>
  <p class="sub">Get a dedicated MCP Security Gateway — no Docker, no DevOps, no setup. Just a URL your agents connect to.</p>
  <div class="features">
    <div class="feat"><div class="feat-dot"></div><div>10-layer zero-trust security pipeline active instantly</div></div>
    <div class="feat"><div class="feat-dot"></div><div>your-name.mcpsecurity.dev gateway URL ready in seconds</div></div>
    <div class="feat"><div class="feat-dot"></div><div>Works with LangChain, CrewAI, AutoGen, or direct HTTP</div></div>
    <div class="feat"><div class="feat-dot"></div><div>PII masking, anomaly detection, full audit log included</div></div>
  </div>
  <form onsubmit="signup(event)">
    <label>Your name or company</label>
    <input type="text" id="name" placeholder="Acme AI" required>
    <label>Work email</label>
    <input type="email" id="email" placeholder="you@company.com" required>
    <button type="submit" id="btn">Start free — get your gateway URL</button>
  </form>
  <div class="price">$29/month after 14-day trial · <strong>No card required to start</strong></div>
</div>
<script>
async function signup(e){
  e.preventDefault();
  const btn=document.getElementById('btn');
  btn.textContent='Setting up your gateway…';btn.disabled=true;
  const name=document.getElementById('name').value;
  const email=document.getElementById('email').value;
  window.location='/cloud/welcome?name='+encodeURIComponent(name)+'&email='+encodeURIComponent(email);
}
</script>
</html>`;

function buildWelcomePage(tenant: CloudTenant): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Your gateway is ready — MCP Security</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#060809;color:#e8f0f7;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#0b0f12;border:1px solid #1e262d;border-radius:16px;padding:40px;max-width:560px;width:100%}
h1{font-size:22px;font-weight:700;margin-bottom:6px;color:#00e5a0}
.sub{font-size:14px;color:#7a9ab0;margin-bottom:28px}
.cred{background:#111619;border:1px solid #1e262d;border-radius:8px;padding:14px;margin-bottom:12px}
.cred-label{font-size:11px;color:#3a5060;font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.cred-value{font-family:'IBM Plex Mono',monospace;font-size:13px;color:#00e5a0;word-break:break-all}
.steps{margin-top:24px}
.step{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #1e262d;font-size:13px;align-items:flex-start}
.step:last-child{border-bottom:none}
.step-n{width:22px;height:22px;border-radius:50%;background:rgba(0,229,160,.1);border:1px solid rgba(0,229,160,.2);color:#00e5a0;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
.code{background:#060809;border-radius:6px;padding:8px 12px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#7a9ab0;margin-top:8px;white-space:pre-wrap;word-break:break-all}
.warn{background:rgba(255,184,48,.07);border:1px solid rgba(255,184,48,.2);border-radius:8px;padding:12px;font-size:12px;color:#ffb830;margin:16px 0}
a.btn{display:block;text-align:center;padding:12px;background:rgba(0,229,160,.1);border:1px solid rgba(0,229,160,.3);border-radius:8px;color:#00e5a0;font-size:14px;font-weight:600;text-decoration:none;margin-top:20px}
</style>
</head>
<body>
<div class="card">
  <h1>Your gateway is live</h1>
  <p class="sub">Everything is configured. Connect your agents in the next 5 minutes.</p>

  <div class="warn">Save your API key now — it will not be shown again after you close this page.</div>

  <div class="cred">
    <div class="cred-label">Gateway URL</div>
    <div class="cred-value">${tenant.gatewayUrl}</div>
  </div>
  <div class="cred">
    <div class="cred-label">Agent ID</div>
    <div class="cred-value">${tenant.agentId}</div>
  </div>
  <div class="cred">
    <div class="cred-label">API Key (bearer token) — save this now</div>
    <div class="cred-value">${tenant.apiKey}</div>
  </div>

  <div class="steps">
    <div class="step"><div class="step-n">1</div>
    <div><strong>Python (LangChain / CrewAI / AutoGen)</strong>
    <div class="code">pip install mcpsecurity
from mcpsecurity import McpGatewayClient
async with McpGatewayClient(
  gateway_url="${tenant.gatewayUrl}",
  token="${tenant.apiKey}",
) as client:
  result = await client.query_database("SELECT 1")</div></div></div>

    <div class="step"><div class="step-n">2</div>
    <div><strong>TypeScript / Node.js</strong>
    <div class="code">npm install @mcp-security/sdk
import { McpGatewayClient } from '@mcp-security/sdk';
const client = new McpGatewayClient({
  gatewayUrl: '${tenant.gatewayUrl}',
  token: '${tenant.apiKey}',
});</div></div></div>

    <div class="step"><div class="step-n">3</div>
    <div><strong>Direct HTTP (any language)</strong>
    <div class="code">curl -X POST ${tenant.gatewayUrl}/mcp \\
  -H "Authorization: Bearer ${tenant.apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"test.txt"}}}'</div></div></div>
  </div>

  <a class="btn" href="${tenant.gatewayUrl}/dashboard">Open your dashboard →</a>
</div>
</body>
</html>`;
}
