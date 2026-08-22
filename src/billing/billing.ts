/**
 * Billing Integration — Stripe (global) + Dodo Payments (India UPI/cards)
 * Handles subscriptions, overage billing, invoices, and webhooks.
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import { ensurePlanLimitSchema, getPlanLimits, getPlanUsage } from './plan-limits';

const PLAN_PRICES: Record<string, { stripePriceId: string; monthlyUsd: number }> = {
  starter:    { stripePriceId: process.env.STRIPE_PRICE_STARTER    || '', monthlyUsd: 49  },
  growth:     { stripePriceId: process.env.STRIPE_PRICE_GROWTH     || '', monthlyUsd: 199 },
  enterprise: { stripePriceId: process.env.STRIPE_PRICE_ENTERPRISE || '', monthlyUsd: 999 },
};

function tenantIdFrom(req: any): string | undefined {
  return req.tenant?.id || req.headers['x-tenant-id'];
}

function appUrl(req?: any): string {
  const configured = process.env.APP_URL;
  if (configured) return configured.replace(/\/$/, '');
  const proto = req?.headers?.['x-forwarded-proto'] || 'http';
  const host = req?.headers?.host || 'localhost:3000';
  return `${proto}://${host}`;
}

function missingStripeConfig(plan?: string): string[] {
  const missing: string[] = [];
  if (!process.env.STRIPE_SECRET_KEY) missing.push('STRIPE_SECRET_KEY');
  if (!process.env.STRIPE_WEBHOOK_SECRET) missing.push('STRIPE_WEBHOOK_SECRET');
  if (plan && !PLAN_PRICES[plan]?.stripePriceId) missing.push(`STRIPE_PRICE_${plan.toUpperCase()}`);
  return missing;
}

function billingNotConfiguredPayload(plan?: string) {
  const missing = missingStripeConfig(plan);
  return {
    error: 'Billing provider not configured',
    code: 'BILLING_PROVIDER_NOT_CONFIGURED',
    missing,
    message: `Configure ${missing.join(', ')} to enable real Stripe checkout and customer portal.`,
  };
}

export async function billingPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
) {
  const { db } = opts;
  await ensurePlanLimitSchema(db);

  // ── Create checkout session ────────────────────────────────────────

  fastify.post('/api/billing/checkout', async (req: any, reply) => {
    const { plan, successUrl, cancelUrl } = req.body || {};
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });

    const planConfig = PLAN_PRICES[plan];
    if (!planConfig) return reply.code(400).send({ error: 'Invalid plan' });
    const missing = missingStripeConfig(plan);
    if (missing.length) return reply.code(501).send(billingNotConfiguredPayload(plan));

    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      const tenant = await db.query(`SELECT billing_email, stripe_customer_id FROM tenants WHERE id=$1`, [tenantId]);
      if (!tenant.rows[0]) return reply.code(404).send({ error: 'Tenant not found' });

      let customerId = tenant.rows[0]?.stripe_customer_id;

      if (!customerId) {
        const customer = await stripe.customers.create({
          email: tenant.rows[0]?.billing_email,
          metadata: { tenantId },
        });
        customerId = customer.id;
        await db.query(`UPDATE tenants SET stripe_customer_id=$1 WHERE id=$2`, [customerId, tenantId]);
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        payment_method_types: ['card'],
        line_items: [{ price: planConfig.stripePriceId, quantity: 1 }],
        mode: 'subscription',
        success_url: successUrl || `${appUrl(req)}/dashboard`,
        cancel_url: cancelUrl || `${appUrl(req)}/dashboard`,
        metadata: { tenantId, plan },
        subscription_data: { metadata: { tenantId, plan } },
      });

      return { checkoutUrl: session.url, sessionId: session.id };
    } catch (err: any) {
      fastify.log.error(err, 'Stripe checkout failed');
      return reply.code(502).send({ error: 'Billing system error', message: err?.message || 'Stripe checkout failed' });
    }
  });

  // ── Stripe webhook handler ─────────────────────────────────────────

  fastify.post('/api/billing/webhook', {
    config: { rawBody: true },
  }, async (req: any, reply) => {
    const sig = req.headers['stripe-signature'];
    let event: any;

    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err: any) {
      return reply.code(400).send({ error: `Webhook Error: ${err.message}` });
    }

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { tenantId, plan } = session.metadata;
        await db.query(
          `UPDATE tenants SET plan=$1, stripe_subscription_id=$2, subscription_status='active' WHERE id=$3`,
          [plan, session.subscription, tenantId]
        );
        fastify.log.info({ tenantId, plan }, 'Subscription activated');
        break;
      }

      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        const sub = await require('stripe')(process.env.STRIPE_SECRET_KEY).subscriptions.retrieve(invoice.subscription);
        const tenantId = sub.metadata.tenantId;
        await db.query(
          `INSERT INTO billing_invoices (tenant_id, stripe_invoice_id, amount_usd, status, paid_at)
           VALUES ($1,$2,$3,'paid',NOW()) ON CONFLICT (stripe_invoice_id) DO UPDATE SET status='paid', paid_at=NOW()`,
          [tenantId, invoice.id, invoice.amount_paid / 100]
        );
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const sub = await require('stripe')(process.env.STRIPE_SECRET_KEY).subscriptions.retrieve(invoice.subscription);
        const tenantId = sub.metadata.tenantId;
        await db.query(`UPDATE tenants SET subscription_status='past_due' WHERE id=$1`, [tenantId]);
        fastify.log.warn({ tenantId }, 'Payment failed — tenant marked past_due');
        break;
      }

      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const tenantId = sub.metadata.tenantId;
        await db.query(
          `UPDATE tenants SET subscription_status='cancelled', plan='starter',
           api_calls_limit=10000, agents_limit=5 WHERE id=$1`,
          [tenantId]
        );
        break;
      }
    }

    return { received: true };
  });

  // ── Get billing status ─────────────────────────────────────────────

  fastify.get('/api/billing/status', async (req: any, reply) => {
    const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const r = await db.query(
      `SELECT plan, subscription_status, stripe_customer_id,
              api_calls_limit, agents_limit
       FROM tenants WHERE id=$1`,
      [tenantId]
    );
    if (!r.rows[0]) return reply.code(404).send({ error: 'Tenant not found' });

    const usage = await db.query(
      `SELECT api_calls FROM usage_metrics
       WHERE tenant_id=$1 AND month=TO_CHAR(NOW(),'YYYY-MM')`,
      [tenantId]
    );

    const invoices = await db.query(
      `SELECT * FROM billing_invoices WHERE tenant_id=$1 ORDER BY paid_at DESC LIMIT 12`,
      [tenantId]
    );

    const [{ plan, limits }, planUsage, blocked] = await Promise.all([
      getPlanLimits(db, tenantId),
      getPlanUsage(db, tenantId),
      db.query(
        `SELECT feature_key, action, message, used, limit_value, actor_email, created_at
         FROM plan_limit_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 10`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
    ]);

    return {
      ...r.rows[0],
      plan,
      featureLimits: limits,
      featureUsage: planUsage,
      blockedActions: blocked.rows,
      apiCallsThisMonth: parseInt(usage.rows[0]?.api_calls || '0', 10),
      invoices: invoices.rows,
      billingProvider: {
        stripeConfigured: missingStripeConfig().length === 0,
        webhookConfigured: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
        customerPortalAvailable: Boolean(process.env.STRIPE_SECRET_KEY && r.rows[0].stripe_customer_id),
        stripeCustomerLinked: Boolean(r.rows[0].stripe_customer_id),
        missingConfig: missingStripeConfig(),
        checkoutPriceIds: Object.fromEntries(Object.entries(PLAN_PRICES).map(([key, value]) => [key, Boolean(value.stripePriceId)])),
      },
    };
  });

  fastify.get('/api/billing/limits', async (req: any, reply) => {
    const tenantId = req.tenant?.id || req.headers['x-tenant-id'];
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const [{ plan, limits }, usage, blocked] = await Promise.all([
      getPlanLimits(db, tenantId),
      getPlanUsage(db, tenantId),
      db.query(
        `SELECT feature_key, action, message, used, limit_value, actor_email, created_at
         FROM plan_limit_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
    ]);
    return { plan, limits, usage, blockedActions: blocked.rows };
  });

  // ── Customer portal (manage subscription) ─────────────────────────

  fastify.post('/api/billing/portal', async (req: any, reply) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    if (!process.env.STRIPE_SECRET_KEY) return reply.code(501).send(billingNotConfiguredPayload());
    const r = await db.query(`SELECT stripe_customer_id FROM tenants WHERE id=$1`, [tenantId]);
    if (!r.rows[0]) return reply.code(404).send({ error: 'Tenant not found' });
    if (!r.rows[0]?.stripe_customer_id) {
      return reply.code(400).send({
        error: 'No Stripe customer linked',
        code: 'NO_STRIPE_CUSTOMER',
        message: 'Create a checkout session first, or link this tenant to a Stripe customer in Admin.',
      });
    }

    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.billingPortal.sessions.create({
      customer: r.rows[0].stripe_customer_id,
      return_url: `${appUrl(req)}/dashboard`,
    });
    return { portalUrl: session.url };
  });
}
