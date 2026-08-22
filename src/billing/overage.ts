/**
 * billing/overage.ts — Overage billing processing
 * FIX: overages were tracked in DB but never invoiced via Stripe.
 */
import { Pool } from 'pg';

const OVERAGE_RATE_USD = 0.005; // $0.005 per call over limit

export async function processOverageBilling(db: Pool): Promise<void> {
  const lastMonth = new Date();
  lastMonth.setMonth(lastMonth.getMonth() - 1);
  const month = lastMonth.toISOString().slice(0, 7);

  const overages = await db.query(`
    SELECT uo.tenant_id, uo.overage_calls, t.stripe_customer_id, t.billing_email, t.name
    FROM usage_overage uo
    JOIN tenants t ON t.id = uo.tenant_id
    WHERE uo.month = $1 AND uo.overage_calls > 0
      AND NOT EXISTS (
        SELECT 1 FROM billing_invoices bi
        WHERE bi.tenant_id=uo.tenant_id AND bi.stripe_invoice_id LIKE 'overage_%' || uo.month
      )
  `, [month]);

  if (!overages.rows.length) return;

  let stripe: any;
  try { stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); } catch { return; }

  for (const ov of overages.rows) {
    const amountUsd = parseFloat((ov.overage_calls * OVERAGE_RATE_USD).toFixed(2));
    if (amountUsd < 0.50) continue; // Stripe minimum $0.50

    try {
      const invoice = await stripe.invoices.create({
        customer: ov.stripe_customer_id,
        description: `Overage billing: ${ov.overage_calls.toLocaleString()} extra calls in ${month}`,
        metadata: { type: 'overage', month, tenantId: ov.tenant_id },
      });

      await stripe.invoiceItems.create({
        customer: ov.stripe_customer_id,
        invoice: invoice.id,
        amount: Math.round(amountUsd * 100),
        currency: 'usd',
        description: `${ov.overage_calls.toLocaleString()} overage calls × $0.005`,
      });

      await stripe.invoices.finalizeInvoice(invoice.id);
      await stripe.invoices.pay(invoice.id);

      await db.query(
        `INSERT INTO billing_invoices (tenant_id, stripe_invoice_id, amount_usd, status, paid_at)
         VALUES ($1,$2,$3,'paid',NOW())`,
        [ov.tenant_id, `overage_${month}_${invoice.id}`, amountUsd]
      );

      console.log(`Overage billed: tenant=${ov.tenant_id} amount=$${amountUsd} month=${month}`);
    } catch (e) {
      console.error(`Overage billing failed for tenant ${ov.tenant_id}:`, e);
    }
  }
}
