/**
 * tenant/trial.ts — Trial expiry enforcement
 * FIX: trial_ends_at was stored but never checked. Trials ran indefinitely.
 */
import { Pool } from 'pg';

export async function enforceTrialExpiry(db: Pool): Promise<void> {
  // Find tenants whose trials have expired and are still active
  const expired = await db.query(`
    SELECT id, name, billing_email FROM tenants
    WHERE trial_ends_at < NOW()
      AND subscription_status = 'trialing'
      AND active = true
  `);

  for (const tenant of expired.rows) {
    // Suspend tenant
    await db.query(`
      UPDATE tenants SET active=false, subscription_status='trial_expired',
        suspension_reason='Trial period ended'
      WHERE id=$1
    `, [tenant.id]);

    // Send trial expired email
    await db.query(`
      INSERT INTO email_queue (to_email, template, payload, created_at)
      VALUES ($1, 'trial_expired', $2, NOW())
    `, [tenant.billing_email, JSON.stringify({ tenantName: tenant.name, upgradeUrl: process.env.APP_URL + '/billing' })]);
  }

  if (expired.rows.length > 0) {
    console.log(`Trial expiry: suspended ${expired.rows.length} tenants`);
  }
}

// Send 3-day and 1-day warning before expiry
export async function sendTrialWarnings(db: Pool): Promise<void> {
  const warn3 = await db.query(`
    SELECT id, name, billing_email FROM tenants
    WHERE trial_ends_at BETWEEN NOW() + INTERVAL '2 days' AND NOW() + INTERVAL '3 days'
      AND subscription_status = 'trialing' AND active=true
  `);
  for (const t of warn3.rows) {
    await db.query(
      `INSERT INTO email_queue (to_email, template, payload) VALUES ($1,'trial_warning_3d',$2)`,
      [t.billing_email, JSON.stringify({ tenantName: t.name, daysLeft: 3 })]
    );
  }
}
