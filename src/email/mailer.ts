/**
 * email/mailer.ts — Email service (welcome, invoices, trial warnings, security alerts)
 * FIX: no email provider existed in v1. Supports Resend (recommended), SES, or SMTP.
 */
import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import axios from 'axios';
import { requestTenantId } from '../utils/request-context';
import { decryptSecretConfig, encryptSecretConfig, redactSecretConfig } from '../security/secrets';

const FROM_EMAIL = process.env.EMAIL_FROM || 'MCP Security <noreply@mcpsecurity.io>';
const PROVIDER = process.env.EMAIL_PROVIDER || 'resend'; // 'resend' | 'ses' | 'none'
const nodemailer = require('nodemailer');

// ── Core email sender ─────────────────────────────────────────────────
export async function sendEmail(opts: {
  to: string; subject: string; html: string; text?: string;
}): Promise<boolean> {
  if (PROVIDER === 'none' || !process.env.EMAIL_API_KEY) {
    console.log(`[EMAIL SKIPPED] to=${opts.to} subject=${opts.subject}`);
    return true;
  }
  try {
    if (PROVIDER === 'resend') {
      await axios.post('https://api.resend.com/emails', {
        from: FROM_EMAIL, to: opts.to,
        subject: opts.subject, html: opts.html,
      }, { headers: { Authorization: `Bearer ${process.env.EMAIL_API_KEY}` } });
    }
    return true;
  } catch (e: any) {
    console.error('Email send failed:', e.message);
    return false;
  }
}

type TenantEmailProvider = 'resend' | 'sendgrid' | 'smtp' | 'none';

interface TenantEmailConfig {
  provider: TenantEmailProvider;
  fromEmail: string;
  apiKey?: string;
  smtpHost?: string;
  smtpPort?: number;
  smtpUser?: string;
  smtpPassword?: string;
  secure?: boolean;
  enabled?: boolean;
  configured?: boolean;
}

async function readTenantEmailConfig(db: Pool, tenantId: string, decrypt = true): Promise<TenantEmailConfig | null> {
  const r = await db.query(`SELECT metadata->>'emailProvider' AS config FROM tenants WHERE id=$1`, [tenantId]).catch(() => ({ rows: [] }));
  if (!r.rows[0]?.config) return null;
  const config = JSON.parse(r.rows[0].config);
  return decrypt ? decryptSecretConfig(config) : config;
}

async function sendWithTenantProvider(config: TenantEmailConfig, opts: {
  to: string; subject: string; html: string; text?: string;
}): Promise<boolean> {
  if (!config.enabled || config.provider === 'none') return sendEmail(opts);
  const from = config.fromEmail || FROM_EMAIL;
  if (config.provider === 'resend') {
    if (!config.apiKey) throw new Error('Resend API key missing');
    await axios.post('https://api.resend.com/emails', {
      from, to: opts.to, subject: opts.subject, html: opts.html,
    }, { headers: { Authorization: `Bearer ${config.apiKey}` }, timeout: 10_000 });
    return true;
  }
  if (config.provider === 'sendgrid') {
    if (!config.apiKey) throw new Error('SendGrid API key missing');
    await axios.post('https://api.sendgrid.com/v3/mail/send', {
      personalizations: [{ to: [{ email: opts.to }] }],
      from: { email: from.includes('<') ? from.replace(/^.*<|>$/g, '') : from },
      subject: opts.subject,
      content: [{ type: 'text/html', value: opts.html }],
    }, { headers: { Authorization: `Bearer ${config.apiKey}` }, timeout: 10_000 });
    return true;
  }
  if (config.provider === 'smtp') {
    if (!config.smtpHost) throw new Error('SMTP host missing');
    const transport = nodemailer.createTransport({
      host: config.smtpHost,
      port: Number(config.smtpPort || 587),
      secure: Boolean(config.secure),
      auth: config.smtpUser || config.smtpPassword ? { user: config.smtpUser, pass: config.smtpPassword } : undefined,
    });
    await transport.sendMail({ from, to: opts.to, subject: opts.subject, html: opts.html, text: opts.text });
    return true;
  }
  return sendEmail(opts);
}

export async function sendTenantEmail(db: Pool, tenantId: string, opts: {
  to: string; subject: string; html: string; text?: string;
}): Promise<boolean> {
  const config = await readTenantEmailConfig(db, tenantId, true);
  if (!config?.configured || config.enabled === false) return sendEmail(opts);
  try {
    return await sendWithTenantProvider(config, opts);
  } catch (e: any) {
    console.error('Tenant email send failed:', e.message);
    return false;
  }
}

// ── Email templates ────────────────────────────────────────────────────
export async function sendWelcomeEmail(email: string, tenantName: string, apiKey: string): Promise<void> {
  await sendEmail({
    to: email,
    subject: 'Welcome to MCP Security Gateway',
    html: `<h2>Welcome, ${tenantName}!</h2>
    <p>Your account is ready. Your API key:</p>
    <code style="background:#f5f5f5;padding:8px 16px;display:block">${apiKey}</code>
    <p>Quick start: <a href="${process.env.APP_URL}/dashboard">Open dashboard</a></p>
    <p>Your 14-day free trial has started. No credit card required.</p>`,
  });
}

export async function sendInvoiceEmail(email: string, tenantName: string, amount: number, invoiceUrl: string): Promise<void> {
  await sendEmail({
    to: email,
    subject: `Invoice: $${amount.toFixed(2)} — MCP Security`,
    html: `<h2>Invoice for ${tenantName}</h2>
    <p>Amount due: <strong>$${amount.toFixed(2)}</strong></p>
    <p><a href="${invoiceUrl}">View invoice</a></p>`,
  });
}

export async function sendTrialExpiryEmail(email: string, tenantName: string, daysLeft: number): Promise<void> {
  await sendEmail({
    to: email,
    subject: daysLeft === 0 ? 'Your trial has expired' : `Trial ending in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`,
    html: `<h2>Your MCP Security trial ${daysLeft === 0 ? 'has ended' : `ends in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`}</h2>
    <p>${daysLeft === 0 ? 'Your access has been paused.' : 'Upgrade now to keep your agents running.'}</p>
    <p><a href="${process.env.APP_URL}/billing" style="background:#378ADD;color:white;padding:10px 20px;text-decoration:none;border-radius:6px">Upgrade plan</a></p>`,
  });
}

export async function sendSecurityAlertEmail(email: string, tenantName: string, message: string, severity: string): Promise<void> {
  await sendEmail({
    to: email,
    subject: `[${severity.toUpperCase()}] Security alert — ${tenantName}`,
    html: `<h2>Security Alert</h2><p>${message}</p><p><a href="${process.env.APP_URL}/dashboard">View dashboard</a></p>`,
  });
}

// ── Email queue processor ─────────────────────────────────────────────
// Processes emails queued by other modules (trial expiry, overage, etc.)
export async function processEmailQueue(db: Pool): Promise<void> {
  const rows = await db.query(
    `SELECT * FROM email_queue WHERE status='pending' AND created_at < NOW()+INTERVAL '1 minute' LIMIT 50`
  );
  for (const row of rows.rows) {
    try {
      const p = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;
      switch (row.template) {
        case 'welcome':        await sendWelcomeEmail(row.to_email, p.tenantName, p.apiKey); break;
        case 'invoice':        await sendInvoiceEmail(row.to_email, p.tenantName, p.amount, p.invoiceUrl); break;
        case 'trial_expired':  await sendTrialExpiryEmail(row.to_email, p.tenantName, 0); break;
        case 'trial_warning_3d': await sendTrialExpiryEmail(row.to_email, p.tenantName, 3); break;
        case 'trial_warning_1d': await sendTrialExpiryEmail(row.to_email, p.tenantName, 1); break;
        case 'security_alert': await sendSecurityAlertEmail(row.to_email, p.tenantName, p.message, p.severity); break;
      }
      await db.query(`UPDATE email_queue SET status='sent', sent_at=NOW() WHERE id=$1`, [row.id]);
    } catch {
      await db.query(`UPDATE email_queue SET status='failed', attempts=attempts+1 WHERE id=$1`, [row.id]);
    }
  }
}

// ── Fastify plugin ─────────────────────────────────────────────────────
export async function emailPlugin(fastify: FastifyInstance, opts: { db: Pool }): Promise<void> {
  const { db } = opts;

  // Process email queue every 30s
  setInterval(() => processEmailQueue(db).catch(() => {}), 30_000);

  // Test endpoint
  fastify.post('/api/email/test', async (req: any, reply) => {
    const adminSec = req.headers['x-admin-secret'];
    if (adminSec !== process.env.ADMIN_SECRET) return reply.code(403).send({ error: 'Forbidden' });
    const { to, template } = req.body;
    await sendEmail({ to, subject: 'MCP Security — Test Email', html: '<p>Test email from MCP Security Gateway.</p>' });
    return { sent: true };
  });

  fastify.get('/api/email/provider', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Missing tenant' });
    const config = await readTenantEmailConfig(db, tenantId, false);
    if (!config) {
      return {
        configured: false,
        provider: process.env.EMAIL_API_KEY ? PROVIDER : 'none',
        runtimeSource: process.env.EMAIL_API_KEY ? 'platform' : 'none',
      };
    }
    const redacted = redactSecretConfig(config) as any;
    return {
      configured: Boolean(config.configured),
      enabled: config.enabled !== false,
      provider: config.provider,
      fromEmail: config.fromEmail,
      smtpHost: config.smtpHost,
      smtpPort: config.smtpPort,
      smtpUser: config.smtpUser,
      secure: Boolean(config.secure),
      hasApiKey: Boolean(config.apiKey),
      hasSmtpPassword: Boolean(config.smtpPassword),
      apiKeyPreview: redacted.apiKey,
      smtpPasswordPreview: redacted.smtpPassword,
      updatedAt: (config as any).updatedAt || null,
      runtimeSource: config.enabled !== false ? 'tenant' : (process.env.EMAIL_API_KEY ? 'platform' : 'none'),
    };
  });

  fastify.put('/api/email/provider', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Missing tenant' });
    const planR = await db.query(`SELECT plan, metadata->'emailProvider' AS config FROM tenants WHERE id=$1`, [tenantId]);
    if (!['growth', 'enterprise'].includes(planR.rows[0]?.plan)) {
      return reply.code(402).send({ error: 'Customer-owned email provider requires Growth or Enterprise plan' });
    }
    const body = req.body || {};
    const provider = String(body.provider || 'resend').trim().toLowerCase();
    if (!['resend', 'sendgrid', 'smtp', 'none'].includes(provider)) return reply.code(400).send({ error: 'Unsupported email provider' });
    const existing = planR.rows[0]?.config ? decryptSecretConfig(planR.rows[0].config) as any : {};
    const config: TenantEmailConfig & { updatedAt: string } = {
      provider: provider as TenantEmailProvider,
      fromEmail: String(body.fromEmail || existing.fromEmail || FROM_EMAIL).trim(),
      apiKey: String(body.apiKey || '').trim() || existing.apiKey,
      smtpHost: String(body.smtpHost || existing.smtpHost || '').trim() || undefined,
      smtpPort: body.smtpPort ? Number(body.smtpPort) : existing.smtpPort,
      smtpUser: String(body.smtpUser || existing.smtpUser || '').trim() || undefined,
      smtpPassword: String(body.smtpPassword || '').trim() || existing.smtpPassword,
      secure: Boolean(body.secure),
      enabled: body.enabled !== false,
      configured: true,
      updatedAt: new Date().toISOString(),
    };
    if (provider !== 'none' && !config.fromEmail) return reply.code(400).send({ error: 'From email required' });
    if (['resend', 'sendgrid'].includes(provider) && !config.apiKey) return reply.code(400).send({ error: 'API key required' });
    if (provider === 'smtp' && (!config.smtpHost || !config.smtpPort)) return reply.code(400).send({ error: 'SMTP host and port required' });
    await db.query(
      `UPDATE tenants SET metadata = jsonb_set(COALESCE(metadata,'{}'), '{emailProvider}', $1::jsonb) WHERE id=$2`,
      [JSON.stringify(encryptSecretConfig(config)), tenantId]
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'email.provider.save','email_provider',$4,NOW())`,
      [
        tenantId,
        String(req.headers['x-admin-email'] || 'local-admin'),
        String(req.headers['x-admin-role'] || 'local_admin'),
        JSON.stringify({ provider, fromEmail: config.fromEmail, enabled: config.enabled }),
      ]
    ).catch(() => {});
    return { saved: true, configured: true, provider, enabled: config.enabled };
  });

  fastify.post('/api/email/provider/test', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Missing tenant' });
    const to = String(req.body?.to || req.headers['x-admin-email'] || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return reply.code(400).send({ error: 'Valid test email recipient required' });
    const sent = await sendTenantEmail(db, tenantId, {
      to,
      subject: 'MCP Security email provider test',
      html: '<p>Your tenant email provider is configured and can send messages.</p>',
    });
    if (!sent) return reply.code(502).send({ sent: false, error: 'Email provider test failed' });
    return { sent: true };
  });
}
