/**
 * Webhook & Alerting Engine
 * Sends real-time alerts to Slack, PagerDuty, email, or custom webhooks
 * when security events occur.
 */

import { Pool } from 'pg';
import axios from 'axios';
import { ensurePlanLimitSchema, enforcePlanLimit, getPlanUsage, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';
import { decryptSecretConfig, decryptValue, encryptSecretConfig, encryptValue, redactSecretConfig } from '../security/secrets';
import { sendTenantEmail } from '../email/mailer';

export type AlertChannel = 'slack' | 'pagerduty' | 'email' | 'webhook' | 'teams' | 'siem';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AlertRule {
  id: string;
  tenantId?: string;
  tenant_id?: string;
  name: string;
  eventType?: string;
  event_type?: string;
  threshold?: number;
  windowSeconds?: number;
  window_seconds?: number;
  window_minutes?: number;
  severity?: AlertSeverity;
  channels?: AlertChannel[];
  cooldownSeconds?: number;
  cooldown_seconds?: number;
  active: boolean;
}

export interface AlertEvent {
  tenantId: string;
  ruleId: string;
  ruleName: string;
  severity: AlertSeverity;
  eventType: string;
  message: string;
  details: Record<string, unknown>;
  triggeredAt: Date;
}

function tenantIdFrom(req: any): string | undefined {
  return req?.tenant?.id || req?.headers?.['x-tenant-id'];
}

function allowBrowserRoleHeaders(): boolean {
  return process.env.NODE_ENV !== 'production' || process.env.ALLOW_DEV_ROLE_HEADERS === 'true';
}

function securityRoleFrom(req: any): string {
  const sessionRole = req?.user?.role;
  if (sessionRole) return String(sessionRole);
  if (allowBrowserRoleHeaders()) return String(req?.headers?.['x-admin-role'] || 'local_admin');
  return 'viewer';
}

function validateChannelConfig(type: string, config: any): string | null {
  const value = String(config?.url || config?.webhookUrl || config?.email || config?.integrationKey || '').trim();
  if (!value) return 'Channel destination is required';
  if (['webhook', 'slack', 'teams', 'siem'].includes(type)) {
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol)) return 'URL must start with http:// or https://';
    } catch {
      return 'Enter a valid http:// or https:// URL';
    }
  }
  if (type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'Enter a valid email address';
  if (type === 'pagerduty' && value.length < 8) return 'Enter a valid PagerDuty integration key';
  return null;
}

function channelLabel(type: string): string {
  return type === 'slack' ? 'Slack'
    : type === 'pagerduty' ? 'PagerDuty'
    : type === 'webhook' ? 'Custom webhook'
    : type === 'email' ? 'Email'
    : type === 'teams' ? 'Microsoft Teams'
    : type === 'siem' ? 'SIEM / HTTP collector'
    : String(type).replace(/_/g, ' ');
}

function channelDetail(config: any): string {
  const safeConfig = decryptSecretConfig(config || {});
  const name = safeConfig?.channel || safeConfig?.name;
  const destination = maskDestination(safeConfig);
  if (name && destination) return `${name} -> ${destination}`;
  return name || destination || 'configured';
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function maskDestination(config: any): string {
  const raw = String(config?.url || config?.webhookUrl || config?.email || config?.integrationKey || '').trim();
  if (!raw) return '';
  if (raw.includes('@') && !raw.startsWith('http')) {
    const [name, domain] = raw.split('@');
    return `${name.slice(0, 2)}***@${domain}`;
  }
  if (/^[A-Za-z0-9_-]{8,}$/.test(raw) && !raw.startsWith('http')) {
    return `${raw.slice(0, 4)}...${raw.slice(-4)}`;
  }
  try {
    const url = new URL(raw);
    if (url.hostname.includes('hooks.slack.com') || url.hostname.includes('office.com')) {
      return `${url.origin}${url.pathname.split('/').slice(0, 3).join('/')}/...`;
    }
    return `${url.origin}${url.pathname}`;
  } catch {
    return raw.length > 24 ? `${raw.slice(0, 12)}...${raw.slice(-6)}` : raw;
  }
}

function requireSecurityRole(req: any, reply: any): boolean {
  const role = securityRoleFrom(req);
  if (['local_admin', 'super_admin', 'security_analyst'].includes(String(role))) return true;
  reply.code(403).send({ error: 'Requires security_analyst or super_admin role' });
  return false;
}

async function ensureAlertSchema(db: Pool): Promise<void> {
  await ensurePlanLimitSchema(db);
  await db.query(`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS owner_email TEXT`).catch(() => {});
  await db.query(`ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS cooldown_seconds INTEGER DEFAULT 300`).catch(() => {});
  await db.query(`
    CREATE TABLE IF NOT EXISTS alert_channel_configs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      channel_type TEXT NOT NULL,
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (tenant_id, channel_type)
    )
  `).catch(() => {});
  await db.query(`
    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      channel TEXT NOT NULL,
      event_type TEXT NOT NULL,
      status_code INTEGER,
      success BOOLEAN DEFAULT FALSE,
      duration_ms INTEGER,
      error_message TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS delivered BOOLEAN DEFAULT FALSE`).catch(() => {});
  await db.query(`ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ`).catch(() => {});
  await db.query(`ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS max_retries INTEGER DEFAULT 5`).catch(() => {});
  await db.query(`ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS dead_lettered BOOLEAN DEFAULT FALSE`).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant ON webhook_deliveries(tenant_id, created_at DESC)`).catch(() => {});
  await db.query(`
    CREATE TABLE IF NOT EXISTS alert_channels (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id UUID NOT NULL,
      type TEXT NOT NULL,
      name TEXT NOT NULL,
      owner_email TEXT,
      scope TEXT NOT NULL DEFAULT 'prod',
      config JSONB NOT NULL DEFAULT '{}'::jsonb,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `).catch(() => {});
  await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_channels_unique_name ON alert_channels(tenant_id, type, name)`).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alert_channels_tenant ON alert_channels(tenant_id, active, type)`).catch(() => {});
  await db.query(`
    CREATE TABLE IF NOT EXISTS alert_rule_channels (
      rule_id UUID NOT NULL,
      channel_id UUID NOT NULL,
      tenant_id UUID NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (rule_id, channel_id)
    )
  `).catch(() => {});
  await db.query(`CREATE INDEX IF NOT EXISTS idx_alert_rule_channels_rule ON alert_rule_channels(rule_id)`).catch(() => {});
}

function ruleTenantId(rule: AlertRule): string {
  return String(rule.tenant_id || rule.tenantId || '');
}

function ruleEventType(rule: AlertRule): string {
  return normalizeEventType(String(rule.event_type || rule.eventType || ''));
}

function normalizeEventType(eventType: string): string {
  const aliases: Record<string, string> = {
    high_denial_rate: 'denial_rate_spike',
    denial_rate: 'denial_rate_spike',
    prompt_injection: 'injection_detected',
  };
  return aliases[eventType] || eventType;
}

function ruleWindowSeconds(rule: AlertRule): number {
  return Number(rule.window_seconds || rule.windowSeconds || (rule.window_minutes ? rule.window_minutes * 60 : 3600));
}

function parseChannels(value: unknown): AlertChannel[] {
  if (!value) return [];
  if (Array.isArray(value)) return value as AlertChannel[];
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return value.split(',').map(v => v.trim()).filter(Boolean) as AlertChannel[];
  }
}

function channelsAndConfigs(rule: any, storedConfigs: Record<string, any>) {
  const configs = { ...storedConfigs };
  const channels = new Set<AlertChannel>(parseChannels(rule.channels));

  if (rule.slack_webhook) {
    channels.add('slack');
    configs.slack = { webhookUrl: decryptValue(rule.slack_webhook) };
  }
  if (rule.webhook_url) {
    channels.add('webhook');
    configs.webhook = { url: decryptValue(rule.webhook_url) };
  }
  if (rule.pagerduty_key) {
    channels.add('pagerduty');
    configs.pagerduty = { integrationKey: decryptValue(rule.pagerduty_key) };
  }

  return { channels: Array.from(channels), configs };
}

async function deliveryTargetsForRule(rule: any, db: Pool): Promise<Array<{ id?: string; type: AlertChannel; label: string; config: any }>> {
  const selected = await db.query(
    `SELECT c.id, c.type, c.name, c.config
     FROM alert_rule_channels rc
     JOIN alert_channels c ON c.id=rc.channel_id AND c.tenant_id=rc.tenant_id
     WHERE rc.rule_id=$1 AND rc.tenant_id=$2 AND c.active=true
     ORDER BY c.type, c.name`,
    [rule.id, rule.tenant_id]
  ).catch(() => ({ rows: [] }));

  if (selected.rows.length) {
    return selected.rows.map((row: any) => ({
      id: row.id,
      type: row.type,
      label: row.name || channelLabel(row.type),
      config: decryptSecretConfig(row.config || {}),
    }));
  }

  const storedConfigs = await getChannelConfigs(rule.tenant_id, db);
  const { channels, configs } = channelsAndConfigs(rule, storedConfigs);
  return channels.map(ch => ({ type: ch, label: channelLabel(ch), config: configs[ch] }));
}

export async function dispatchAlert(event: AlertEvent, db: Pool): Promise<void> {
  const ruleResult = await db.query(
    `SELECT * FROM alert_rules
     WHERE id = $1 AND tenant_id = $2 AND active = true`,
    [event.ruleId, event.tenantId]
  );
  if (!ruleResult.rows.length) return;

  const rule = ruleResult.rows[0];
  const cooldownSeconds = Number(rule.cooldown_seconds || 300);
  const lastSent = await db.query(
    `SELECT sent_at FROM alert_log
     WHERE rule_id = $1 AND tenant_id = $2
     ORDER BY sent_at DESC LIMIT 1`,
    [event.ruleId, event.tenantId]
  );

  if (lastSent.rows.length) {
    const secondsSinceLast = (Date.now() - new Date(lastSent.rows[0].sent_at).getTime()) / 1000;
    if (secondsSinceLast < cooldownSeconds) return;
  }

  const targets = await deliveryTargetsForRule(rule, db);
  await Promise.all(targets.map(async target => {
    const started = Date.now();
    try {
      const statusCode = await sendToChannel(target.type, event, target.config, db);
      await recordDelivery(db, {
        tenantId: event.tenantId,
        channel: target.id ? `${target.type}:${target.id}` : target.type,
        eventType: event.eventType,
        success: true,
        statusCode,
        durationMs: Date.now() - started,
      });
    } catch (err: any) {
      await recordDelivery(db, {
        tenantId: event.tenantId,
        channel: target.id ? `${target.type}:${target.id}` : target.type,
        eventType: event.eventType,
        success: false,
        durationMs: Date.now() - started,
        errorMessage: err?.response?.data ? JSON.stringify(err.response.data).slice(0, 500) : (err?.message || 'delivery failed').slice(0, 500),
      });
    }
  }));

  await db.query(
    `INSERT INTO alert_log (tenant_id, rule_id, event_type, severity, message, details, sent_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
    [event.tenantId, event.ruleId, event.eventType, event.severity, event.message, JSON.stringify(event.details)]
  );

  await db.query(`UPDATE alert_rules SET last_triggered=NOW() WHERE id=$1`, [event.ruleId]).catch(() => {});
}

async function recordDelivery(db: Pool, params: {
  tenantId: string;
  channel: string;
  eventType: string;
  success: boolean;
  statusCode?: number;
  durationMs?: number;
  errorMessage?: string;
}) {
  await db.query(
    `INSERT INTO webhook_deliveries
       (tenant_id, channel, event_type, status_code, success, delivered, duration_ms, error_message, next_retry_at, dead_lettered, created_at)
     VALUES ($1,$2,$3,$4,$5,$5,$6,$7,CASE WHEN $5 THEN NULL ELSE NOW()+INTERVAL '5 minutes' END,false,NOW())`,
    [
      params.tenantId,
      params.channel,
      params.eventType,
      params.statusCode || null,
      params.success,
      params.durationMs || null,
      params.errorMessage || null,
    ]
  ).catch(() => {});
}

async function sendToChannel(channel: AlertChannel, event: AlertEvent, config: any, db?: Pool): Promise<number | undefined> {
  if (!config) throw new Error(`Channel ${channel} is not configured`);
  const safeConfig = decryptSecretConfig(config);

  switch (channel) {
    case 'slack': return sendSlack(event, safeConfig);
    case 'pagerduty': return sendPagerDuty(event, safeConfig);
    case 'webhook': return sendWebhook(event, safeConfig);
    case 'teams': return sendWebhook(event, { url: safeConfig.webhookUrl || safeConfig.url });
    case 'siem': return sendWebhook(event, { url: safeConfig.url || safeConfig.webhookUrl, secret: safeConfig.secret });
    case 'email': return sendEmailAlert(event, safeConfig, db);
    default: throw new Error(`Unsupported channel ${channel}`);
  }
}

async function sendEmailAlert(event: AlertEvent, config: { email?: string; to?: string; name?: string }, db?: Pool): Promise<number | undefined> {
  if (!db) throw new Error('Email provider is not available');
  const to = config.email || config.to;
  if (!to) throw new Error('Email recipient missing');
  const sent = await sendTenantEmail(db, event.tenantId, {
    to,
    subject: `[${event.severity.toUpperCase()}] ${event.ruleName}`,
    html: `<h2>MCP Security Alert</h2>
      <p><strong>${event.message}</strong></p>
      <p>Event: ${event.eventType}</p>
      <p>Tenant: ${event.tenantId}</p>
      <pre>${escapeHtml(JSON.stringify(event.details || {}, null, 2))}</pre>`,
    text: `${event.ruleName}\n${event.message}\n${JSON.stringify(event.details || {})}`,
  });
  if (!sent) throw new Error('Email provider delivery failed');
  return 202;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function sendSlack(event: AlertEvent, config: { webhookUrl?: string; url?: string }): Promise<number | undefined> {
  const webhookUrl = config.webhookUrl || config.url;
  if (!webhookUrl) throw new Error('Slack webhookUrl missing');
  const color = { critical: '#E24B4A', high: '#BA7517', medium: '#378ADD', low: '#1D9E75', info: '#888780' }[event.severity];
  const response = await axios.post(webhookUrl, {
    attachments: [{
      color,
      title: `[${event.severity.toUpperCase()}] ${event.ruleName}`,
      text: event.message,
      fields: [
        { title: 'Event type', value: event.eventType, short: true },
        { title: 'Tenant', value: event.tenantId, short: true },
        ...Object.entries(event.details).map(([k, v]) => ({ title: k, value: String(v), short: true })),
      ],
      footer: 'MCP Security Gateway',
      ts: Math.floor(event.triggeredAt.getTime() / 1000),
    }],
  });
  return response.status;
}

async function sendPagerDuty(event: AlertEvent, config: { integrationKey?: string; routingKey?: string }): Promise<number | undefined> {
  const integrationKey = config.integrationKey || config.routingKey;
  if (!integrationKey) throw new Error('PagerDuty integration key missing');
  const urgency = event.severity === 'critical' || event.severity === 'high' ? 'high' : 'low';
  const response = await axios.post('https://events.pagerduty.com/v2/enqueue', {
    routing_key: integrationKey,
    event_action: 'trigger',
    dedup_key: `${event.tenantId}:${event.ruleId}:${event.eventType}`,
    payload: {
      summary: `[MCP Security] ${event.ruleName}: ${event.message}`,
      severity: urgency,
      source: 'mcp-security-gateway',
      timestamp: event.triggeredAt.toISOString(),
      custom_details: event.details,
    },
  });
  return response.status;
}

async function sendWebhook(event: AlertEvent, config: { url?: string; webhookUrl?: string; secret?: string }): Promise<number | undefined> {
  const url = config.url || config.webhookUrl;
  if (!url) throw new Error('Webhook URL missing');
  const payload = JSON.stringify({ event, sentAt: new Date().toISOString() });
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (config.secret) {
    const crypto = require('crypto');
    headers['X-MCP-Signature'] = crypto.createHmac('sha256', config.secret).update(payload).digest('hex');
  }
  const response = await axios.post(url, payload, { headers, timeout: 10_000 });
  return response.status;
}

async function getChannelConfigs(tenantId: string, db: Pool): Promise<Record<string, any>> {
  try {
    const result = await db.query(
      `SELECT channel_type, config FROM alert_channel_configs WHERE tenant_id = $1 AND active = true`,
      [tenantId]
    );
    return Object.fromEntries(result.rows.map(r => [r.channel_type, decryptSecretConfig(r.config)]));
  } catch {
    return {};
  }
}

export async function evaluateAlertRules(db: Pool): Promise<void> {
  const rules = await db.query(`SELECT * FROM alert_rules WHERE active = true`);
  for (const rule of rules.rows) {
    try {
      await evaluateRule(rule, db);
    } catch (e) {
      console.error(`Alert rule ${rule.id} evaluation failed:`, e);
    }
  }
}

async function evaluateRule(rule: AlertRule, db: Pool): Promise<void> {
  const windowSeconds = ruleWindowSeconds(rule);
  const tenantId = ruleTenantId(rule);
  const eventType = ruleEventType(rule);
  const threshold = Number(rule.threshold || 1);
  const severity = (rule.severity || 'medium') as AlertSeverity;
  const windowStart = new Date(Date.now() - windowSeconds * 1000);

  if (eventType === 'denial_rate_spike') {
    const stats = await db.query(
      `SELECT COUNT(*) as total,
              COUNT(*) FILTER (WHERE decision='DENY') as denied
       FROM audit_log
       WHERE tenant_id=$1 AND created_at > $2`,
      [tenantId, windowStart]
    );
    const { total, denied } = stats.rows[0];
    const rate = total > 0 ? (denied / total) * 100 : 0;
    if (rate >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity, eventType,
        message: `Denial rate ${Math.round(rate)}% exceeded threshold ${threshold}% in last ${windowSeconds}s`,
        details: { denialRate: Math.round(rate), totalRequests: total, deniedRequests: denied },
        triggeredAt: new Date(),
      }, db);
    }
  }

  if (eventType === 'injection_detected') {
    const count = await db.query(
      `SELECT COUNT(*) as cnt FROM audit_log
       WHERE tenant_id=$1 AND created_at > $2 AND reason LIKE 'prompt_injection%'`,
      [tenantId, windowStart]
    );
    if (Number(count.rows[0].cnt) >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity: 'critical', eventType,
        message: `${count.rows[0].cnt} prompt injection attempts detected in last ${windowSeconds}s`,
        details: { injectionAttempts: count.rows[0].cnt },
        triggeredAt: new Date(),
      }, db);
    }
  }

  if (eventType === 'auth_failure') {
    const count = await db.query(
      `SELECT COUNT(*) as cnt FROM audit_log
       WHERE tenant_id=$1 AND created_at > $2 AND decision='DENY' AND reason LIKE 'auth_%'`,
      [tenantId, windowStart]
    );
    if (Number(count.rows[0].cnt) >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity, eventType,
        message: `${count.rows[0].cnt} authentication failures detected in last ${windowSeconds}s`,
        details: { authFailures: Number(count.rows[0].cnt) },
        triggeredAt: new Date(),
      }, db);
    }
  }

  if (eventType === 'dlp_blocked') {
    const count = await db.query(
      `SELECT COUNT(*) as cnt FROM audit_log
       WHERE tenant_id=$1 AND created_at > $2 AND reason LIKE 'dlp_blocked%'`,
      [tenantId, windowStart]
    );
    if (Number(count.rows[0].cnt) >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity, eventType,
        message: `${count.rows[0].cnt} DLP-blocked tool calls detected in last ${windowSeconds}s`,
        details: { dlpBlocked: Number(count.rows[0].cnt) },
        triggeredAt: new Date(),
      }, db);
    }
  }

  if (eventType === 'hitl_timeout') {
    const count = await db.query(
      `SELECT COUNT(*) as cnt FROM hitl_approvals
       WHERE tenant_id=$1 AND created_at > $2 AND decision='timeout'`,
      [tenantId, windowStart]
    ).catch(() => ({ rows: [{ cnt: 0 }] }));
    if (Number(count.rows[0].cnt) >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity, eventType,
        message: `${count.rows[0].cnt} human approvals timed out in last ${windowSeconds}s`,
        details: { hitlTimeouts: Number(count.rows[0].cnt) },
        triggeredAt: new Date(),
      }, db);
    }
  }

  if (eventType === 'anomaly_detected') {
    const count = await db.query(
      `SELECT COUNT(*) as cnt FROM anomaly_events
       WHERE tenant_id=$1 AND created_at > $2`,
      [tenantId, windowStart]
    );
    if (Number(count.rows[0].cnt) >= threshold) {
      await dispatchAlert({
        tenantId, ruleId: rule.id, ruleName: rule.name, severity, eventType,
        message: `${count.rows[0].cnt} ML anomaly events detected in last ${windowSeconds}s`,
        details: { anomalyEvents: Number(count.rows[0].cnt) },
        triggeredAt: new Date(),
      }, db);
    }
  }
}

export async function alertPlugin(fastify: any, opts: { db: Pool }): Promise<void> {
  const { db } = opts;
  await ensureAlertSchema(db);

  async function listRules(req: any, reply: any) {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const r = await db.query(
      `SELECT r.*, COALESCE(r.owner_email, r.email, 'unassigned') AS owner,
              COALESCE(json_agg(json_build_object('id', c.id, 'type', c.type, 'name', c.name, 'scope', c.scope) ORDER BY c.type, c.name)
                FILTER (WHERE c.id IS NOT NULL), '[]'::json) AS selected_channels
       FROM alert_rules r
       LEFT JOIN alert_rule_channels rc ON rc.rule_id=r.id AND rc.tenant_id=r.tenant_id
       LEFT JOIN alert_channels c ON c.id=rc.channel_id AND c.tenant_id=rc.tenant_id
       WHERE r.tenant_id=$1
       GROUP BY r.id
       ORDER BY r.created_at DESC`,
      [tenantId]
    );
    return {
      rules: r.rows.map((row: any) => ({
        ...row,
        slack_webhook: row.slack_webhook ? '[configured]' : null,
        webhook_url: row.webhook_url ? '[configured]' : null,
        pagerduty_key: row.pagerduty_key ? '[configured]' : null,
      })),
    };
  }

  async function listChannels(req: any, reply: any) {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });

    const [enterpriseChannels, configured, ruleDestinations] = await Promise.all([
      db.query(
        `SELECT c.*,
                COUNT(rc.rule_id)::int AS rule_count,
                MAX(wd.created_at) AS last_delivery_at,
                COUNT(wd.id) FILTER (WHERE wd.success=false)::int AS failed_deliveries
         FROM alert_channels c
         LEFT JOIN alert_rule_channels rc ON rc.channel_id=c.id AND rc.tenant_id=c.tenant_id
         LEFT JOIN webhook_deliveries wd ON wd.tenant_id=c.tenant_id AND wd.channel LIKE (c.type || ':' || c.id::text)
         WHERE c.tenant_id=$1
         GROUP BY c.id
         ORDER BY c.type ASC, c.name ASC`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT id, channel_type, active, created_at, config
         FROM alert_channel_configs
         WHERE tenant_id=$1
         ORDER BY channel_type ASC`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT
           COUNT(*) FILTER (WHERE active=true AND slack_webhook IS NOT NULL AND slack_webhook <> '') AS slack_rules,
           COUNT(*) FILTER (WHERE active=true AND webhook_url IS NOT NULL AND webhook_url <> '') AS webhook_rules,
           COUNT(*) FILTER (WHERE active=true AND email IS NOT NULL AND email <> '') AS email_rules
         FROM alert_rules WHERE tenant_id=$1`,
        [tenantId]
      ),
    ]);

    const ruleCounts = ruleDestinations.rows[0] || {};
    const channels = new Map<string, any>();
    const enterprise = enterpriseChannels.rows.map((row: any) => ({
      id: row.id,
      type: row.type,
      label: channelLabel(row.type),
      name: row.name,
      active: Boolean(row.active),
      configured: true,
      source: 'alert_channels',
      detail: channelDetail(row.config || {}),
      destinationMasked: maskDestination(decryptSecretConfig(row.config || {})),
      ownerEmail: row.owner_email || 'unassigned',
      scope: row.scope || 'prod',
      ruleCount: Number(row.rule_count || 0),
      failedDeliveries: Number(row.failed_deliveries || 0),
      lastDeliveryAt: row.last_delivery_at,
    }));
    const add = (type: string, label: string, configuredNow: boolean, source: string, detail: string) => {
      const existing = channels.get(type);
      channels.set(type, {
        type,
        label,
        active: Boolean(existing?.active || configuredNow),
        configured: Boolean(existing?.configured || configuredNow),
        source: source === 'channel_config' || !existing?.source ? source : existing.source,
        detail: configuredNow && detail !== 'not configured' ? detail : (existing?.detail || detail),
      });
    };

    add('slack', 'Slack', Number(ruleCounts.slack_rules || 0) > 0, 'rule', Number(ruleCounts.slack_rules || 0) > 0 ? 'configured in alert rule' : 'not configured');
    add('pagerduty', 'PagerDuty', false, 'none', 'not configured');
    add('webhook', 'Custom webhook', Number(ruleCounts.webhook_rules || 0) > 0, 'rule', Number(ruleCounts.webhook_rules || 0) > 0 ? 'configured in alert rule' : 'not configured');
    add('email', 'Email', Number(ruleCounts.email_rules || 0) > 0, 'rule', Number(ruleCounts.email_rules || 0) > 0 ? 'configured in alert rule' : 'not configured');
    add('teams', 'Microsoft Teams', false, 'none', 'not configured');
    add('siem', 'SIEM / HTTP collector', false, 'none', 'not configured');

    for (const row of configured.rows) {
      const type = row.channel_type;
      const config = decryptSecretConfig(row.config || {});
      if (enterprise.some((ch: any) => ch.type === type && ch.name === (config.name || channelLabel(type)))) continue;
      const label = channelLabel(type);
      const detail = channelDetail(config);
      add(type, label, row.active, 'channel_config', row.active ? detail : 'disabled');
    }

    const savedTypes = new Set(configured.rows.map((row: any) => row.channel_type));
    const enterpriseTypes = new Set(enterprise.map((row: any) => row.type));
    const result = Array.from(channels.values()).filter((channel: any) =>
      !enterpriseTypes.has(channel.type) && (channel.configured || savedTypes.has(channel.type) || ['slack', 'pagerduty', 'webhook', 'email', 'teams', 'siem'].includes(channel.type))
    );
    return { channels: [...enterprise, ...result] };
  }

  async function createRule(req: any, reply: any) {
    if (!requireSecurityRole(req, reply)) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const { name, eventType, threshold, windowSeconds, windowMinutes, severity, slackWebhook, webhookUrl, email, ownerEmail, cooldownSeconds, channelIds } = req.body || {};
    const normalizedEventType = normalizeEventType(eventType || 'anomaly_detected');
    try {
      const usage = await getPlanUsage(db, tenantId);
      await enforcePlanLimit(db, {
        tenantId,
        featureKey: 'alert_rules',
        used: usage.alert_rules,
        action: 'alerts.rule.create',
        actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }
    const r = await db.query(
      `INSERT INTO alert_rules (tenant_id,name,event_type,threshold,window_minutes,severity,slack_webhook,webhook_url,email,owner_email,cooldown_seconds,active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) RETURNING *`,
      [
        tenantId,
        name || normalizedEventType || 'Security alert',
        normalizedEventType,
        threshold ?? 1,
        windowMinutes ?? (windowSeconds ? Math.max(1, Math.round(windowSeconds / 60)) : 60),
        severity || 'medium',
        slackWebhook ? encryptValue(slackWebhook) : null,
        webhookUrl ? encryptValue(webhookUrl) : null,
        email || null,
        ownerEmail || email || null,
        Math.max(30, Math.min(86400, parseInt(cooldownSeconds, 10) || 300)),
      ]
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'alerts.rule.create',$4,$5,NOW())`,
      [
        tenantId,
        String(req.headers['x-admin-email'] || 'local-admin'),
        String(req.headers['x-admin-role'] || 'local_admin'),
        `rule:${r.rows[0].id}`,
        JSON.stringify({ name: r.rows[0].name, eventType: normalizedEventType, severity: r.rows[0].severity }),
      ]
    ).catch(() => {});
    if (Array.isArray(channelIds) && channelIds.length) {
      for (const channelId of channelIds.filter((id: any) => isUuid(String(id)))) {
        await db.query(
          `INSERT INTO alert_rule_channels (rule_id, channel_id, tenant_id)
           SELECT $1, id, tenant_id FROM alert_channels WHERE id=$2 AND tenant_id=$3
           ON CONFLICT DO NOTHING`,
          [r.rows[0].id, channelId, tenantId]
        ).catch(() => {});
      }
    }
    return { created: true, id: r.rows[0].id, rule: r.rows[0] };
  }

  fastify.get('/api/alerts', listRules);
  fastify.get('/api/alerts/rules', listRules);
  fastify.get('/api/alerts/channels', listChannels);
  fastify.post('/api/alerts/channels', async (req: any, reply: any) => {
    if (!requireSecurityRole(req, reply)) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const { type, config, active = true, name, ownerEmail, scope } = req.body || {};
    if (!type || typeof config !== 'object') return reply.code(400).send({ error: 'type and config object required' });
    if (!['webhook', 'slack', 'pagerduty', 'email', 'teams', 'siem'].includes(String(type))) {
      return reply.code(400).send({ error: 'Unsupported alert channel type' });
    }
    const validationError = validateChannelConfig(String(type), config);
    if (validationError) return reply.code(400).send({ error: validationError });
    const channelName = String(name || config.name || channelLabel(String(type))).trim();
    const channelScope = String(scope || config.scope || 'prod').trim() || 'prod';
    const existing = await db.query(
      `SELECT id FROM alert_channels WHERE tenant_id=$1 AND type=$2 AND name=$3`,
      [tenantId, type, channelName]
    );
    if (!existing.rows.length && Boolean(active)) {
      try {
        const usage = await getPlanUsage(db, tenantId);
        await enforcePlanLimit(db, {
          tenantId,
          featureKey: 'alert_channels',
          used: usage.alert_channels,
          action: 'alerts.channel.create',
          actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
        });
        if (['slack', 'pagerduty', 'teams', 'siem'].includes(String(type))) {
          await enforcePlanLimit(db, {
            tenantId,
            featureKey: 'integrations',
            used: usage.integrations,
            action: 'alerts.integration.create',
            actorEmail: String(req.headers['x-admin-email'] || 'local-admin'),
          });
        }
      } catch (err: any) {
        if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
          return reply.code(403).send(planLimitErrorPayload(err));
        }
        throw err;
      }
    }
    const r = await db.query(
      `INSERT INTO alert_channels (tenant_id, type, name, owner_email, scope, config, active, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
       ON CONFLICT (tenant_id, type, name)
       DO UPDATE SET owner_email=$4, scope=$5, config=$6, active=$7, updated_at=NOW()
       RETURNING id, type, name, owner_email, scope, active, config, created_at, updated_at`,
      [tenantId, type, channelName, ownerEmail || config.ownerEmail || null, channelScope, JSON.stringify(encryptSecretConfig({ ...config, name: channelName })), Boolean(active)]
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'alerts.channel.save',$4,$5,NOW())`,
      [
        tenantId,
        String(req.headers['x-admin-email'] || 'local-admin'),
        String(req.headers['x-admin-role'] || 'local_admin'),
        `channel:${r.rows[0].id}`,
        JSON.stringify({ active: Boolean(active), type, name: channelName, scope: channelScope }),
      ]
    ).catch(() => {});
    return { saved: true, channel: { ...r.rows[0], config: redactSecretConfig(r.rows[0].config || {}) } };
  });

  fastify.patch('/api/alerts/channels/:id', async (req: any, reply: any) => {
    if (!requireSecurityRole(req, reply)) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const id = String(req.params.id || '').trim();
    if (!isUuid(id)) return reply.code(400).send({ error: 'Channel id required' });
    const active = Boolean(req.body?.active);
    const r = await db.query(
      `UPDATE alert_channels SET active=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING id, type, name, active`,
      [active, id, tenantId]
    );
    if (!r.rows.length) return reply.code(404).send({ error: 'Channel not found' });
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'alerts.channel.set_active',$4,$5,NOW())`,
      [tenantId, String(req.headers['x-admin-email'] || 'local-admin'), String(req.headers['x-admin-role'] || 'local_admin'), `channel:${id}`, JSON.stringify({ active })]
    ).catch(() => {});
    return { saved: true, channel: r.rows[0] };
  });

  fastify.delete('/api/alerts/channels/:idOrType', async (req: any, reply: any) => {
    if (!requireSecurityRole(req, reply)) return;
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const idOrType = String(req.params.idOrType || '').trim();
    if (!idOrType) return reply.code(400).send({ error: 'Missing channel' });
    if (isUuid(idOrType)) {
      await db.query(`DELETE FROM alert_rule_channels WHERE tenant_id=$1 AND channel_id=$2`, [tenantId, idOrType]).catch(() => {});
      await db.query(`DELETE FROM alert_channels WHERE tenant_id=$1 AND id=$2`, [tenantId, idOrType]);
    } else {
      await db.query(`DELETE FROM alert_channel_configs WHERE tenant_id=$1 AND channel_type=$2`, [tenantId, idOrType]);
      await db.query(`DELETE FROM alert_channels WHERE tenant_id=$1 AND type=$2`, [tenantId, idOrType]);
    }
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'alerts.channel.delete',$4,'{}'::jsonb,NOW())`,
      [tenantId, String(req.headers['x-admin-email'] || 'local-admin'), String(req.headers['x-admin-role'] || 'local_admin'), `channel:${idOrType}`]
    ).catch(() => {});
    return { deleted: true, channel: idOrType };
  });
  fastify.post('/api/alerts', createRule);
  fastify.post('/api/alerts/rules', createRule);

  fastify.delete('/api/alerts/rules/:id', async (req: any, reply: any) => {
    if (!requireSecurityRole(req, reply)) return;
    const tenantId = tenantIdFrom(req);
    await db.query(`UPDATE alert_rules SET active=false WHERE id=$1 AND tenant_id=$2`, [req.params.id, tenantId]);
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'alerts.rule.delete',$4,'{}'::jsonb,NOW())`,
      [tenantId, String(req.headers['x-admin-email'] || 'local-admin'), String(req.headers['x-admin-role'] || 'local_admin'), `rule:${req.params.id}`]
    ).catch(() => {});
    return { deleted: true };
  });

  fastify.get('/api/alerts/delivery-status', async (req: any, reply: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const r = await db.query(
      `SELECT channel, event_type,
              COUNT(*)::int AS attempts,
              COUNT(*) FILTER (WHERE success=true)::int AS succeeded,
              COUNT(*) FILTER (WHERE success=false)::int AS failed,
              MAX(created_at) AS last_attempt,
              MAX(error_message) FILTER (WHERE success=false) AS last_error
       FROM webhook_deliveries
       WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30 days'
       GROUP BY channel, event_type
       ORDER BY last_attempt DESC`,
      [tenantId]
    ).catch(() => ({ rows: [] }));
    return { deliveries: r.rows };
  });

  fastify.get('/api/alerts/log', async (req: any, reply: any) => {
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing tenant' });
    const r = await db.query(
      `SELECT * FROM alert_log WHERE tenant_id=$1 ORDER BY sent_at DESC LIMIT 50`,
      [tenantId]
    );
    return { alerts: r.rows };
  });

  fastify.post('/api/alerts/test', async (req: any, reply: any) => {
    if (!requireSecurityRole(req, reply)) return;
    const { channel, channelId } = req.body || {};
    const tenantId = tenantIdFrom(req);
    if (!tenantId) return { sent: false, error: 'Missing tenant' };
    let target: any = null;
    if (channelId && isUuid(String(channelId))) {
      const row = await db.query(`SELECT id, type, name, config FROM alert_channels WHERE tenant_id=$1 AND id=$2`, [tenantId, channelId]);
      if (!row.rows.length) return reply.code(404).send({ sent: false, error: 'Channel not found' });
      target = { ...row.rows[0], config: decryptSecretConfig(row.rows[0].config || {}) };
    }
    const configs = target ? {} : await getChannelConfigs(tenantId, db);
    const event = {
      tenantId, ruleId: 'test', ruleName: 'Test alert',
      severity: 'info' as AlertSeverity, eventType: 'test',
      message: 'This is a test alert from MCP Security Gateway',
      details: { source: 'manual test' }, triggeredAt: new Date(),
    };
    const started = Date.now();
    try {
      const channelType = target?.type || channel;
      const statusCode = await sendToChannel(channelType, event, target?.config || configs[channel], db);
      await recordDelivery(db, { tenantId, channel: target?.id ? `${channelType}:${target.id}` : channelType, eventType: 'test', success: true, statusCode, durationMs: Date.now() - started });
      return { sent: true };
    } catch (err: any) {
      const channelType = target?.type || channel;
      await recordDelivery(db, { tenantId, channel: target?.id ? `${channelType}:${target.id}` : channelType, eventType: 'test', success: false, durationMs: Date.now() - started, errorMessage: err?.message || 'delivery failed' });
      return reply.code(502).send({ sent: false, error: err?.message || 'delivery failed' });
    }
  });
}
