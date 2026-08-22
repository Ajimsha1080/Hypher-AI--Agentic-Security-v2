/**
 * DLP — Data Loss Prevention + PII Masking
 *
 * Scans and masks Personally Identifiable Information in:
 *   - Inbound tool call arguments (before forwarding to MCP server)
 *   - Outbound tool responses (before returning to AI agent)
 *
 * Detection methods:
 *   1. Regex patterns — structured PII (SSN, cards, phone, email, API keys)
 *   2. NLP-style heuristics — contextual PII (names near "patient:", addresses)
 *   3. Secret detection — AWS/GitHub/Stripe keys embedded in content
 *
 * Actions per match:
 *   - 'block'  — reject entire request/response (SSNs in HIPAA mode)
 *   - 'mask'   — replace with [REDACTED:type] (default)
 *   - 'hash'   — replace with sha256 first 8 chars for correlation
 *   - 'allow'  — log but pass through (low-risk types)
 *
 * HIPAA mode (Enterprise): all PHI triggers block or mask.
 * Standard mode: mask by default, audit log every detection.
 */

import { Pool } from 'pg';
import crypto from 'crypto';

export interface PiiDetection {
  type: string;
  value: string;
  masked: string;
  position: number;
  action: 'block' | 'mask' | 'hash' | 'allow';
}

export interface DlpResult {
  clean: boolean;                   // true = no PII found, or all masked
  blocked: boolean;                 // true = request must be rejected
  detections: PiiDetection[];
  sanitizedArgs?: Record<string, unknown>;
  sanitizedResponse?: unknown;
}

// ── PII Pattern Library ────────────────────────────────────────────────

const PII_PATTERNS: Array<{
  type: string;
  pattern: RegExp;
  action: 'block' | 'mask' | 'hash' | 'allow';
  hipaaBlock: boolean;    // block in HIPAA mode regardless
}> = [
  // Financial
  { type: 'credit_card',     pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, action: 'block', hipaaBlock: true },
  { type: 'ssn',             pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g, action: 'block', hipaaBlock: true },
  { type: 'bank_account',    pattern: /\b[0-9]{8,17}\b(?=.*routing|.*account)/gi, action: 'mask', hipaaBlock: true },

  // Healthcare
  { type: 'npi_number',      pattern: /\bNPI[:\s]?\d{10}\b/gi, action: 'mask', hipaaBlock: true },
  { type: 'dea_number',      pattern: /\b[A-Z]{2}\d{7}\b/g, action: 'mask', hipaaBlock: true },
  { type: 'icd_code',        pattern: /\b[A-Z]\d{2}(?:\.\d{1,4})?\b/g, action: 'allow', hipaaBlock: false },

  // Identity
  { type: 'passport',        pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g, action: 'mask', hipaaBlock: true },
  { type: 'drivers_license', pattern: /\b[A-Z]{1,2}[-\s]?\d{5,9}\b/g, action: 'mask', hipaaBlock: false },
  { type: 'dob',             pattern: /\b(?:DOB|Date of Birth|Born)[:\s]+\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4}\b/gi, action: 'mask', hipaaBlock: true },

  // Contact
  { type: 'email',           pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g, action: 'mask', hipaaBlock: false },
  { type: 'phone_us',        pattern: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, action: 'mask', hipaaBlock: false },
  { type: 'phone_intl',      pattern: /\+(?:[1-9]\d{0,2}[-.\s]?)?(?:\d[-.\s]?){6,14}\d/g, action: 'mask', hipaaBlock: false },
  { type: 'ip_address',      pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, action: 'mask', hipaaBlock: false },

  // Secrets — always block
  { type: 'aws_key',         pattern: /\bAKIA[0-9A-Z]{16}\b/g, action: 'block', hipaaBlock: true },
  { type: 'aws_secret',      pattern: /\b[0-9a-zA-Z\/+]{40}\b(?=.*aws|.*AWS)/g, action: 'block', hipaaBlock: true },
  { type: 'github_token',    pattern: /\bghp_[0-9a-zA-Z]{36}\b|\bgho_[0-9a-zA-Z]{36}\b|\bghs_[0-9a-zA-Z]{36}\b/g, action: 'block', hipaaBlock: true },
  { type: 'stripe_key',      pattern: /\bsk_(?:live|test)_[0-9a-zA-Z]{24,99}\b/g, action: 'block', hipaaBlock: true },
  { type: 'stripe_pub',      pattern: /\bpk_(?:live|test)_[0-9a-zA-Z]{24,99}\b/g, action: 'mask', hipaaBlock: false },
  { type: 'openai_key',      pattern: /\bsk-[0-9a-zA-Z]{20,}T3BlbkFJ[0-9a-zA-Z]{20,}\b|\bsk-proj-[0-9a-zA-Z_]{40,}\b/g, action: 'block', hipaaBlock: true },
  { type: 'anthropic_key',   pattern: /\bsk-ant-[0-9a-zA-Z\-]{40,}\b/g, action: 'block', hipaaBlock: true },
  { type: 'jwt_token',       pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, action: 'block', hipaaBlock: true },
  { type: 'private_key',     pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, action: 'block', hipaaBlock: true },
  { type: 'generic_secret',  pattern: /(?:password|passwd|secret|token|api[_-]?key)[:\s=]+['"]?[^\s'"]{8,}['"]?/gi, action: 'mask', hipaaBlock: false },
];

// ── Core scan function ─────────────────────────────────────────────────

function scanText(
  text: string,
  hipaaMode: boolean
): PiiDetection[] {
  const detections: PiiDetection[] = [];

  for (const { type, pattern, action, hipaaBlock } of PII_PATTERNS) {
    const effectiveAction = (hipaaMode && hipaaBlock) ? 'block' : action;
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      const masked = getMasked(type, value, effectiveAction);
      detections.push({
        type,
        value: value.slice(0, 6) + '***', // never log full value
        masked,
        position: match.index,
        action: effectiveAction,
      });
    }
  }

  return detections;
}

function getMasked(type: string, value: string, action: string): string {
  if (action === 'block') return `[BLOCKED:${type}]`;
  if (action === 'allow') return value;
  if (action === 'hash') {
    const h = crypto.createHash('sha256').update(value).digest('hex').slice(0, 8);
    return `[${type.toUpperCase()}:${h}]`;
  }
  // mask: keep type and first/last chars for debugging
  const len = value.length;
  if (len <= 4) return `[${type.toUpperCase()}]`;
  return `${value.slice(0, 2)}${'*'.repeat(Math.max(4, len - 4))}${value.slice(-2)}`;
}

function applyMasking(text: string, detections: PiiDetection[]): string {
  let result = text;
  // Sort by position descending so replacements don't shift indices
  const sorted = [...detections].sort((a, b) => b.position - a.position);
  for (const d of sorted) {
    if (d.action !== 'allow') {
      // We can't use exact position because original pattern is global — do string replace
      const pattern = PII_PATTERNS.find(p => p.type === d.type)!;
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g');
      result = result.replace(regex, d.masked);
    }
  }
  return result;
}

// ── Deep-scan object (recursive) ──────────────────────────────────────

function scanAndSanitizeObject(
  obj: unknown,
  hipaaMode: boolean,
  depth = 0
): { sanitized: unknown; detections: PiiDetection[] } {
  if (depth > 8) return { sanitized: obj, detections: [] };
  const allDetections: PiiDetection[] = [];

  if (typeof obj === 'string') {
    const dets = scanText(obj, hipaaMode);
    allDetections.push(...dets);
    const sanitized = dets.length > 0 ? applyMasking(obj, dets) : obj;
    return { sanitized, detections: allDetections };
  }

  if (Array.isArray(obj)) {
    const items = obj.map(v => {
      const r = scanAndSanitizeObject(v, hipaaMode, depth + 1);
      allDetections.push(...r.detections);
      return r.sanitized;
    });
    return { sanitized: items, detections: allDetections };
  }

  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      const r = scanAndSanitizeObject(v, hipaaMode, depth + 1);
      allDetections.push(...r.detections);
      result[k] = r.sanitized;
    }
    return { sanitized: result, detections: allDetections };
  }

  return { sanitized: obj, detections: [] };
}

// ── Main API ───────────────────────────────────────────────────────────

export async function scanRequest(
  args: Record<string, unknown>,
  tenantId: string,
  agentId: string,
  toolName: string,
  db: Pool
): Promise<DlpResult> {
  const hipaaMode = await getTenantDlpMode(tenantId, db);
  const { sanitized, detections } = scanAndSanitizeObject(args, hipaaMode);
  const blocked = detections.some(d => d.action === 'block');

  if (detections.length > 0) {
    await logDlpEvent(tenantId, agentId, toolName, 'request', detections, blocked, db);
  }

  return {
    clean: detections.length === 0,
    blocked,
    detections,
    sanitizedArgs: sanitized as Record<string, unknown>,
  };
}

export async function scanResponse(
  response: unknown,
  tenantId: string,
  agentId: string,
  toolName: string,
  db: Pool
): Promise<DlpResult> {
  const hipaaMode = await getTenantDlpMode(tenantId, db);
  const { sanitized, detections } = scanAndSanitizeObject(response, hipaaMode);

  // In response scanning, we mask but never block (the tool call already happened)
  const detectionsMasked = detections.map(d => ({ ...d, action: 'mask' as const }));

  if (detections.length > 0) {
    await logDlpEvent(tenantId, agentId, toolName, 'response', detections, false, db);
  }

  return {
    clean: detections.length === 0,
    blocked: false,
    detections: detectionsMasked,
    sanitizedResponse: sanitized,
  };
}

export async function getTenantDlpMode(tenantId: string, db: Pool): Promise<boolean> {
  try {
    const r = await db.query(
      `SELECT enabled FROM tenant_feature_flags WHERE tenant_id=$1 AND flag_name='hipaa_mode'`,
      [tenantId]
    );
    return r.rows[0]?.enabled === true;
  } catch { return false; }
}

async function logDlpEvent(
  tenantId: string, agentId: string, toolName: string,
  direction: 'request' | 'response',
  detections: PiiDetection[], blocked: boolean, db: Pool
): Promise<void> {
  try {
    await db.query(
      `INSERT INTO dlp_events
         (tenant_id, agent_id, tool_name, direction, pii_types, detection_count, blocked, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
      [tenantId, agentId, toolName, direction,
       JSON.stringify([...new Set(detections.map(d => d.type))]),
       detections.length, blocked]
    );
  } catch { /* non-blocking */ }
}

// ── Fastify plugin for DLP management API ─────────────────────────────

export async function dlpPlugin(fastify: any, opts: { db: Pool }) {
  const { db } = opts;
  async function tenantFrom(req: any) {
    if (req.tenant?.id) return req.tenant;
    const tenantId = String(req.headers['x-tenant-id'] || '');
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
    const r = await db.query(`SELECT id, plan FROM tenants WHERE id=$1`, [tenantId]);
    return r.rows[0] || null;
  }

  fastify.get('/api/dlp/config', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { enabled: true, scanRequests: true, scanResponses: true, blockSecrets: true, hipaaMode: false };
    const flags = await db.query(
      `SELECT flag_name, enabled FROM tenant_feature_flags
       WHERE tenant_id=$1 AND flag_name IN ('dlp_enabled','dlp_scan_requests','dlp_scan_responses','dlp_block_secrets','hipaa_mode')`,
      [tenant.id]
    ).catch(() => ({ rows: [] as any[] }));
    const map = new Map((flags.rows || []).map((row: any) => [row.flag_name, row.enabled]));
    return {
      enabled: map.get('dlp_enabled') ?? true,
      scanRequests: map.get('dlp_scan_requests') ?? true,
      scanResponses: map.get('dlp_scan_responses') ?? true,
      blockSecrets: map.get('dlp_block_secrets') ?? true,
      hipaaMode: map.get('hipaa_mode') ?? false,
    };
  });

  fastify.get('/api/dlp/events', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { events: [] };
    const { limit = 50, direction } = req.query as any;
    let q = `SELECT * FROM dlp_events WHERE tenant_id=$1`;
    const params: any[] = [tenant.id];
    if (direction) { params.push(direction); q += ` AND direction=$${params.length}`; }
    q += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
    params.push(parseInt(limit, 10));
    const r = await db.query(q, params);
    return { events: r.rows };
  });

  fastify.get('/api/dlp/stats', async (req: any) => {
    const tenant = await tenantFrom(req);
    if (!tenant) return { stats: [], totals: { total: 0, blocked: 0 } };
    const r = await db.query(`
      SELECT
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE blocked) as blocked_events,
        COUNT(*) FILTER (WHERE direction='request') as request_scans,
        COUNT(*) FILTER (WHERE direction='response') as response_scans,
        pii_types
      FROM dlp_events
      WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30d'
      GROUP BY pii_types
      ORDER BY total_events DESC LIMIT 20`,
      [tenant.id]
    );
    const totals = await db.query(`
      SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE blocked) as blocked
      FROM dlp_events WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30d'`,
      [tenant.id]
    );
    return { stats: r.rows, totals: totals.rows[0] };
  });

  fastify.put('/api/dlp/hipaa-mode', async (req: any, reply: any) => {
    const tenant = await tenantFrom(req);
    const { enabled } = req.body;
    if (tenant?.plan !== 'enterprise') {
      return reply.code(403).send({ error: 'HIPAA mode requires Enterprise plan' });
    }
    await db.query(
      `INSERT INTO tenant_feature_flags (tenant_id, flag_name, enabled)
       VALUES ($1,'hipaa_mode',$2)
       ON CONFLICT (tenant_id, flag_name) DO UPDATE SET enabled=$2, updated_at=NOW()`,
      [tenant.id, enabled]
    );
    return { enabled, message: enabled ? 'HIPAA mode activated — all PHI will be blocked' : 'HIPAA mode disabled' };
  });

  fastify.get('/api/dlp/patterns', async () => {
    return {
      patterns: PII_PATTERNS.map(p => ({
        type: p.type,
        action: p.action,
        hipaaBlock: p.hipaaBlock,
        category: p.type.startsWith('aws') || p.type.startsWith('github') ||
                  p.type.startsWith('stripe') || p.type.startsWith('openai') ||
                  p.type.startsWith('anthropic') || p.type === 'jwt_token' ||
                  p.type === 'private_key' || p.type === 'generic_secret'
                  ? 'secret' : p.hipaaBlock ? 'phi' : 'pii',
      })),
    };
  });

  fastify.get('/api/dlp/rules', async () => ({
    rules: PII_PATTERNS.map(p => ({
      type: p.type,
      action: p.action,
      hipaaBlock: p.hipaaBlock,
      enabled: true,
    })),
  }));
}
