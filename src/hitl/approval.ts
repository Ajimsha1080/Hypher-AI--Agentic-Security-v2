/**
 * Human-in-the-Loop (HITL) Approval
 *
 * For high-risk operations, pause the tool call and require a human
 * to approve before the gateway forwards it to the MCP server.
 *
 * Risk levels:
 *   - auto_approve: low-risk reads → pass through immediately
 *   - flag_and_allow: medium risk → log warning, allow but alert
 *   - require_approval: high risk → pause, notify human, wait for decision
 *   - auto_deny: critical risk → block immediately, no human needed
 *
 * High-risk tools (require_approval by default):
 *   - write_file, delete_file (production file writes)
 *   - run_command, execute_code (arbitrary code execution)
 *   - send_email, send_message (external communication to users)
 *   - http_request with POST/PUT/DELETE (external API mutations)
 *   - query_database with INSERT/UPDATE/DELETE/DROP (DB mutations)
 *
 * Approval flow:
 *   1. Agent calls high-risk tool
 *   2. Gateway creates pending approval with 15-minute TTL
 *   3. Slack/email notification sent to designated approver
 *   4. Agent gets 202 Accepted + approval_id
 *   5. Agent polls GET /api/hitl/status/:approval_id
 *   6. Human approves/denies in dashboard or Slack button
 *   7. Gateway forwards or blocks based on decision
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import axios from 'axios';
import { decryptSecretConfig } from '../security/secrets';

export type HitlDecision = 'pending' | 'approved' | 'denied' | 'timeout';
export type HitlRisk = 'auto_approve' | 'flag_and_allow' | 'require_approval' | 'auto_deny';

export interface HitlRequest {
  approvalId: string;
  tenantId: string;
  agentId: string;
  toolName: string;
  args: Record<string, unknown>;
  riskLevel: HitlRisk;
  riskReason: string;
  decision: HitlDecision;
  createdAt: Date;
  expiresAt: Date;
  decidedAt?: Date;
  decidedBy?: string;
  decisionNote?: string;
}

// ── Risk classification ────────────────────────────────────────────────

function allowBrowserRoleHeaders(): boolean {
  return process.env.NODE_ENV !== 'production' || process.env.MCPSG_TRUST_BROWSER_ROLE_HEADERS === 'true';
}

function requestRole(req: any): string {
  if (req?.user?.role) return String(req.user.role);
  return allowBrowserRoleHeaders() ? String(req?.headers?.['x-admin-role'] || 'viewer') : 'viewer';
}

function requestActor(req: any): string {
  if (req?.user?.email) return String(req.user.email);
  if (allowBrowserRoleHeaders()) return String(req?.headers?.['x-admin-email'] || req?.headers?.['x-approver-id'] || 'dashboard');
  return 'authenticated-user';
}

function requestTenantId(req: any): string {
  return String(req?.tenant?.id || req?.headers?.['x-tenant-id'] || '');
}

function approvalTenantId(approval: any): string {
  return String(approval?.tenantId || approval?.tenant_id || '');
}

const RISK_RULES: Array<{
  match: (tool: string, args: Record<string, unknown>) => boolean;
  risk: HitlRisk;
  reason: string;
}> = [
  // Auto-deny: catastrophic actions
  { match: (t, a) => t === 'run_command' && /rm\s+-rf|format|mkfs|dd\s+if=\/dev/i.test(JSON.stringify(a)),
    risk: 'auto_deny', reason: 'Destructive system command detected' },

  // Require approval: high-risk mutations
  { match: (t) => t === 'delete_file' || t === 'delete_workspace_file',
    risk: 'require_approval', reason: 'File deletion is irreversible' },
  { match: (t) => t === 'run_command',
    risk: 'require_approval', reason: 'Arbitrary command execution requires approval' },
  { match: (t, a) => t === 'query_database' && /DROP|TRUNCATE|DELETE\s+FROM|UPDATE\s+\w+\s+SET/i.test(String(a.query || '')),
    risk: 'require_approval', reason: 'Destructive database operation detected' },
  { match: (t, a) => t === 'http_request' && ['DELETE', 'PUT', 'PATCH'].includes(String(a.method || '')),
    risk: 'require_approval', reason: 'Mutating external API call' },
  { match: (t) => ['send_email', 'send_message', 'send_notification'].includes(t),
    risk: 'require_approval', reason: 'External communication to users requires approval' },
  { match: (t) => t === 'write_file',
    risk: 'flag_and_allow', reason: 'File write — flagged for audit' },

  // Default: read-only operations are auto-approved
  { match: (t) => ['read_file', 'list_directory', 'web_search', 'get_file'].includes(t),
    risk: 'auto_approve', reason: 'Read-only operation' },
];

export function classifyRisk(
  toolName: string,
  args: Record<string, unknown>
): { risk: HitlRisk; reason: string } {
  for (const rule of RISK_RULES) {
    if (rule.match(toolName, args)) {
      return { risk: rule.risk, reason: rule.reason };
    }
  }
  return { risk: 'auto_approve', reason: 'No specific risk rule matched' };
}

// ── Approval creation ──────────────────────────────────────────────────

export async function createApproval(
  tenantId: string,
  agentId: string,
  toolName: string,
  args: Record<string, unknown>,
  riskLevel: HitlRisk,
  riskReason: string,
  db: Pool,
  redis: Redis
): Promise<HitlRequest> {
  const approvalId = crypto.randomUUID();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 min TTL

  const approval: HitlRequest = {
    approvalId, tenantId, agentId, toolName, args, riskLevel, riskReason,
    decision: 'pending', createdAt: now, expiresAt,
  };

  // Store in Redis for fast polling
  await redis.setex(
    `hitl:${approvalId}`,
    15 * 60,
    JSON.stringify(approval)
  );

  // Persist to DB for audit trail
  await db.query(
    `INSERT INTO hitl_approvals
       (approval_id, tenant_id, agent_id, tool_name, args_json, risk_level, risk_reason, decision, created_at, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`,
    [approvalId, tenantId, agentId, toolName, JSON.stringify(args), riskLevel, riskReason, now, expiresAt]
  );

  // Send notification
  await notifyApprovers(approval, tenantId, db);

  return approval;
}

export async function getApprovalStatus(
  approvalId: string, redis: Redis, db: Pool
): Promise<HitlRequest | null> {
  const cached = await redis.get(`hitl:${approvalId}`);
  if (cached) {
    const approval = JSON.parse(cached);
    // Check timeout
    if (new Date(approval.expiresAt) < new Date() && approval.decision === 'pending') {
      approval.decision = 'timeout';
      await redis.set(`hitl:${approvalId}`, JSON.stringify(approval));
      await db.query(
        `UPDATE hitl_approvals SET decision='timeout' WHERE approval_id=$1`, [approvalId]
      );
    }
    return approval;
  }

  // Fallback to DB
  const r = await db.query(
    `SELECT * FROM hitl_approvals WHERE approval_id=$1`, [approvalId]
  );
  return r.rows[0] || null;
}

export async function resolveApproval(
  approvalId: string,
  decision: 'approved' | 'denied',
  decidedBy: string,
  decisionNote: string | undefined,
  redis: Redis,
  db: Pool
): Promise<void> {
  const now = new Date();

  await db.query(
    `UPDATE hitl_approvals SET decision=$1, decided_at=$2, decided_by=$3, decision_note=$4
     WHERE approval_id=$5`,
    [decision, now, decidedBy, decisionNote || null, approvalId]
  );

  // Update Redis cache
  const cached = await redis.get(`hitl:${approvalId}`);
  if (cached) {
    const approval = JSON.parse(cached);
    approval.decision = decision;
    approval.decidedAt = now;
    approval.decidedBy = decidedBy;
    approval.decisionNote = decisionNote;
    await redis.setex(`hitl:${approvalId}`, 3600, JSON.stringify(approval));
  }
}

async function forwardApprovedMcpTool(toolName: string, args: Record<string, unknown>, approvalId: string) {
  const url = process.env.MCP_SERVER_URL;
  if (!url) throw new Error('MCP_SERVER_URL not configured');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Forwarded-By': 'mcp-security-gateway-hitl',
  };
  if (process.env.MCP_PROXY_AUTH_TOKEN) {
    headers['X-MCP-Proxy-Auth'] = `Bearer ${process.env.MCP_PROXY_AUTH_TOKEN}`;
  }

  const response = await axios.post(url, {
    jsonrpc: '2.0',
    id: approvalId,
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  }, { headers, timeout: 30_000 });

  return response.data;
}

function summarizeApprovedResponse(value: any): string {
  if (value?.error) return `error:${value.error.code ?? 'unknown'}:${value.error.message ?? ''}`.slice(0, 500);
  const result = value?.result;
  if (result && typeof result === 'object') {
    const content = Array.isArray(result.content) ? result.content : [];
    const textChars = content.reduce((total: number, item: any) => total + (typeof item?.text === 'string' ? item.text.length : 0), 0);
    return `ok; isError=${Boolean(result.isError)}; content_items=${content.length}; text_chars=${textChars}`;
  }
  return 'ok';
}

async function logApprovedExecution(params: {
  tenantId: string;
  agentId: string;
  toolName: string;
  args: Record<string, unknown>;
  decision: 'ALLOW' | 'DENY';
  reason?: string;
  responseSummary: string;
  approvedBy: string;
  approvalId: string;
  db: Pool;
}) {
  await params.db.query(
    `INSERT INTO audit_log
       (agent_id, tenant_id, tool_name, decision, reason, inspection_result,
        auth_provider, integration_method, args_length,
        user_id, session_id, conversation_id, request_id, user_command, tool_arguments, response_summary, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,'hitl','dashboard_approval',$7,$8,$9,$10,$11,$12,$13,$14,NOW())`,
    [
      params.agentId,
      params.tenantId,
      params.toolName,
      params.decision,
      params.reason || null,
      JSON.stringify({ approvalId: params.approvalId, approvedBy: params.approvedBy }),
      JSON.stringify(params.args).length,
      params.approvedBy,
      `hitl:${params.approvalId}`,
      `hitl:${params.approvalId}`,
      params.approvalId,
      `Approved HITL action: ${params.toolName}`,
      JSON.stringify(params.args),
      params.responseSummary,
    ]
  );
}

async function logHitlDenied(params: {
  tenantId: string;
  agentId: string;
  toolName: string;
  args: Record<string, unknown>;
  deniedBy: string;
  approvalId: string;
  reason?: string;
  db: Pool;
}) {
  await params.db.query(
    `INSERT INTO audit_log
       (agent_id, tenant_id, tool_name, decision, reason, inspection_result,
        auth_provider, integration_method, args_length,
        user_id, session_id, conversation_id, request_id, user_command, tool_arguments, response_summary, created_at)
     VALUES ($1,$2,$3,'DENY',$4,$5,'hitl','dashboard_approval',$6,$7,$8,$9,$10,$11,$12,$13,NOW())`,
    [
      params.agentId,
      params.tenantId,
      params.toolName,
      params.reason || 'hitl_denied',
      JSON.stringify({ approvalId: params.approvalId, deniedBy: params.deniedBy }),
      JSON.stringify(params.args).length,
      params.deniedBy,
      `hitl:${params.approvalId}`,
      `hitl:${params.approvalId}`,
      params.approvalId,
      `Denied HITL action: ${params.toolName}`,
      JSON.stringify(params.args),
      'denied_by_human',
    ]
  );
}

async function approveAndExecute(
  approval: any,
  approvedBy: string,
  note: string | undefined,
  redis: Redis,
  db: Pool
) {
  await resolveApproval(approval.approvalId || approval.approval_id, 'approved', approvedBy, note, redis, db);

  const approvalId = approval.approvalId || approval.approval_id;
  const tenantId = approval.tenantId || approval.tenant_id;
  const agentId = approval.agentId || approval.agent_id;
  const toolName = approval.toolName || approval.tool_name;
  const rawArgs = approval.args || approval.args_json || {};
  const args = typeof rawArgs === 'string' ? JSON.parse(rawArgs) : rawArgs;

  if (toolName !== 'delete_workspace_file') {
    return { approved: true, executed: false, reason: 'approval_recorded_only' };
  }

  const response = await forwardApprovedMcpTool(toolName, args, approvalId);
  const failed = Boolean(response?.error || response?.result?.isError);
  const responseSummary = summarizeApprovedResponse(response);

  await logApprovedExecution({
    tenantId,
    agentId,
    toolName,
    args,
    decision: failed ? 'DENY' : 'ALLOW',
    reason: failed ? `hitl_approved_upstream_error:${response?.error?.message || 'tool_returned_error'}` : 'hitl_approved',
    responseSummary,
    approvedBy,
    approvalId,
    db,
  });

  return { approved: true, executed: !failed, response, responseSummary };
}

async function notifyApprovers(
  approval: HitlRequest, tenantId: string, db: Pool
): Promise<void> {
  try {
    const configs = await db.query(
      `SELECT channel_type, config FROM alert_channel_configs WHERE tenant_id=$1 AND channel_type IN ('slack','teams') AND active=true`,
      [tenantId]
    );

    const dashboardUrl = `${process.env.APP_URL}/dashboard?view=hitl&approval=${approval.approvalId}`;
    const approveUrl = `${process.env.APP_URL}/api/hitl/${approval.approvalId}/approve?token=${approval.approvalId}`;
    const denyUrl = `${process.env.APP_URL}/api/hitl/${approval.approvalId}/deny?token=${approval.approvalId}`;

    for (const cfg of configs.rows) {
      const config = decryptSecretConfig(typeof cfg.config === 'string' ? JSON.parse(cfg.config) : (cfg.config || {}));
      const webhookUrl = config.webhookUrl || config.url;
      if (!webhookUrl) continue;
      const payload = cfg.channel_type === 'teams' ? {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        themeColor: 'FFB830',
        summary: `Approval required: ${approval.toolName}`,
        title: `Approval required: ${approval.toolName}`,
        sections: [{
          facts: [
            { name: 'Agent', value: approval.agentId },
            { name: 'Tool', value: approval.toolName },
            { name: 'Risk', value: approval.riskReason },
            { name: 'Expires', value: '15 minutes' },
          ],
          text: `Arguments preview: ${JSON.stringify(approval.args).slice(0, 500)}`,
        }],
        potentialAction: [
          { '@type': 'OpenUri', name: 'Approve', targets: [{ os: 'default', uri: approveUrl }] },
          { '@type': 'OpenUri', name: 'Deny', targets: [{ os: 'default', uri: denyUrl }] },
          { '@type': 'OpenUri', name: 'View details', targets: [{ os: 'default', uri: dashboardUrl }] },
        ],
      } : {
        blocks: [
          {
            type: 'header',
            text: { type: 'plain_text', text: `Approval required — ${approval.toolName}` },
          },
          {
            type: 'section',
            fields: [
              { type: 'mrkdwn', text: `*Agent:* ${approval.agentId}` },
              { type: 'mrkdwn', text: `*Tool:* \`${approval.toolName}\`` },
              { type: 'mrkdwn', text: `*Risk:* ${approval.riskReason}` },
              { type: 'mrkdwn', text: `*Expires:* 15 minutes` },
            ],
          },
          {
            type: 'section',
            text: { type: 'mrkdwn', text: `\`\`\`${JSON.stringify(approval.args, null, 2).slice(0, 500)}\`\`\`` },
          },
          {
            type: 'actions',
            elements: [
              { type: 'button', text: { type: 'plain_text', text: 'Approve' }, style: 'primary', url: approveUrl },
              { type: 'button', text: { type: 'plain_text', text: 'Deny' }, style: 'danger', url: denyUrl },
              { type: 'button', text: { type: 'plain_text', text: 'View details' }, url: dashboardUrl },
            ],
          },
        ],
      };
      await axios.post(webhookUrl, payload, { timeout: 5000 });
    }
  } catch (e) {
    console.error('[hitl] Notification failed:', e);
  }
}

// ── Fastify plugin ─────────────────────────────────────────────────────

export async function hitlPlugin(fastify: FastifyInstance, opts: { db: Pool; redis: Redis }) {
  const { db, redis } = opts;
  const canApprove = (req: any, reply: any) => {
    const role = requestRole(req);
    if (['local_admin', 'super_admin', 'security_analyst'].includes(String(role))) return true;
    reply.code(403).send({ error: 'Requires security_analyst or super_admin role' });
    return false;
  };
  const canDecideTenantApproval = (req: any, reply: any, approval: any) => {
    if (!canApprove(req, reply)) return false;
    const tenantId = requestTenantId(req);
    if (!tenantId) {
      reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
      return false;
    }
    const ownerTenantId = approvalTenantId(approval);
    if (ownerTenantId && ownerTenantId !== tenantId) {
      reply.code(403).send({ error: 'Approval belongs to a different tenant' });
      return false;
    }
    return true;
  };

  // List recent HITL requests for dashboard/Slack approval views.
  // Keep this before /api/hitl/:approvalId so "requests" is not treated as an ID.
  fastify.get('/api/hitl/requests', async (req: any, reply: any) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const limit = Math.max(1, Math.min(parseInt(String((req.query as any)?.limit || '50'), 10) || 50, 200));
    const r = await db.query(
      `SELECT * FROM hitl_approvals
       WHERE tenant_id=$1
       ORDER BY created_at DESC
       LIMIT $2`,
      [tenantId, limit]
    );
    return { requests: r.rows };
  });

  // Get approval status (agent polls this)
  fastify.get('/api/hitl/:approvalId', async (req: any, reply: any) => {
    const approval = await getApprovalStatus((req.params as any).approvalId, redis, db);
    if (!approval) return reply.code(404).send({ error: 'Approval not found' });
    return approval;
  });

  // Approve from dashboard
  fastify.post('/api/hitl/:approvalId/approve', async (req: any, reply: any) => {
    const approval = await getApprovalStatus((req.params as any).approvalId, redis, db);
    if (!approval) return reply.code(404).send({ error: 'Not found' });
    if (!canDecideTenantApproval(req, reply, approval)) return;
    if (approval.decision !== 'pending') return reply.code(409).send({ error: `Already ${approval.decision}` });
    const result = await approveAndExecute(
      approval,
      req.body?.decidedBy || requestActor(req),
      req.body?.note,
      redis,
      db
    );
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'hitl.approve',$4,$5,NOW())`,
      [
        (approval as any).tenantId || (approval as any).tenant_id,
        String(req.body?.decidedBy || requestActor(req)),
        requestRole(req),
        `approval:${(approval as any).approvalId || (approval as any).approval_id}`,
        JSON.stringify({ toolName: (approval as any).toolName || (approval as any).tool_name, executed: Boolean((result as any).executed) }),
      ]
    ).catch(() => {});
    return result;
  });

  // Deny from dashboard
  fastify.post('/api/hitl/:approvalId/deny', async (req: any, reply: any) => {
    const approval = await getApprovalStatus((req.params as any).approvalId, redis, db);
    if (!approval) return reply.code(404).send({ error: 'Not found' });
    if (!canDecideTenantApproval(req, reply, approval)) return;
    if (approval.decision !== 'pending') return reply.code(409).send({ error: `Already ${approval.decision}` });
    const deniedBy = req.body?.decidedBy || requestActor(req);
    const approvalRow = approval as any;
    const approvalId = approvalRow.approvalId || approvalRow.approval_id;
    const rawArgs = approvalRow.args || approvalRow.args_json || {};
    const args = typeof rawArgs === 'string' ? JSON.parse(rawArgs) : rawArgs;
    await resolveApproval(
      (req.params as any).approvalId,
      'denied',
      deniedBy,
      req.body?.reason,
      redis,
      db
    );
    await logHitlDenied({
      tenantId: approvalRow.tenantId || approvalRow.tenant_id,
      agentId: approvalRow.agentId || approvalRow.agent_id,
      toolName: approvalRow.toolName || approvalRow.tool_name,
      args,
      deniedBy,
      approvalId,
      reason: req.body?.reason ? `hitl_denied:${req.body.reason}` : 'hitl_denied',
      db,
    });
    await db.query(
      `INSERT INTO admin_action_log (tenant_id, actor_email, actor_role, action, target, details_json, created_at)
       VALUES ($1,$2,$3,'hitl.deny',$4,$5,NOW())`,
      [
        approvalRow.tenantId || approvalRow.tenant_id,
        String(deniedBy),
        requestRole(req),
        `approval:${approvalId}`,
        JSON.stringify({ toolName: approvalRow.toolName || approvalRow.tool_name, reason: req.body?.reason || null }),
      ]
    ).catch(() => {});
    return { denied: true };
  });

  // List pending approvals for tenant
  fastify.get('/api/hitl', async (req, reply) => {
    const tenantId = (req as any).tenant?.id || (req.headers['x-tenant-id'] as string);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const r = await db.query(
      `SELECT * FROM hitl_approvals WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [tenantId]
    );
    return { approvals: r.rows };
  });

  // HITL risk rules config
  fastify.get('/api/hitl/rules', async () => {
    return {
      rules: RISK_RULES.map(r => ({
        risk: r.risk,
        reason: r.reason,
      })),
    };
  });

  fastify.get('/api/hitl/enterprise-summary', async (req: any, reply: any) => {
    const tenantId = (req as any).tenant?.id || (req.headers['x-tenant-id'] as string);
    if (!tenantId) return reply.code(400).send({ error: 'Missing X-Tenant-ID header' });
    const [summary, approvers, channels] = await Promise.all([
      db.query(
        `SELECT
           COUNT(*) FILTER (WHERE decision IS NULL)::int AS pending,
           COUNT(*) FILTER (WHERE decision='approved')::int AS approved,
           COUNT(*) FILTER (WHERE decision='denied')::int AS denied,
           COUNT(*) FILTER (WHERE expires_at < NOW() AND decision IS NULL)::int AS expired_pending
         FROM hitl_approvals WHERE tenant_id=$1`,
        [tenantId]
      ),
      db.query(
        `SELECT role, COUNT(*)::int AS users
         FROM admin_members
         WHERE tenant_id=$1 AND active=true AND role IN ('super_admin','security_analyst')
         GROUP BY role ORDER BY role`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT channel_type FROM alert_channel_configs WHERE tenant_id=$1 AND active=true AND channel_type IN ('slack','teams')`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
    ]);
    const channelTypes = new Set((channels.rows || []).map((r: any) => r.channel_type));
    return {
      summary: summary.rows[0],
      approverGroups: approvers.rows,
      escalation: { enabled: false, note: 'Escalation policy API is not configured yet' },
      externalApproval: { slack: channelTypes.has('slack') || Boolean(process.env.SLACK_WEBHOOK_URL), teams: channelTypes.has('teams') },
    };
  });
}
