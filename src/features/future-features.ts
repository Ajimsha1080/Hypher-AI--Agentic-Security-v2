/**
 * Future Features F4–F10 Backend
 *
 * F4:  Webhook delivery dashboard
 * F5:  Tool argument schema editor
 * F6:  API key rotation with grace period
 * F7:  Budget & cost controls per agent
 * F8:  Policy templates (community library)
 * F9:  Prompt injection visual debugger (enhanced inspection result)
 * F10: Agent behaviour ML profiling (enhanced anomaly baseline)
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { requestHasPlan, requestTenantId } from '../utils/request-context';

// ═══════════════════════════════════════════════════════
// F4: Webhook Delivery Dashboard
// ═══════════════════════════════════════════════════════

export async function webhookDeliveryPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/webhooks/deliveries — list recent webhook delivery attempts
  fastify.get('/api/webhooks/deliveries', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT wd.id, wd.rule_name, wd.event_type, wd.destination_type,
              wd.destination_url, wd.status_code AS http_status, wd.duration_ms AS response_ms,
              wd.retry_count, COALESCE(wd.delivered, wd.success, FALSE) AS delivered, wd.error_message, wd.created_at
       FROM webhook_deliveries wd
       WHERE wd.tenant_id=$1
       ORDER BY wd.created_at DESC LIMIT 100`,
      [tenantId]
    );
    const stats = {
      total: r.rows.length,
      delivered: r.rows.filter((d: any) => d.delivered).length,
      failed: r.rows.filter((d: any) => !d.delivered).length,
      avgResponseMs: Math.round(r.rows.reduce((s: number, d: any) => s + (d.response_ms || 0), 0) / (r.rows.length || 1)),
    };
    return { deliveries: r.rows, stats };
  });

  // POST /api/webhooks/retry/:deliveryId — manually retry a failed delivery
  fastify.post('/api/webhooks/retry/:deliveryId', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT * FROM webhook_deliveries WHERE id=$1 AND tenant_id=$2`,
      [(req.params as any).deliveryId, tenantId]
    );
    if (!r.rows[0]) return reply.code(404).send({ error: 'Delivery not found' });
    if (r.rows[0].delivered) return { alreadyDelivered: true };

    // Re-queue for delivery
    await db.query(
      `UPDATE webhook_deliveries SET retry_count=retry_count+1, error_message=NULL WHERE id=$1`,
      [r.rows[0].id]
    );
    return { queued: true, deliveryId: r.rows[0].id };
  });
}

// ═══════════════════════════════════════════════════════
// F5: Tool Argument Schema Editor
// ═══════════════════════════════════════════════════════

export async function argSchemaPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/arg-schema — list all rules for tenant
  fastify.get('/api/arg-schema', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT * FROM tool_arg_rules WHERE (tenant_id=$1 OR tenant_id IS NULL) AND active=TRUE
       ORDER BY tool_name, arg_key`,
      [tenantId]
    );
    return { rules: r.rows };
  });

  // POST /api/arg-schema — create or update an arg rule
  fastify.post('/api/arg-schema', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Growth features requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { toolName, argKey, allowedPattern, maxLength = 4096, required = false, description } = req.body as any;
    if (!toolName || !argKey) return reply.code(400).send({ error: 'toolName and argKey required' });

    // Test the pattern is valid regex
    if (allowedPattern) {
      try { new RegExp(allowedPattern); }
      catch { return reply.code(400).send({ error: 'Invalid regex pattern' }); }
    }

    const r = await db.query(
      `INSERT INTO tool_arg_rules (tool_name, arg_key, allowed_pattern, max_length, required, description, tenant_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (tool_name, arg_key) WHERE tenant_id=$7
       DO UPDATE SET allowed_pattern=$3, max_length=$4, required=$5, description=$6, active=TRUE
       RETURNING *`,
      [toolName, argKey, allowedPattern || null, maxLength, required, description || null, tenantId]
    );
    return { created: r.rows[0] };
  });

  // DELETE /api/arg-schema/:id
  fastify.delete('/api/arg-schema/:id', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    await db.query('UPDATE tool_arg_rules SET active=FALSE WHERE id=$1 AND tenant_id=$2', [(req.params as any).id, tenantId]);
    return { removed: true };
  });

  // POST /api/arg-schema/test — test a value against a rule pattern
  fastify.post('/api/arg-schema/test', async (req: any, reply) => {
    const { pattern, value } = req.body as any;
    try {
      const re = new RegExp(pattern);
      return { matches: re.test(value), pattern, value };
    } catch (err: any) {
      return reply.code(400).send({ error: 'Invalid pattern: ' + err.message });
    }
  });
}

// ═══════════════════════════════════════════════════════
// F6: API Key Rotation with Grace Period
// ═══════════════════════════════════════════════════════

export async function keyRotationPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // POST /api/agents/:agentId/rotate-key — generate new key, keep old active for N hours
  fastify.post('/api/agents/:agentId/rotate-key', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId } = req.params as any;
    const { gracePeriodHours = 24 } = req.body as any;

    // Verify agent belongs to tenant
    const existing = await db.query(
      'SELECT id FROM agent_tokens WHERE agent_id=$1 AND tenant_id=$2 AND active=TRUE',
      [agentId, tenantId]
    );
    if (!existing.rows.length) return reply.code(404).send({ error: 'Agent not found' });

    const newKey = 'mcpsg_' + crypto.randomBytes(32).toString('hex');
    const newKeyHash = crypto.createHash('sha256').update(newKey).digest('hex');
    const expiresAt = new Date(Date.now() + gracePeriodHours * 3600_000);

    await db.query('BEGIN');
    try {
      // Mark old key(s) as pending expiry
      await db.query(
        `UPDATE agent_tokens SET description='[rotating — expires ' || $2 || ']'
         WHERE agent_id=$1 AND tenant_id=$3 AND active=TRUE
           AND description NOT LIKE '[rotating%'`,
        [agentId, expiresAt.toISOString(), tenantId]
      );
      // Schedule old key expiry
      await db.query(
        `UPDATE agent_tokens SET expires_at=$2
         WHERE agent_id=$1 AND tenant_id=$3 AND expires_at IS NULL`,
        [agentId, expiresAt, tenantId]
      );
      // Create new key
      await db.query(
        `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description)
         VALUES ($1,$2,$3,'Rotated key — active from ' || NOW())`,
        [agentId, tenantId, newKeyHash]
      );
      await db.query('COMMIT');
    } catch (err) {
      await db.query('ROLLBACK');
      throw err;
    }

    return {
      agentId,
      newKey,   // Only shown once — client must save this
      oldKeyExpiresAt: expiresAt.toISOString(),
      gracePeriodHours,
      note: `Old key(s) will continue working until ${expiresAt.toLocaleString()}. Update your agents before then.`,
    };
  });
}

// ═══════════════════════════════════════════════════════
// F7: Budget & Cost Controls Per Agent
// ═══════════════════════════════════════════════════════

export async function budgetPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  // GET /api/budgets — list all agent budgets
  fastify.get('/api/budgets', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT ab.*, 
              (SELECT COUNT(*) FROM audit_log al
               WHERE al.tenant_id=ab.tenant_id AND al.agent_id=ab.agent_id
                 AND al.created_at >= date_trunc('month', NOW())) AS calls_this_month
       FROM agent_budgets ab WHERE ab.tenant_id=$1 ORDER BY ab.agent_id`,
      [tenantId]
    );
    return { budgets: r.rows };
  });

  // POST /api/budgets — set budget for agent
  fastify.post('/api/budgets', async (req: any, reply) => {
    if (!(await requestHasPlan(req, db, ['growth', 'enterprise']))) {
      return reply.code(402).send({ error: 'Growth features requires Growth or Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId, monthlyCallLimit, action = 'throttle' } = req.body as any;
    if (!agentId || !monthlyCallLimit) return reply.code(400).send({ error: 'agentId and monthlyCallLimit required' });
    if (!['throttle', 'require_hitl', 'block'].includes(action)) {
      return reply.code(400).send({ error: 'action must be: throttle | require_hitl | block' });
    }

    const r = await db.query(
      `INSERT INTO agent_budgets (tenant_id, agent_id, monthly_call_limit, action_on_exceed)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (tenant_id, agent_id) DO UPDATE
         SET monthly_call_limit=$3, action_on_exceed=$4, updated_at=NOW()
       RETURNING *`,
      [tenantId, agentId, monthlyCallLimit, action]
    );
    return { budget: r.rows[0] };
  });

  // DELETE /api/budgets/:agentId
  fastify.delete('/api/budgets/:agentId', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    await db.query('DELETE FROM agent_budgets WHERE agent_id=$1 AND tenant_id=$2', [(req.params as any).agentId, tenantId]);
    return { removed: true };
  });
}

// ═══════════════════════════════════════════════════════
// F8: Policy Template Library
// ═══════════════════════════════════════════════════════

export async function policyTemplatesPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  const { db } = opts;

  const BUILT_IN_TEMPLATES = [
    {
      id: 'readonly-filesystem',
      name: 'Read-only filesystem access',
      description: 'Agent can read files but cannot write, delete, or execute',
      tools: ['read_file','list_directory','search_files'],
      tags: ['filesystem','safe','starter'],
    },
    {
      id: 'db-analyst',
      name: 'Database analyst (SELECT only)',
      description: 'Agent can query the database but not modify data',
      tools: ['query_database'],
      argRules: [{ argKey: 'query', allowedPattern: '^\\s*SELECT\\s', description: 'SELECT queries only' }],
      tags: ['database','analytics','safe'],
    },
    {
      id: 'hipaa-healthcare',
      name: 'HIPAA-compliant healthcare agent',
      description: 'Strict read-only with DLP HIPAA mode and no external communication',
      tools: ['read_file','query_database'],
      features: { dlpHipaaMode: true, hitlApprovals: true },
      tags: ['hipaa','healthcare','enterprise'],
    },
    {
      id: 'devops-cicd',
      name: 'DevOps CI/CD agent',
      description: 'Pipeline automation with controlled execution rights',
      tools: ['read_file','write_file','run_command','http_request'],
      argRules: [{ argKey: 'url', allowedPattern: '^https://', description: 'HTTPS only' }],
      tags: ['devops','cicd','growth'],
    },
    {
      id: 'customer-support',
      name: 'Customer support agent',
      description: 'Read CRM, send emails, read knowledge base — no data writes',
      tools: ['read_file','http_request','send_email'],
      argRules: [{ argKey: 'method', allowedPattern: '^GET$', description: 'GET requests only' }],
      tags: ['support','saas'],
    },
  ];

  // GET /api/policy-templates — list built-in + tenant-published templates
  fastify.get('/api/policy-templates', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    const communityR = await db.query(
      `SELECT pt.* FROM policy_templates pt
       WHERE pt.public=TRUE OR pt.tenant_id=$1
       ORDER BY pt.installs DESC, pt.created_at DESC LIMIT 50`,
      [tenantId || 'none']
    ).catch(() => ({ rows: [] }));

    return {
      builtIn: BUILT_IN_TEMPLATES,
      community: communityR.rows,
    };
  });

  // POST /api/policy-templates/:templateId/apply — apply a template to an agent
  fastify.post('/api/policy-templates/:templateId/apply', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId } = req.body as any;
    if (!agentId) return reply.code(400).send({ error: 'agentId required' });

    const templateId = (req.params as any).templateId;
    const template = BUILT_IN_TEMPLATES.find(t => t.id === templateId);
    if (!template) return reply.code(404).send({ error: 'Template not found' });

    let applied = 0;
    for (const tool of template.tools) {
      await db.query(
        `INSERT INTO policies (agent_id, tool_name, action, priority, tenant_id, description)
         VALUES ($1,$2,'allow',100,$3,'Applied from template: ' || $4)
         ON CONFLICT DO NOTHING`,
        [agentId, tool, tenantId, template.name]
      );
      applied++;
    }

    return {
      applied: true,
      templateName: template.name,
      toolsGranted: template.tools,
      count: applied,
      note: template.features ? `Also enable: ${JSON.stringify(template.features)} via /api/tenant/features` : undefined,
    };
  });
}
