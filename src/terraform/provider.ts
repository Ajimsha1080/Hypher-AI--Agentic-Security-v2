/**
 * Terraform Provider API — NEW Enterprise Feature
 *
 * Exposes a REST API that the MCP Security Terraform provider uses
 * to manage resources as infrastructure-as-code.
 *
 * Supported resources:
 *   mcpsecurity_agent        — agent tokens and OIDC mappings
 *   mcpsecurity_policy       — RBAC policies
 *   mcpsecurity_alert_rule   — alert rules
 *   mcpsecurity_arg_rule     — tool argument rules
 *
 * The companion Terraform provider (separate HCL plugin) uses these
 * endpoints for CRUD lifecycle management.
 *
 * Usage in .tf files:
 *   resource "mcpsecurity_policy" "research_agent" {
 *     agent_id      = "agent-abc123"
 *     allowed_tools = ["read_file", "web_search", "query_database"]
 *   }
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { ensurePlanLimitSchema, enforcePlanLimit, getPlanUsage, planLimitErrorPayload, PlanLimitError } from '../billing/plan-limits';

export async function terraformPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;
  await ensurePlanLimitSchema(db);

  // ── Terraform state management ────────────────────────────────────
  // Terraform uses a backend to store state. These endpoints act as
  // a simple HTTP backend for the MCP Security provider.

  fastify.get('/api/terraform/state', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const flag = await checkTerraformAccess((req as any).tenant.id, db);
    if (!flag) return reply.code(403).send({ error: 'Terraform provider requires Enterprise plan' });

    const r = await db.query(
      `SELECT resource_type, resource_id, state_json FROM terraform_state
       WHERE tenant_id=$1 ORDER BY resource_type, resource_id`,
      [(req as any).tenant.id]
    );
    return { resources: r.rows };
  });

  // ── Agent management ──────────────────────────────────────────────

  fastify.get('/api/terraform/agents', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const r = await db.query(
      `SELECT agent_id, active, created_at FROM agent_tokens WHERE tenant_id=$1`,
      [(req as any).tenant.id]
    );
    return { agents: r.rows };
  });

  fastify.post('/api/terraform/agents', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const { agentId, description } = req.body;
    if (!agentId) return reply.code(400).send({ error: 'agentId required' });
    try {
      const usage = await getPlanUsage(db, (req as any).tenant.id);
      await enforcePlanLimit(db, {
        tenantId: (req as any).tenant.id,
        featureKey: 'agents',
        used: usage.agents,
        action: 'terraform.agent.create',
        actorEmail: String(req.headers['x-admin-email'] || 'terraform'),
      });
    } catch (err: any) {
      if (err instanceof PlanLimitError || err?.code === 'PLAN_LIMIT_EXCEEDED') {
        return reply.code(403).send(planLimitErrorPayload(err));
      }
      throw err;
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = require('bcryptjs').hashSync(rawToken, 12);

    await db.query(
      `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description)
       VALUES ($1,$2,$3,$4) ON CONFLICT (agent_id) DO NOTHING`,
      [agentId, (req as any).tenant.id, tokenHash, description || '']
    );

    await upsertTerraformState((req as any).tenant.id, 'mcpsecurity_agent', agentId, { agentId, description }, db);

    return { agentId, token: rawToken, warning: 'Store this token securely — it will not be shown again' };
  });

  fastify.delete('/api/terraform/agents/:agentId', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    await db.query(
      `UPDATE agent_tokens SET active=false WHERE agent_id=$1 AND tenant_id=$2`,
      [(req.params as any).agentId, (req as any).tenant.id]
    );
    await db.query(
      `DELETE FROM terraform_state WHERE tenant_id=$1 AND resource_type='mcpsecurity_agent' AND resource_id=$2`,
      [(req as any).tenant.id, (req.params as any).agentId]
    );
    return { deleted: true };
  });

  // ── Policy management ─────────────────────────────────────────────

  fastify.get('/api/terraform/policies', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const r = await db.query(
      `SELECT * FROM policies WHERE tenant_id=$1 AND active=true ORDER BY created_at DESC`,
      [(req as any).tenant.id]
    );
    return { policies: r.rows };
  });

  fastify.post('/api/terraform/policies', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const { agentId, allowedTools } = req.body;
    if (!agentId || !Array.isArray(allowedTools)) {
      return reply.code(400).send({ error: 'agentId and allowedTools (array) required' });
    }

    // Deactivate existing, insert new (idempotent upsert)
    await db.query(`UPDATE policies SET active=false WHERE agent_id=$1 AND tenant_id=$2`, [agentId, (req as any).tenant.id]);
    const r = await db.query(
      `INSERT INTO policies (agent_id, tenant_id, allowed_tools, active)
       VALUES ($1,$2,$3,true) RETURNING *`,
      [agentId, (req as any).tenant.id, allowedTools]
    );

    await upsertTerraformState((req as any).tenant.id, 'mcpsecurity_policy', agentId, { agentId, allowedTools }, db);
    return { policy: r.rows[0] };
  });

  fastify.put('/api/terraform/policies/:agentId', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const { allowedTools } = (req.body as any);
    await db.query(
      `UPDATE policies SET allowed_tools=$1, updated_at=NOW() WHERE agent_id=$2 AND tenant_id=$3 AND active=true`,
      [allowedTools, (req.params as any).agentId, (req as any).tenant.id]
    );
    await upsertTerraformState((req as any).tenant.id, 'mcpsecurity_policy', (req.params as any).agentId, { allowedTools }, db);
    return { updated: true };
  });

  fastify.delete('/api/terraform/policies/:agentId', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    await db.query(
      `UPDATE policies SET active=false WHERE agent_id=$1 AND tenant_id=$2`,
      [(req.params as any).agentId, (req as any).tenant.id]
    );
    await db.query(
      `DELETE FROM terraform_state WHERE tenant_id=$1 AND resource_type='mcpsecurity_policy' AND resource_id=$2`,
      [(req as any).tenant.id, (req.params as any).agentId]
    );
    return { deleted: true };
  });

  // ── Alert rule management ─────────────────────────────────────────

  fastify.post('/api/terraform/alert-rules', async (req: any, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const { name, eventType, threshold, windowSeconds, severity, channels, cooldownSeconds } = req.body;
    const r = await db.query(
      `INSERT INTO alert_rules (tenant_id, name, event_type, threshold, window_seconds, severity, channels, cooldown_seconds)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [(req as any).tenant.id, name, eventType, threshold, windowSeconds, severity, JSON.stringify(channels), cooldownSeconds || 300]
    );
    await upsertTerraformState((req as any).tenant.id, 'mcpsecurity_alert_rule', r.rows[0].id, req.body, db);
    return { rule: r.rows[0] };
  });

  fastify.delete('/api/terraform/alert-rules/:id', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    await db.query(`UPDATE alert_rules SET active=false WHERE id=$1 AND tenant_id=$2`, [(req.params as any).id, (req as any).tenant.id]);
    await db.query(`DELETE FROM terraform_state WHERE tenant_id=$1 AND resource_type='mcpsecurity_alert_rule' AND resource_id=$2`, [(req as any).tenant.id, (req.params as any).id]);
    return { deleted: true };
  });

  // ── Export current config as Terraform HCL ───────────────────────
  fastify.get('/api/terraform/export-hcl', async (req, reply) => {
    if ((req as any).tenant?.plan !== 'enterprise') {
      return reply.code(402).send({ error: 'Terraform provider requires Enterprise plan' });
    }
    const [policies, alertRules, agents] = await Promise.all([
      db.query(`SELECT * FROM policies WHERE tenant_id=$1 AND active=true`, [(req as any).tenant.id]),
      db.query(`SELECT * FROM alert_rules WHERE tenant_id=$1 AND active=true`, [(req as any).tenant.id]),
      db.query(`SELECT agent_id, description FROM agent_tokens WHERE tenant_id=$1 AND active=true`, [(req as any).tenant.id]),
    ]);

    const hcl = generateHCL(agents.rows, policies.rows, alertRules.rows);
    return { hcl };
  });
}

// ── HCL generator ─────────────────────────────────────────────────────

function generateHCL(agents: any[], policies: any[], alertRules: any[]): string {
  const lines: string[] = [
    'terraform {',
    '  required_providers {',
    '    mcpsecurity = {',
    '      source  = "antigravity/mcpsecurity"',
    '      version = "~> 2.0"',
    '    }',
    '  }',
    '}',
    '',
    'provider "mcpsecurity" {',
    '  gateway_url = var.gateway_url',
    '  api_key     = var.api_key',
    '}',
    '',
  ];

  for (const agent of agents) {
    const slug = agent.agent_id.replace(/[^a-z0-9_]/gi, '_');
    lines.push(`resource "mcpsecurity_agent" "${slug}" {`);
    lines.push(`  agent_id    = "${agent.agent_id}"`);
    if (agent.description) lines.push(`  description = "${agent.description}"`);
    lines.push('}', '');
  }

  for (const policy of policies) {
    const slug = policy.agent_id.replace(/[^a-z0-9_]/gi, '_');
    lines.push(`resource "mcpsecurity_policy" "${slug}" {`);
    lines.push(`  agent_id      = "${policy.agent_id}"`);
    lines.push(`  allowed_tools = ${JSON.stringify(policy.allowed_tools)}`);
    lines.push('}', '');
  }

  for (const rule of alertRules) {
    const slug = rule.name.replace(/[^a-z0-9_]/gi, '_').toLowerCase();
    lines.push(`resource "mcpsecurity_alert_rule" "${slug}" {`);
    lines.push(`  name             = "${rule.name}"`);
    lines.push(`  event_type       = "${rule.event_type}"`);
    lines.push(`  threshold        = ${rule.threshold}`);
    lines.push(`  window_seconds   = ${rule.window_seconds}`);
    lines.push(`  severity         = "${rule.severity}"`);
    lines.push(`  channels         = ${JSON.stringify(rule.channels)}`);
    lines.push(`  cooldown_seconds = ${rule.cooldown_seconds}`);
    lines.push('}', '');
  }

  return lines.join('\n');
}

async function checkTerraformAccess(tenantId: string, db: Pool): Promise<boolean> {
  const r = await db.query(
    `SELECT enabled FROM tenant_feature_flags WHERE tenant_id=$1 AND flag_name='terraform_provider'`,
    [tenantId]
  );
  return r.rows[0]?.enabled === true;
}

async function upsertTerraformState(
  tenantId: string, resourceType: string, resourceId: string,
  state: object, db: Pool
): Promise<void> {
  await db.query(
    `INSERT INTO terraform_state (tenant_id, resource_type, resource_id, state_json)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (tenant_id, resource_type, resource_id) DO UPDATE SET state_json=$4, updated_at=NOW()`,
    [tenantId, resourceType, resourceId, JSON.stringify(state)]
  );
}
