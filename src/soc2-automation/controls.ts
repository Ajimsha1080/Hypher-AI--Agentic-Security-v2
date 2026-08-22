/**
 * SOC 2 Type II Automation — M3-4
 *
 * Automates evidence collection for SOC 2 Type II certification.
 * Works alongside Vanta or Drata — feeds them structured evidence
 * so auditors can verify controls without manual screenshots.
 *
 * Trust Service Criteria covered:
 *   CC6.1  Logical access controls          → RBAC policies, auth logs
 *   CC6.2  Access removal on termination    → agent deactivation log
 *   CC6.3  Least privilege                  → tool allowlists per agent
 *   CC7.1  System monitoring                → anomaly detection active
 *   CC7.2  Malware protection               → injection detection logs
 *   CC8.1  Change management                → policy change audit trail
 *   A1.1   Availability monitoring          → health check uptime log
 *
 * Run evidence collection: npx ts-node src/soc2-automation/collect.ts
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import crypto from 'crypto';
import { requestHasPlan, requestTenantId } from '../utils/request-context';
import fs from 'fs';
import path from 'path';

export interface SocControl {
  id: string;            // e.g. "CC6.1"
  criterion: string;     // e.g. "Logical and Physical Access Controls"
  description: string;
  evidenceQuery: string; // SQL to pull evidence
  evidenceCount?: number;
  status: 'passing' | 'failing' | 'not_applicable' | 'collecting';
  lastCollected?: Date;
}

export interface EvidencePackage {
  controlId: string;
  tenantId: string;
  periodStart: Date;
  periodEnd: Date;
  rowCount: number;
  sha256: string;
  evidence: any[];
  collectedAt: Date;
}

// ── SOC 2 control definitions ─────────────────────────────────────────

export const SOC2_CONTROLS: SocControl[] = [
  {
    id: 'CC6.1',
    criterion: 'Logical Access Controls',
    description: 'System limits access to authorized users via RBAC policies',
    evidenceQuery: `
      SELECT agent_id, tool_name, decision, reason, created_at, auth_provider
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
        AND decision='DENY' AND reason LIKE 'policy_%'
      ORDER BY created_at DESC LIMIT 500
    `,
    status: 'collecting',
  },
  {
    id: 'CC6.2',
    criterion: 'Access Removal',
    description: 'Agent tokens deactivated when no longer needed',
    evidenceQuery: `
      SELECT agent_id, active, updated_at FROM agent_tokens
      WHERE tenant_id=$1 AND updated_at BETWEEN $2 AND $3
      ORDER BY updated_at DESC
    `,
    status: 'collecting',
  },
  {
    id: 'CC6.3',
    criterion: 'Least Privilege',
    description: 'Each agent only has access to explicitly allowed tools',
    evidenceQuery: `
      SELECT agent_id, allowed_tools, active, created_at
      FROM policies WHERE tenant_id=$1
      ORDER BY created_at DESC
    `,
    status: 'collecting',
  },
  {
    id: 'CC7.1',
    criterion: 'System Monitoring',
    description: 'Anomaly detection active — statistical baseline monitoring',
    evidenceQuery: `
      SELECT agent_id, tool_name, reason, created_at
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
        AND reason LIKE 'anomaly_%'
      ORDER BY created_at DESC
    `,
    status: 'collecting',
  },
  {
    id: 'CC7.2',
    criterion: 'Malicious Activity Detection',
    description: 'Prompt injection and malicious input blocked at inspection layer',
    evidenceQuery: `
      SELECT agent_id, tool_name, reason, inspection_result, created_at
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
        AND reason LIKE 'prompt_injection%'
      ORDER BY created_at DESC
    `,
    status: 'collecting',
  },
  {
    id: 'CC8.1',
    criterion: 'Change Management',
    description: 'All policy changes logged with timestamp, actor, and reason',
    evidenceQuery: `
      SELECT action, target_id, reason, performed_by, created_at
      FROM admin_actions
      WHERE created_at BETWEEN $2 AND $3
      ORDER BY created_at DESC
    `,
    status: 'collecting',
  },
  {
    id: 'A1.1',
    criterion: 'Availability Monitoring',
    description: 'System health checked and logged — uptime evidence',
    evidenceQuery: `
      SELECT date_trunc('hour', created_at) as hour,
             COUNT(*) as requests,
             COUNT(*) FILTER (WHERE decision='ALLOW') as allowed,
             AVG(execution_time_ms) as avg_ms
      FROM audit_log
      WHERE tenant_id=$1 AND created_at BETWEEN $2 AND $3
      GROUP BY 1 ORDER BY 1
    `,
    status: 'collecting',
  },
  {
    id: 'CC9.1',
    criterion: 'Risk Mitigation — Supply Chain',
    description: 'Third-party MCP server trust scores maintained in registry',
    evidenceQuery: `
      SELECT name, trust_level, trust_score, verified, updated_at
      FROM registry_servers WHERE active=true
      ORDER BY trust_score DESC
    `,
    status: 'collecting',
  },
];

// ── Evidence collector ─────────────────────────────────────────────────

export async function collectEvidence(
  tenantId: string,
  periodStart: Date,
  periodEnd: Date,
  db: Pool
): Promise<EvidencePackage[]> {
  const packages: EvidencePackage[] = [];

  for (const control of SOC2_CONTROLS) {
    try {
      const r = await db.query(control.evidenceQuery, [tenantId, periodStart, periodEnd]);
      const evidence = r.rows;
      const sha256 = crypto
        .createHash('sha256')
        .update(JSON.stringify(evidence))
        .digest('hex');

      packages.push({
        controlId: control.id,
        tenantId,
        periodStart,
        periodEnd,
        rowCount: evidence.length,
        sha256,
        evidence,
        collectedAt: new Date(),
      });

      // Persist to DB for audit trail
      await db.query(
        `INSERT INTO compliance_exports
           (tenant_id, export_type, date_from, date_to, row_count, file_hash, generated_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'soc2-automation')`,
        [tenantId, `soc2-${control.id}`, periodStart, periodEnd, evidence.length, sha256.slice(0, 16)]
      );
    } catch (e) {
      console.error(`[soc2] Evidence collection failed for ${control.id}:`, e);
    }
  }

  return packages;
}

// ── Vanta/Drata webhook push ───────────────────────────────────────────

export async function pushToVanta(
  packages: EvidencePackage[],
  apiKey: string
): Promise<void> {
  if (!apiKey) return;

  for (const pkg of packages) {
    const payload = {
      controlId: pkg.controlId,
      evidenceType: 'audit_log_export',
      period: { start: pkg.periodStart.toISOString(), end: pkg.periodEnd.toISOString() },
      recordCount: pkg.rowCount,
      checksum: pkg.sha256,
      collectedAt: pkg.collectedAt.toISOString(),
      source: 'mcp-security-gateway',
    };

    try {
      const { default: axios } = await import('axios');
      await axios.post('https://api.vanta.com/v1/evidence', payload, {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 15_000,
      });
      console.log(`[soc2] Pushed evidence for ${pkg.controlId} to Vanta`);
    } catch (e: any) {
      console.error(`[soc2] Vanta push failed for ${pkg.controlId}:`, e.message);
    }
  }
}

export async function pushToDrata(
  packages: EvidencePackage[],
  apiKey: string
): Promise<void> {
  if (!apiKey) return;

  for (const pkg of packages) {
    try {
      const { default: axios } = await import('axios');
      await axios.post(
        `https://public-api.drata.com/public/evidence`,
        {
          title: `MCP Security Gateway — ${pkg.controlId} Evidence`,
          description: `Automated audit evidence for SOC 2 control ${pkg.controlId}`,
          dateCollected: pkg.collectedAt.toISOString(),
          recordCount: pkg.rowCount,
          checksum: pkg.sha256,
          metadata: { controlId: pkg.controlId, period: `${pkg.periodStart.toISOString().slice(0,10)} to ${pkg.periodEnd.toISOString().slice(0,10)}` },
        },
        {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          timeout: 15_000,
        }
      );
      console.log(`[soc2] Pushed evidence for ${pkg.controlId} to Drata`);
    } catch (e: any) {
      console.error(`[soc2] Drata push failed for ${pkg.controlId}:`, e.message);
    }
  }
}

// ── Continuous monitoring — runs daily via cron ────────────────────────

export async function runDailySoc2Collection(db: Pool): Promise<void> {
  const tenants = await db.query(
    `SELECT id FROM tenants WHERE active=true AND plan='enterprise'`
  );

  const periodEnd = new Date();
  const periodStart = new Date(Date.now() - 24 * 60 * 60 * 1000); // last 24h

  for (const tenant of tenants.rows) {
    const packages = await collectEvidence(tenant.id, periodStart, periodEnd, db);

    if (process.env.VANTA_API_KEY) {
      await pushToVanta(packages, process.env.VANTA_API_KEY);
    }
    if (process.env.DRATA_API_KEY) {
      await pushToDrata(packages, process.env.DRATA_API_KEY);
    }

    console.log(`[soc2] Daily collection complete for tenant ${tenant.id}: ${packages.length} controls`);
  }
}

// ── Fastify API plugin ─────────────────────────────────────────────────

export async function soc2AutomationPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;

  // Get control status for this tenant
  fastify.get('/api/soc2/controls', async (req, reply) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SOC 2 automation requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const controls = await Promise.all(
      SOC2_CONTROLS.map(async (control) => {
        const r = await db.query(
          `SELECT COUNT(*) as cnt FROM compliance_exports
           WHERE tenant_id=$1 AND export_type=$2`,
          [tenantId, `soc2-${control.id}`]
        );
        return {
          ...control,
          evidenceQuery: undefined, // don't expose SQL
          evidenceCollected: parseInt(r.rows[0]?.cnt || '0', 10) > 0,
        };
      })
    );
    return { controls };
  });

  // Trigger evidence collection for all controls
  fastify.post('/api/soc2/collect', async (req: any, reply: any) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SOC 2 automation requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const { periodStart, periodEnd } = req.body;
    const packages = await collectEvidence(
      tenantId,
      new Date(periodStart || Date.now() - 90 * 24 * 60 * 60 * 1000),
      new Date(periodEnd || Date.now()),
      db
    );

    return {
      collected: packages.length,
      controls: packages.map(p => ({ controlId: p.controlId, rowCount: p.rowCount, sha256: p.sha256 })),
    };
  });

  // Download evidence package as JSON
  fastify.get('/api/soc2/download/:controlId', async (req: any, reply: any) => {
    if (!(await requestHasPlan(req, db, ['enterprise']))) {
      return reply.code(402).send({ error: 'SOC 2 automation requires Enterprise plan' });
    }
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });
    const { controlId } = req.params;
    const periodEnd = new Date();
    const periodStart = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

    const control = SOC2_CONTROLS.find(c => c.id === controlId);
    if (!control) return reply.code(404).send({ error: 'Unknown control' });

    const r = await db.query(control.evidenceQuery, [tenantId, periodStart, periodEnd]);

    return reply
      .type('application/json')
      .header('Content-Disposition', `attachment; filename="soc2-${controlId}-evidence.json"`)
      .send(JSON.stringify({ control: controlId, period: { start: periodStart, end: periodEnd }, evidence: r.rows }, null, 2));
  });
}
