/**
 * Audit Log Hash Chaining
 *
 * Every audit event is stored with:
 *   prev_hash = SHA-256(prev_row_hash)
 *   row_hash  = SHA-256(prev_hash || tenant_id || agent_id || tool_name || decision || created_at)
 *
 * This creates a Merkle-style chain. Any tampered row breaks the chain.
 * Verifiable by auditors using audit.verify_chain() SQL function.
 *
 * SOC 2 control: CC7.2 — Tamper-evident audit logging
 */

import { Pool } from 'pg';
import crypto from 'crypto';

export interface AuditEntry {
  tenantId: string;
  agentId: string;
  toolName: string;
  decision: 'ALLOW' | 'DENY';
  reason?: string;
  argsHash?: string;
}

/**
 * Append a new entry to the hash-chained immutable audit log.
 * Returns the row_hash of the appended entry.
 */
export async function appendHashChainedLog(
  db: Pool,
  entry: AuditEntry
): Promise<string> {
  // Get the latest row_hash for this tenant (for chain continuity)
  const prev = await db.query(
    `SELECT row_hash FROM audit.immutable_log
     WHERE tenant_id = $1
     ORDER BY seq DESC LIMIT 1`,
    [entry.tenantId]
  );

  const prevHash = prev.rows[0]?.row_hash ??
    '0000000000000000000000000000000000000000000000000000000000000000';

  const now = new Date().toISOString();

  // Compute row hash: SHA-256 of all key fields
  const rowHash = crypto
    .createHash('sha256')
    .update([prevHash, entry.tenantId, entry.agentId, entry.toolName, entry.decision, now].join('|'))
    .digest('hex');

  await db.query(
    `INSERT INTO audit.immutable_log
       (tenant_id, agent_id, tool_name, decision, reason, prev_hash, row_hash, args_hash, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz)`,
    [
      entry.tenantId, entry.agentId, entry.toolName,
      entry.decision, entry.reason ?? null, prevHash, rowHash,
      entry.argsHash ?? null, now,
    ]
  );

  return rowHash;
}

/**
 * Verify the hash chain for a tenant.
 * Returns { valid: true } or { valid: false, brokenAt: seq, detail }
 */
export async function verifyHashChain(
  db: Pool,
  tenantId: string,
  limit = 10000
): Promise<{ valid: boolean; brokenAt?: number; totalChecked: number; detail?: string }> {
  const rows = await db.query(
    `SELECT seq, prev_hash, row_hash, tenant_id, agent_id, tool_name, decision, created_at
     FROM audit.immutable_log
     WHERE tenant_id = $1
     ORDER BY seq ASC
     LIMIT $2`,
    [tenantId, limit]
  );

  if (!rows.rows.length) {
    return { valid: true, totalChecked: 0 };
  }

  let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

  for (const row of rows.rows) {
    // Check prev_hash linkage
    if (row.prev_hash !== prevHash) {
      return {
        valid: false,
        brokenAt: row.seq,
        totalChecked: rows.rows.indexOf(row),
        detail: `Chain broken at seq ${row.seq}: expected prev_hash ${prevHash.slice(0,16)}… got ${row.prev_hash.slice(0,16)}…`,
      };
    }

    // Recompute expected row_hash
    const expectedHash = crypto
      .createHash('sha256')
      .update([
        row.prev_hash, row.tenant_id, row.agent_id,
        row.tool_name, row.decision,
        new Date(row.created_at).toISOString(),
      ].join('|'))
      .digest('hex');

    if (expectedHash !== row.row_hash) {
      return {
        valid: false,
        brokenAt: row.seq,
        totalChecked: rows.rows.indexOf(row),
        detail: `Hash mismatch at seq ${row.seq}: row data may have been tampered`,
      };
    }

    prevHash = row.row_hash;
  }

  return { valid: true, totalChecked: rows.rows.length };
}
