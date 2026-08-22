#!/usr/bin/env ts-node
/**
 * Migration runner v3.0.0
 * Runs all schemas and migrations in order, idempotently.
 */

import 'dotenv/config';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import path from 'path';

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) {
  console.error('DATABASE_URL not set');
  process.exit(1);
}

function psqlBinary(): string {
  const candidates = [
    process.env.PSQL_BIN,
    'psql',
    'C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe',
    'C:\\Program Files\\PostgreSQL\\15\\bin\\psql.exe',
    'C:\\Program Files\\PostgreSQL\\14\\bin\\psql.exe',
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ['--version'], { stdio: 'pipe' });
      return candidate;
    } catch {
      // Try the next candidate.
    }
  }

  console.error('psql not found. Set PSQL_BIN to your psql executable path.');
  process.exit(1);
}

const PSQL = psqlBinary();

const migrations = [
  'src/db/schema.sql',
  'src/audit/schema.sql',
  'src/db/migrations/001_production_gaps.sql',
  'src/db/migrations/002_new_features.sql',
  'src/db/migrations/003_admin_billing_analytics.sql',
  'src/db/migrations/004_v2_enterprise.sql',
  'src/db/migrations/004_v2_fixes.sql',
  'src/db/migrations/005_immediate_features.sql',
  'src/db/migrations/005_roadmap_m1_m6.sql',
  'src/db/migrations/006_sprint3_4_enterprise.sql',
  'src/db/migrations/007_future_features.sql',
  'src/db/migrations/008_ml_anomaly.sql',
  'src/db/migrations/009_f11_f20_features.sql',
  'src/db/migrations/010_command_audit_timeline.sql',
  'src/db/migrations/011_prompt_audit_settings.sql',
  'src/db/migrations/012_plan_limits_enterprise.sql',
  'src/db/migrations/013_tenant_tool_arg_rules.sql',
  'src/db/migrations/014_policy_allowed_tools.sql',
  'src/db/migrations/015_ucp_protection.sql',
  'src/db/migrations/016_secure_agent_runtime.sql',
];

console.log('Running MCP Security Gateway database migrations...\n');
console.log(`Using psql: ${PSQL}\n`);

let ran = 0;
for (const migration of migrations) {
  const file = path.join(process.cwd(), migration);
  if (!existsSync(file)) {
    console.warn(`  ! Skipped (not found): ${path.basename(migration)}`);
    continue;
  }
  try {
    execFileSync(PSQL, ['-v', 'ON_ERROR_STOP=1', '-f', file, DB_URL], { stdio: 'pipe' });
    console.log(`  OK ${path.basename(migration)}`);
    ran++;
  } catch (e: any) {
    const stderr = e.stderr?.toString() || e.message || '';
    console.error(`  FAIL ${path.basename(migration)}: ${stderr.slice(0, 800)}`);
    process.exit(1);
  }
}

console.log(`\nDone - ran ${ran}/${migrations.length} migrations.`);
