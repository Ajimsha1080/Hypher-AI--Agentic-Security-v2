/**
 * db/run-migrations.ts — FIX: package.json only ran migration 001.
 * Now runs all 4 migrations in sequence.
 */
import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';

const DB_URL = process.env.DATABASE_URL;
if (!DB_URL) { console.error('DATABASE_URL not set'); process.exit(1); }

const migrations = [
  'src/db/migrations/001_production_gaps.sql',
  'src/db/migrations/002_new_features.sql',
  'src/db/migrations/003_admin_billing_analytics.sql',
  'src/db/migrations/004_v2_fixes.sql',
];

let ran = 0, skipped = 0, failed = 0;
for (const m of migrations) {
  const path = join(process.cwd(), m);
  if (!existsSync(path)) { console.log(`  SKIP ${m} (not found)`); skipped++; continue; }
  try {
    execSync(`psql "${DB_URL}" -f "${path}"`, { stdio: 'inherit' });
    console.log(`  OK   ${m}`);
    ran++;
  } catch (e: any) {
    console.error(`  FAIL ${m}: ${e.message?.slice(0, 100)}`);
    failed++;
  }
}
console.log(`\nMigrations: ${ran} ran, ${skipped} skipped, ${failed} failed`);
if (failed > 0) process.exit(1);
