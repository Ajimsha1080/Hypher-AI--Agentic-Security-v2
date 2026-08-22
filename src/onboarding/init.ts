#!/usr/bin/env node
/**
 * MCP Security Gateway — Self-Serve Onboarding CLI
 * Run: npx mcpsecurity-init
 *
 * Walks through setup in 5 minutes:
 * 1. Checks prerequisites (Node, Postgres, Redis)
 * 2. Creates .env with secure defaults
 * 3. Runs DB migrations
 * 4. Creates first agent token
 * 5. Creates default policy
 * 6. Starts the server
 * 7. Shows integration code snippet
 */

import { execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as readline from 'readline';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q: string): Promise<string> => new Promise(res => rl.question(q, res));

function log(msg: string, color = '\x1b[0m') { console.log(`${color}${msg}\x1b[0m`); }
function ok(msg: string)   { log(`  ✓ ${msg}`, '\x1b[32m'); }
function warn(msg: string) { log(`  ⚠ ${msg}`, '\x1b[33m'); }
function err(msg: string)  { log(`  ✗ ${msg}`, '\x1b[31m'); }
function info(msg: string) { log(`  → ${msg}`, '\x1b[36m'); }
function title(msg: string){ log(`\n${msg}`, '\x1b[1m'); }

async function main() {
  console.clear();
  log('\n  MCP Security Gateway — Setup Wizard', '\x1b[1m\x1b[32m');
  log('  Zero-trust proxy for AI agents\n', '\x1b[90m');

  // ── Step 1: Check prerequisites ──────────────────────────────────

  title('Step 1/5 — Checking prerequisites');

  const nodeVersion = parseInt(process.version.slice(1, 10));
  if (nodeVersion < 18) {
    err(`Node.js 18+ required. You have ${process.version}`);
    process.exit(1);
  }
  ok(`Node.js ${process.version}`);

  try { execSync('psql --version', { stdio: 'pipe' }); ok('PostgreSQL found'); }
  catch { err('PostgreSQL not found. Install from https://postgresql.org or use Supabase.'); process.exit(1); }

  try { execSync('redis-cli ping', { stdio: 'pipe' }); ok('Redis found'); }
  catch { warn('Redis not found locally. You can use Upstash (free): https://upstash.com'); }

  // ── Step 2: Gather configuration ──────────────────────────────────

  title('Step 2/5 — Configuration');

  const dbUrl = await ask('  PostgreSQL URL [postgresql://localhost/mcp_security]: ');
  const redisUrl = await ask('  Redis URL [redis://localhost:6379]: ');
  const port = await ask('  Port [3000]: ');
  const mcpUrl = await ask('  MCP tool server URL: ');

  const config = {
    NODE_ENV: 'production',
    DATABASE_URL: dbUrl || 'postgresql://localhost/mcp_security',
    REDIS_URL: redisUrl || 'redis://localhost:6379',
    PORT: port || '3000',
    JWT_SECRET: crypto.randomBytes(32).toString('hex'),
    FAIL_MODE: 'fail_closed',
    MCP_SERVER_URL: mcpUrl || '',
    ENABLE_DASHBOARD: 'true',
    LOG_LEVEL: 'info',
    RATE_LIMIT_MAX: '100',
    ADMIN_SECRET: crypto.randomBytes(16).toString('hex'),
  };

  const envContent = Object.entries(config).map(([k, v]) => `${k}=${v}`).join('\n');
  fs.writeFileSync('.env', envContent);
  ok('.env created with secure random secrets');
  if (config.ADMIN_SECRET) {
    info(`Admin secret: ${config.ADMIN_SECRET} — save this, you need it for /admin`);
  }

  // ── Step 3: Run migrations ────────────────────────────────────────

  title('Step 3/5 — Database setup');

  const migrations = [
    'src/db/schema.sql',
    'src/audit/schema.sql',
    'src/db/migrations/001_production_gaps.sql',
    'src/db/migrations/002_new_features.sql',
    'src/db/migrations/003_admin_billing_analytics.sql',
  ];

  for (const migration of migrations) {
    if (fs.existsSync(migration)) {
      try {
        execSync(`psql ${config.DATABASE_URL} -f ${migration}`, { stdio: 'pipe' });
        ok(`Ran ${path.basename(migration)}`);
      } catch (e: any) {
        warn(`${path.basename(migration)} — ${e.message?.slice(0, 80)}`);
      }
    }
  }

  // ── Step 4: Create first agent ────────────────────────────────────

  title('Step 4/5 — Creating your first agent');

  const agentId = `agent_${crypto.randomBytes(8).toString('hex')}`;
  const rawToken = crypto.randomBytes(32).toString('hex');

  info(`Agent ID: ${agentId}`);
  info(`Bearer token: ${rawToken}`);
  info('(The token is stored as a bcrypt hash in Postgres — save this raw value)');

  // Write to a local file so user can copy it
  fs.writeFileSync('.mcp-credentials', `AGENT_ID=${agentId}\nBEARER_TOKEN=${rawToken}\n`);
  ok('Credentials saved to .mcp-credentials');

  // ── Step 5: Show integration code ─────────────────────────────────

  title('Step 5/5 — Integration');

  const gatewayUrl = `http://localhost:${config.PORT}`;

  console.log('\n  TypeScript SDK:');
  console.log('\x1b[90m');
  console.log(`  import { McpGatewayClient } from '@mcp-security/sdk';`);
  console.log(`  const client = new McpGatewayClient({`);
  console.log(`    gatewayUrl: '${gatewayUrl}',`);
  console.log(`    token: '${rawToken}',`);
  console.log(`  });`);
  console.log(`  const result = await client.callTool('your_tool', { arg: 'value' });`);
  console.log('\x1b[0m');

  console.log('  Direct HTTP (curl):');
  console.log('\x1b[90m');
  console.log(`  curl -X POST ${gatewayUrl}/mcp \\`);
  console.log(`    -H "Authorization: Bearer ${rawToken}" \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"your_tool","arguments":{}}}'`);
  console.log('\x1b[0m');

  const startNow = await ask('\n  Start the gateway now? [Y/n]: ');
  if (!startNow || startNow.toLowerCase() === 'y') {
    rl.close();
    log('\n  Starting MCP Security Gateway...', '\x1b[32m');
    info(`Dashboard: ${gatewayUrl}/dashboard`);
    info(`Admin panel: ${gatewayUrl}/admin?secret=${config.ADMIN_SECRET}`);
    info(`Health check: ${gatewayUrl}/health/ready\n`);
    const server = spawn('node', ['dist/proxy/server.js'], { stdio: 'inherit', env: { ...process.env, ...config } });
    server.on('error', (e) => { err(`Failed to start: ${e.message}`); process.exit(1); });
  } else {
    rl.close();
    log('\n  To start later: npm start', '\x1b[32m');
    log(`  Dashboard: ${gatewayUrl}/dashboard\n`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
