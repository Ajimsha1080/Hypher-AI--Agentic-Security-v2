require('dotenv/config');

const crypto = require('crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

function argValue(name, fallback = '') {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  return process.argv[index + 1] || fallback;
}

async function main() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not set in .env');
  }

  const tenantName = argValue('--tenant-name', 'Local Dev Tenant');
  const billingEmail = argValue('--email', 'local@example.com');
  const agentId = argValue('--agent-id', `agent_${crypto.randomBytes(6).toString('hex')}`);
  const allowedTools = argValue('--tools', '*').split(',').map((tool) => tool.trim()).filter(Boolean);
  const tenantId = crypto.randomUUID();
  const apiKey = `mcpsg_${crypto.randomBytes(32).toString('hex')}`;
  const apiKeyHash = await bcrypt.hash(apiKey, 12);
  const tenantApiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');

  const db = new Pool({ connectionString: process.env.DATABASE_URL });

  try {
    await db.query('BEGIN');

    await db.query(
      `INSERT INTO tenants
         (id, name, plan, billing_email, api_calls_limit, agents_limit, api_key_hash, active)
       VALUES ($1, $2, 'enterprise', $3, 1000000, 200, $4, true)`,
      [tenantId, tenantName, billingEmail, tenantApiKeyHash]
    );

    await db.query(
      `INSERT INTO agent_tokens (agent_id, tenant_id, token_hash, description, active)
       VALUES ($1, $2, $3, 'Local external MCP test agent', true)`,
      [agentId, tenantId, apiKeyHash]
    );

    await db.query(
      `INSERT INTO policies (agent_id, tenant_id, tool_name, action, allowed_tools, active, description)
       VALUES ($1, $2, '*', 'allow', $3, true, 'Local external MCP test policy')`,
      [agentId, tenantId, allowedTools]
    );

    await db.query('COMMIT');

    console.log('Created local MCP gateway credentials:');
    console.log(`TENANT_ID=${tenantId}`);
    console.log(`AGENT_ID=${agentId}`);
    console.log(`AGENT_API_KEY=${apiKey}`);
    console.log(`ALLOWED_TOOLS=${allowedTools.join(',')}`);
    console.log('');
    console.log('Use these values in your /mcp call. The API key is only printed once.');
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await db.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
