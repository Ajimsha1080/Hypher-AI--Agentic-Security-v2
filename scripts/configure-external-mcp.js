const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const envPath = path.join(root, '.env');

function usage() {
  console.log([
    'Usage:',
    '  npm run mcp:configure -- --url <http://host:port/mcp> [--token <upstream-token>]',
    '',
    'Example:',
    '  npm run mcp:configure -- --url http://127.0.0.1:8080/mcp --token my-secret',
  ].join('\n'));
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return '';
  return process.argv[index + 1] || '';
}

const url = argValue('--url');
const token = argValue('--token');

if (!url || !/^https?:\/\//i.test(url)) {
  usage();
  process.exit(1);
}

const updates = {
  MOCK_UPSTREAM: 'false',
  MCP_SERVER_URL: url,
  MCP_TIMEOUT_MS: process.env.MCP_TIMEOUT_MS || '30000',
  ENABLE_DASHBOARD: 'true',
  ENABLE_WEBSOCKET: 'true',
};

if (token) {
  updates.MCP_PROXY_AUTH_TOKEN = token;
}

let env = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';

for (const [key, value] of Object.entries(updates)) {
  const line = `${key}=${value}`;
  const pattern = new RegExp(`^${key}=.*$`, 'm');
  if (pattern.test(env)) {
    env = env.replace(pattern, line);
  } else {
    env += `${env.endsWith('\n') || env.length === 0 ? '' : '\n'}${line}\n`;
  }
}

fs.writeFileSync(envPath, env);

console.log(`Configured MCP_SERVER_URL=${url}`);
console.log('Gateway will now forward approved /mcp calls to the external MCP server.');
if (!token) {
  console.log('No upstream token set. Add --token if your MCP server requires X-MCP-Proxy-Auth.');
}
