const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const envPath = path.join(root, '.env');

function loadEnv() {
  if (!fs.existsSync(envPath)) return {};
  return Object.fromEntries(
    fs.readFileSync(envPath, 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && line.includes('='))
      .map((line) => {
        const index = line.indexOf('=');
        return [line.slice(0, index), line.slice(index + 1)];
      })
  );
}

function requestJson(url, body, token) {
  const parsed = new URL(url);
  const client = parsed.protocol === 'https:' ? https : http;
  const payload = JSON.stringify(body);
  const headers = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'X-Forwarded-By': 'mcp-security-gateway-smoke-test',
  };

  if (token) headers['X-MCP-Proxy-Auth'] = `Bearer ${token}`;

  return new Promise((resolve, reject) => {
    const req = client.request({
      method: 'POST',
      hostname: parsed.hostname,
      port: parsed.port || undefined,
      path: `${parsed.pathname}${parsed.search}`,
      headers,
      timeout: 15000,
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = data ? JSON.parse(data) : null; } catch {}
        resolve({ statusCode: res.statusCode, body: json || data });
      });
    });

    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function main() {
  const env = { ...loadEnv(), ...process.env };
  const url = env.MCP_SERVER_URL;
  if (!url || !/^https?:\/\//i.test(url)) {
    throw new Error('MCP_SERVER_URL is not configured. Run npm run mcp:configure first.');
  }

  const response = await requestJson(url, {
    jsonrpc: '2.0',
    id: 'smoke-test',
    method: 'tools/list',
    params: {},
  }, env.MCP_PROXY_AUTH_TOKEN);

  console.log(`POST ${url}`);
  console.log(`Status: ${response.statusCode}`);
  console.log(JSON.stringify(response.body, null, 2));

  if (!response.statusCode || response.statusCode >= 400) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
