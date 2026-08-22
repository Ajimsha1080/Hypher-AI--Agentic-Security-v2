const http = require('http');
const os = require('os');
const fs = require('fs/promises');
const path = require('path');

const host = process.env.EXTERNAL_MCP_HOST || '127.0.0.1';
const port = Number(process.env.EXTERNAL_MCP_PORT || 8080);
const authToken = process.env.MCP_PROXY_AUTH_TOKEN || '';
const workspaceRoot = path.resolve(__dirname, '..');

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function jsonRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function isAuthorized(req) {
  if (!authToken) return true;
  return req.headers['x-mcp-proxy-auth'] === `Bearer ${authToken}`;
}

async function readBody(req) {
  let body = '';
  for await (const chunk of req) body += chunk;
  return body ? JSON.parse(body) : {};
}

function safePath(input) {
  const target = path.resolve(workspaceRoot, input || '.');
  if (target !== workspaceRoot && !target.startsWith(`${workspaceRoot}${path.sep}`)) {
    throw new Error('Path is outside the workspace');
  }
  return target;
}

async function ensureParentDirectory(target) {
  await fs.mkdir(path.dirname(target), { recursive: true });
}

async function ensureFileTarget(input) {
  const target = safePath(input);
  try {
    const stat = await fs.stat(target);
    if (!stat.isFile()) throw new Error('Path is not a file');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return target;
}

function relativePath(target) {
  return path.relative(workspaceRoot, target) || '.';
}

const tools = [
  {
    name: 'codex_status',
    description: 'Returns status information from the external Codex MCP HTTP server.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_workspace',
    description: 'Lists files and folders in the configured workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Workspace-relative path' } },
    },
  },
  {
    name: 'read_workspace_file',
    description: 'Reads a UTF-8 file from the configured workspace.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Workspace-relative file path' } },
      required: ['path'],
    },
  },
  {
    name: 'create_workspace_file',
    description: 'Creates a UTF-8 file inside the workspace. Fails if the file already exists unless overwrite is true.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative file path' },
        content: { type: 'string', description: 'File content' },
        overwrite: { type: 'boolean', description: 'Replace the file if it exists' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'edit_workspace_file',
    description: 'Replaces a UTF-8 file inside the workspace.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative file path' },
        content: { type: 'string', description: 'New file content' },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'delete_workspace_file',
    description: 'Deletes a file inside the workspace. Requires confirmDelete=true.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative file path' },
        confirmDelete: { type: 'boolean', description: 'Must be true to delete' },
      },
      required: ['path', 'confirmDelete'],
    },
  },
];

async function callTool(name, args) {
  if (name === 'codex_status') {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'ok',
          server: 'external-codex-mcp-http',
          workspaceRoot,
          platform: os.platform(),
          time: new Date().toISOString(),
        }, null, 2),
      }],
      isError: false,
    };
  }

  if (name === 'list_workspace') {
    const target = safePath(args.path || '.');
    const entries = await fs.readdir(target, { withFileTypes: true });
    return {
      content: [{
        type: 'text',
        text: entries
          .slice(0, 200)
          .map((entry) => `${entry.isDirectory() ? 'dir ' : 'file'} ${entry.name}`)
          .join('\n'),
      }],
      isError: false,
    };
  }

  if (name === 'read_workspace_file') {
    const target = safePath(args.path);
    const stat = await fs.stat(target);
    if (!stat.isFile()) throw new Error('Path is not a file');
    if (stat.size > 128 * 1024) throw new Error('File is larger than 128 KB');
    return {
      content: [{ type: 'text', text: await fs.readFile(target, 'utf8') }],
      isError: false,
    };
  }

  if (name === 'create_workspace_file') {
    const target = await ensureFileTarget(args.path);
    const exists = await fs.stat(target).then(() => true).catch((error) => {
      if (error.code === 'ENOENT') return false;
      throw error;
    });
    if (exists && !args.overwrite) throw new Error('File already exists');
    await ensureParentDirectory(target);
    await fs.writeFile(target, String(args.content ?? ''), 'utf8');
    return {
      content: [{ type: 'text', text: `created ${relativePath(target)}` }],
      isError: false,
    };
  }

  if (name === 'edit_workspace_file') {
    const target = await ensureFileTarget(args.path);
    await fs.writeFile(target, String(args.content ?? ''), 'utf8');
    return {
      content: [{ type: 'text', text: `edited ${relativePath(target)}` }],
      isError: false,
    };
  }

  if (name === 'delete_workspace_file') {
    if (args.confirmDelete !== true) throw new Error('confirmDelete=true is required');
    const target = safePath(args.path);
    const stat = await fs.stat(target);
    if (!stat.isFile()) throw new Error('Path is not a file');
    await fs.unlink(target);
    return {
      content: [{ type: 'text', text: `deleted ${relativePath(target)}` }],
      isError: false,
    };
  }

  throw new Error(`Unknown tool: ${name}`);
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', `http://${host}:${port}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      sendJson(res, 200, { status: 'ok', server: 'external-codex-mcp-http' });
      return;
    }

    if (req.method !== 'POST' || url.pathname !== '/mcp') {
      sendJson(res, 404, { error: 'Use POST /mcp' });
      return;
    }

    if (!isAuthorized(req)) {
      sendJson(res, 401, { error: 'Invalid X-MCP-Proxy-Auth token' });
      return;
    }

    const body = await readBody(req);
    const id = body.id ?? null;

    if (body.method === 'initialize') {
      sendJson(res, 200, jsonRpcResult(id, {
        protocolVersion: body.params?.protocolVersion || '2024-11-05',
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: 'external-codex-mcp-http',
          version: '1.0.0',
        },
      }));
      return;
    }

    if (body.method === 'notifications/initialized') {
      sendJson(res, 202, { ok: true });
      return;
    }

    if (body.method === 'ping') {
      sendJson(res, 200, jsonRpcResult(id, {}));
      return;
    }

    if (body.method === 'tools/list') {
      sendJson(res, 200, jsonRpcResult(id, { tools }));
      return;
    }

    if (body.method === 'tools/call') {
      const result = await callTool(body.params?.name, body.params?.arguments || {});
      sendJson(res, 200, jsonRpcResult(id, result));
      return;
    }

    sendJson(res, 200, jsonRpcError(id, -32601, `Method not found: ${body.method}`));
  } catch (error) {
    sendJson(res, 200, jsonRpcError(null, -32000, error.message));
  }
}).listen(port, host, () => {
  console.log(`External Codex MCP HTTP server listening at http://${host}:${port}/mcp`);
});
