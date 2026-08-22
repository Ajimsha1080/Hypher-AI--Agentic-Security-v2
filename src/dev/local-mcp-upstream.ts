import http from 'http';

const port = parseInt(process.env.LOCAL_MCP_PORT || '8001', 10);

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return json(res, 200, { status: 'ok', upstream: 'local-mcp-upstream' });
  }

  if (req.method !== 'POST' || req.url !== '/mcp') {
    return json(res, 404, { error: 'Not found' });
  }

  let raw = '';
  req.on('data', chunk => { raw += chunk; });
  req.on('end', () => {
    try {
      const body = JSON.parse(raw || '{}');
      const id = body.id ?? null;
      const method = body.method;

      if (method === 'tools/list') {
        return json(res, 200, {
          jsonrpc: '2.0',
          id,
          result: {
            tools: [
              {
                name: 'echo',
                description: 'Echoes the provided arguments for local gateway testing',
                inputSchema: {
                  type: 'object',
                  properties: { message: { type: 'string' } },
                },
              },
            ],
          },
        });
      }

      if (method === 'tools/call') {
        const name = body.params?.name;
        const args = body.params?.arguments || {};
        return json(res, 200, {
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `${name || 'tool'}: ${JSON.stringify(args)}` }],
            isError: false,
          },
        });
      }

      return json(res, 200, {
        jsonrpc: '2.0',
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      });
    } catch (err: any) {
      return json(res, 400, {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: err.message || 'Parse error' },
      });
    }
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Local MCP upstream listening on http://127.0.0.1:${port}/mcp`);
});
