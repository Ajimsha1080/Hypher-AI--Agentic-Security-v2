const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const dashboardHtml = path.join(root, 'src', 'dashboard', 'combined.html');
const port = Number(process.env.PORT || 3005);

function sendJson(res, body, status = 200) {
  res.writeHead(status, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
  });
  res.end(JSON.stringify(body));
}

http
  .createServer((req, res) => {
    const url = new URL(req.url || '/', `http://localhost:${port}`);

    const pathname = url.pathname.replace(/\/$/, '') || '/';
    if (pathname === '/' || pathname.startsWith('/dashboard') || pathname === '/admin' || pathname === '/benchmarks') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      fs.createReadStream(dashboardHtml).pipe(res);
      return;
    }

    if (pathname === '/health/live' || pathname === '/health/ready') {
      sendJson(res, { status: 'ok', mode: 'local-dashboard' });
      return;
    }

    if (url.pathname === '/api/dashboard/metrics') {
      sendJson(res, {
        summary: {
          calls_1h: 0,
          denials_1h: 0,
          calls_24h: 0,
          denials_24h: 0,
          active_agents: 0,
          avg_latency_ms: 0,
        },
        topTools: [],
        topAgents: [],
        recentDenials: [],
        hourly: [],
      });
      return;
    }

    if (url.pathname === '/api/dashboard/audit') {
      sendJson(res, { logs: [] });
      return;
    }

    sendJson(res, { error: 'not found' }, 404);
  })
  .listen(port, '0.0.0.0', () => {
    console.log(`Dashboard local server on http://localhost:${port}/dashboard`);
  });
