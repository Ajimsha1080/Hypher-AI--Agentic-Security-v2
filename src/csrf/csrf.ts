/**
 * CSRF Protection — NEW (was entirely missing from v1)
 * Double-submit cookie pattern for browser-facing endpoints.
 * Machine-to-machine calls (Bearer + X-Agent-ID) are exempt.
 */
import { FastifyInstance } from 'fastify';
import crypto from 'crypto';

const CSRF_COOKIE = 'mcpsg_csrf';
const CSRF_HEADER = 'x-csrf-token';
const EXEMPT = new Set(['/mcp', '/api/agent/tool-call', '/health/live', '/health/ready', '/api/billing/webhook']);

export async function csrfPlugin(fastify: FastifyInstance) {
  // Issue token
  fastify.get('/api/auth/csrf', async (req, reply) => {
    const token = crypto.randomBytes(32).toString('hex');
    (reply as any).setCookie(CSRF_COOKIE, token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 3600,
    });
    return { csrfToken: token };
  });

  // Validate on mutating requests
  fastify.addHook('preHandler', async (req, reply) => {
    if (!['POST','PUT','PATCH','DELETE'].includes(req.method)) return;
    if (EXEMPT.has(req.url.split('?')[0])) return;
    // M2M calls carry both Bearer token and X-Agent-ID
    if (req.headers.authorization?.startsWith('Bearer ') && req.headers['x-agent-id']) return;

    const cookieToken = ((req as any).cookies)?.[CSRF_COOKIE];
    const headerToken = req.headers[CSRF_HEADER] as string;
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return reply.code(403).send({ error: 'CSRF validation failed' });
    }
  });
}
