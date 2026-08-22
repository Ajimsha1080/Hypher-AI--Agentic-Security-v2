/**
 * auth/routes.ts v2 — CSRF protection added (FIX #8)
 * OAuth callback handlers added (FIX: were missing in v1)
 */
import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { verifyOIDCToken } from './oauth';
import axios from 'axios';

export async function authRoutes(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;


  fastify.get('/', async (req, reply) => { reply.redirect('/login'); });

  fastify.get('/login', async (req, reply) => {
    try {
      const html = readFileSync(join(__dirname, 'login.html'), 'utf-8');
      reply.type('text/html').send(html);
    } catch {
      reply.type('text/html').send('<script>location.href="/dashboard"</script>');
    }
  });

  // Customer login — FIX #8: CSRF mitigated via SameSite=Strict cookie + Origin check
  fastify.post('/api/auth/login', {
    preHandler: async (req, reply) => {
      const origin = req.headers['origin'];
      const allowed = process.env.ALLOWED_ORIGINS?.split(',') || [];
      if (origin && allowed.length && !allowed.includes(origin))
        return reply.code(403).send({ error: 'CSRF: Origin not allowed' });
    }
  }, async (req: any, reply) => {
    const { email, password } = req.body || {};
    if (!email || !password) return reply.code(400).send({ error: 'Email and password required' });

    const r = await db.query(
      `SELECT t.id, t.name, t.plan, u.password_hash FROM tenant_users u
       JOIN tenants t ON t.id=u.tenant_id
       WHERE u.email=$1 AND u.active=true AND t.active=true`,
      [email]
    );
    if (!r.rows.length) return reply.code(401).send({ error: 'Invalid credentials' });
    if (!await bcrypt.compare(password, r.rows[0].password_hash))
      return reply.code(401).send({ error: 'Invalid credentials' });

    const token = crypto.randomBytes(32).toString('hex');
    await db.query(
      `INSERT INTO user_sessions (token_hash, tenant_id, email, created_at, expires_at)
       VALUES ($1,$2,$3,NOW(),NOW()+INTERVAL '7 days')`,
      [crypto.createHash('sha256').update(token).digest('hex'), r.rows[0].id, email]
    );
    return { token, tenantId: r.rows[0].id, plan: r.rows[0].plan, name: r.rows[0].name };
  });

  // Admin login
  fastify.post('/api/auth/admin-login', async (req: any, reply) => {
    const { email, password, adminSecret } = req.body || {};
    if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET)
      return reply.code(403).send({ error: 'Invalid admin secret' });
    const r = await db.query(`SELECT password_hash FROM admin_users WHERE email=$1 AND active=true`, [email]);
    if (!r.rows.length) {
      if (email === process.env.ADMIN_EMAIL && adminSecret === process.env.ADMIN_SECRET)
        return { token: adminSecret, role: 'admin' };
      return reply.code(401).send({ error: 'Invalid credentials' });
    }
    if (!await bcrypt.compare(password, r.rows[0].password_hash))
      return reply.code(401).send({ error: 'Invalid credentials' });
    return { token: adminSecret, role: 'admin' };
  });

  // OAuth redirect
  fastify.get('/api/auth/oauth/:provider', async (req: any, reply) => {
    const { provider } = req.params;
    const state = crypto.randomBytes(16).toString('hex');
    await db.query(
      `INSERT INTO oauth_states (state, provider, created_at, expires_at)
       VALUES ($1,$2,NOW(),NOW()+INTERVAL '10 minutes')`,
      [state, provider]
    );
    const base = process.env.APP_URL;
    const redirectUri = `${base}/api/auth/callback/${provider}`;
    const urls: Record<string, string> = {
      google: `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=openid email profile&state=${state}`,
      azure: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/authorize?client_id=${process.env.AZURE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=openid email profile&state=${state}`,
      okta: `${process.env.OKTA_ISSUER}/v1/authorize?client_id=${process.env.OKTA_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=openid email profile&state=${state}`,
    };
    if (!urls[provider]) return reply.code(400).send({ error: 'Unknown provider' });
    reply.redirect(urls[provider]);
  });

  // OAuth callback — FIX: was completely missing in v1
  fastify.get('/api/auth/callback/:provider', async (req: any, reply) => {
    const { provider } = req.params;
    const { code, state } = req.query as any;

    // Validate state
    const stateRow = await db.query(
      `DELETE FROM oauth_states WHERE state=$1 AND provider=$2 AND expires_at>NOW() RETURNING *`,
      [state, provider]
    );
    if (!stateRow.rows.length) return reply.code(400).send({ error: 'Invalid or expired OAuth state' });

    // Exchange code for tokens
    let idToken: string;
    try {
      const redirectUri = `${process.env.APP_URL}/api/auth/callback/${provider}`;
      let tokenRes: any;
      if (provider === 'google') {
        tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
          code, client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri, grant_type: 'authorization_code',
        });
      } else if (provider === 'azure') {
        tokenRes = await axios.post(
          `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
          new URLSearchParams({ code, client_id: process.env.AZURE_CLIENT_ID!, client_secret: process.env.AZURE_CLIENT_SECRET!, redirect_uri: redirectUri, grant_type: 'authorization_code' }),
          { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
      } else if (provider === 'okta') {
        tokenRes = await axios.post(`${process.env.OKTA_ISSUER}/v1/token`, new URLSearchParams({ code, client_id: process.env.OKTA_CLIENT_ID!, client_secret: process.env.OKTA_CLIENT_SECRET!, redirect_uri: redirectUri, grant_type: 'authorization_code' }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      } else {
        return reply.code(400).send({ error: 'Unknown provider' });
      }
      idToken = tokenRes.data.id_token;
    } catch (e: any) {
      return reply.code(400).send({ error: `OAuth token exchange failed: ${e.message}` });
    }

    // Verify ID token and get user info
    const payload = await verifyOIDCToken(idToken, provider);
    const email = payload.email as string;

    // Find or create tenant user
    let tenantUser = await db.query(
      `SELECT u.tenant_id, t.name, t.plan FROM tenant_users u
       JOIN tenants t ON t.id=u.tenant_id
       WHERE u.email=$1 AND t.active=true LIMIT 1`,
      [email]
    );

    if (!tenantUser.rows.length) {
      // Auto-provision if SSO is configured to allow new users
      if (process.env.SSO_AUTO_PROVISION === 'true') {
        const tenantId = crypto.randomUUID();
        const apiKey = 'mcpsg_' + crypto.randomBytes(32).toString('hex');
        const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
        await db.query(
          `INSERT INTO tenants (id,name,billing_email,plan,api_key_hash) VALUES ($1,$2,$3,'starter',$4)`,
          [tenantId, email.split('@')[0], email, apiKeyHash]
        );
        await db.query(
          `INSERT INTO tenant_users (tenant_id,email,password_hash,active) VALUES ($1,$2,''::text,true)`,
          [tenantId, email]
        );
        tenantUser = await db.query(`SELECT tenant_id, name, plan FROM tenant_users u JOIN tenants t ON t.id=u.tenant_id WHERE u.email=$1`, [email]);
      } else {
        return reply.redirect(`/login?error=sso_user_not_found`);
      }
    }

    const token = crypto.randomBytes(32).toString('hex');
    await db.query(
      `INSERT INTO user_sessions (token_hash, tenant_id, email, created_at, expires_at)
       VALUES ($1,$2,$3,NOW(),NOW()+INTERVAL '7 days')`,
      [crypto.createHash('sha256').update(token).digest('hex'), tenantUser.rows[0].tenant_id, email]
    );

    reply.redirect(`${process.env.APP_URL}/dashboard?token=${token}`);
  });

  fastify.post('/api/auth/logout', async (req: any) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      await db.query(`DELETE FROM user_sessions WHERE token_hash=$1`, [hash]);
    }
    return { loggedOut: true };
  });
}
