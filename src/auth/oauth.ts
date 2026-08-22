import { FastifyRequest, FastifyReply } from 'fastify';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';
import { Pool } from 'pg';
import Redis from 'ioredis';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

export interface OAuthConfig {
  issuer: string;
  audience: string;
  jwksUri: string;
}

export interface AuthenticatedUser {
  agentId: string;
  tenantId?: string;
  sub: string;
  email?: string;
  provider: 'oauth' | 'bearer';
  scopes: string[];
}

const OIDC_PROVIDERS: Record<string, OAuthConfig> = {
  google: {
    issuer: 'https://accounts.google.com',
    audience: process.env.GOOGLE_CLIENT_ID || '',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
  },
  azure: {
    issuer: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/v2.0`,
    audience: process.env.AZURE_CLIENT_ID || '',
    jwksUri: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/discovery/v2.0/keys`,
  },
  okta: {
    issuer: process.env.OKTA_ISSUER || '',
    audience: process.env.OKTA_AUDIENCE || '',
    jwksUri: `${process.env.OKTA_ISSUER}/v1/keys`,
  },
};

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJWKS(uri: string) {
  if (!jwksCache.has(uri)) {
    jwksCache.set(uri, createRemoteJWKSet(new URL(uri)));
  }
  return jwksCache.get(uri)!;
}

export async function verifyOIDCToken(token: string, provider: string, overrideConfig?: OAuthConfig): Promise<JWTPayload> {
  const config = overrideConfig || OIDC_PROVIDERS[provider];
  if (!config || !config.issuer) throw new Error(`Unknown or unconfigured OIDC provider: ${provider}`);
  const { payload } = await jwtVerify(token, getJWKS(config.jwksUri), {
    issuer: config.issuer,
    audience: config.audience,
  });
  return payload;
}

async function tenantOidcConfig(db: Pool, tenantId: string | undefined, provider: string): Promise<OAuthConfig | null> {
  if (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId)) return null;
  const r = await db.query(
    `SELECT metadata->'ssoOidc' AS config FROM tenants WHERE id=$1`,
    [tenantId]
  ).catch(() => ({ rows: [] as any[] }));
  const cfg = r.rows[0]?.config;
  if (!cfg?.configured || cfg.enabled === false || cfg.provider !== provider) return null;
  return {
    issuer: cfg.issuerUrl,
    audience: cfg.clientId,
    jwksUri: cfg.jwksUri,
  };
}

export async function verifyBearerToken(token: string, db: Pool, redis?: Redis): Promise<AuthenticatedUser | null> {
  const tokenSha = crypto.createHash('sha256').update(token).digest('hex');
  const cacheKey = `agent_token_cache:${tokenSha}`;

  if (redis) {
    try {
      const cached = await redis.get(cacheKey);
      if (cached) {
        if (cached === 'invalid') return null;
        return JSON.parse(cached);
      }
    } catch (err) {
      // Ignore cache errors and fallback to DB
    }
  }

  // [BUG #5 FIX] Previously queried WHERE active=true without checking expires_at.
  // A rotated key with expires_at < NOW() but active=TRUE passed auth for up to 5 minutes
  // (until the cron ran). Fix: reject expired tokens at the query level, not just via cron.
  // The cron (every 5 min) now acts as cleanup only — auth is the enforcer.
  const result = await db.query(
    `SELECT agent_id, tenant_id, token_hash, scopes FROM agent_tokens
     WHERE active = true
       AND (expires_at IS NULL OR expires_at > NOW())`
  );
  for (const row of result.rows) {
    if (await bcrypt.compare(token, row.token_hash)) {
      const user: AuthenticatedUser = { agentId: row.agent_id, tenantId: row.tenant_id, sub: row.agent_id, provider: 'bearer', scopes: row.scopes || [] };
      if (redis) {
        // Cache valid token for 5 minutes
        await redis.setex(cacheKey, 300, JSON.stringify(user)).catch(() => {});
      }
      return user;
    }
  }

  if (redis) {
    // Cache invalid token for 1 minute to prevent CPU exhaustion via brute-force
    await redis.setex(cacheKey, 60, 'invalid').catch(() => {});
  }
  return null;
}

export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
  db: Pool,
  redis?: Redis
): Promise<AuthenticatedUser> {
  const authHeader = request.headers.authorization;
  if (!authHeader) {
    reply.code(401).send({ error: 'Missing Authorization header' });
    throw new Error('Unauthenticated');
  }

  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    reply.code(401).send({ error: 'Expected: Authorization: Bearer <token>' });
    throw new Error('Unauthenticated');
  }

  const oidcProvider = request.headers['x-oidc-provider'] as string | undefined;
  const tenantIdHeader = request.headers['x-tenant-id'] as string | undefined;
  if (oidcProvider) {
    try {
      const tenantConfig = await tenantOidcConfig(db, tenantIdHeader, oidcProvider);
      const payload = await verifyOIDCToken(token, oidcProvider, tenantConfig || undefined);
      const r = await db.query(
        `SELECT agent_id, tenant_id, scopes FROM agent_oidc_mappings
         WHERE oidc_sub=$1 AND provider=$2 AND active=true
           AND ($3::uuid IS NULL OR tenant_id=$3::uuid)`,
        [payload.sub, oidcProvider, /^[0-9a-f-]{36}$/i.test(String(tenantIdHeader || '')) ? tenantIdHeader : null]
      );
      if (!r.rows.length) {
        reply.code(403).send({ error: 'OIDC identity not mapped to any agent' });
        throw new Error('Unmapped OIDC');
      }
      return {
        agentId: r.rows[0].agent_id,
        tenantId: r.rows[0].tenant_id,
        sub: payload.sub as string,
        email: payload.email as string | undefined,
        provider: 'oauth',
        scopes: r.rows[0].scopes || [],
      };
    } catch (err: any) {
      reply.code(401).send({ error: `OIDC error: ${err.message}` });
      throw err;
    }
  }

  const user = await verifyBearerToken(token, db, redis);
  if (!user) {
    reply.code(401).send({ error: 'Invalid or expired token' });
    throw new Error('Invalid token');
  }
  return user;
}
