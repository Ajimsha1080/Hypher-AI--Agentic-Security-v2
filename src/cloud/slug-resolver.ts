/**
 * Cloud Tenant Slug Resolver
 *
 * Reads X-Tenant-Slug header injected by Nginx wildcard routing.
 * Resolves the tenant from DB and attaches tenantId to the request
 * BEFORE the main proxy pipeline runs.
 *
 * Add to server.ts bootstrap, BEFORE the /mcp route registration:
 *
 *   await fastify.register(slugResolverPlugin, { db });
 *
 * Sprint 1 fix — ~15 lines of logic, enables the entire managed cloud tier.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { Pool } from 'pg';

export async function slugResolverPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool }
) {
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    const slug = request.headers['x-tenant-slug'] as string | undefined;
    if (!slug) return; // Not a subdomain request — skip

    // Validate slug format (a-z0-9 and hyphens, 3-38 chars)
    if (!/^[a-z0-9][a-z0-9-]{2,37}$/.test(slug)) {
      return reply.status(404).send({ error: 'Invalid subdomain' });
    }

    try {
      const r = await opts.db.query(
        `SELECT id, plan, active, api_calls_limit, agents_limit
         FROM tenants
         WHERE cloud_subdomain = $1
           AND deployment_type = 'managed_cloud'
           AND active = TRUE
         LIMIT 1`,
        [slug]
      );

      if (!r.rows.length) {
        return reply.status(404).send({
          error: 'Subdomain not found',
          message: `No active tenant at ${slug}.mcpsecurity.dev`,
        });
      }

      const tenant = r.rows[0];

      // Attach tenant context to request for downstream pipeline
      (request as any).cloudTenantId = tenant.id;
      (request as any).cloudTenantPlan = tenant.plan;
      (request as any).cloudTenantLimits = {
        apiCallsLimit: tenant.api_calls_limit,
        agentsLimit: tenant.agents_limit,
      };

      // Inject as a header so the existing resolveTenant() middleware
      // can pick it up without modification
      request.headers['x-cloud-tenant-id'] = tenant.id;
    } catch (err) {
      fastify.log.error({ err, slug }, 'Slug resolver DB error');
      return reply.status(503).send({ error: 'Service unavailable' });
    }
  });
}
