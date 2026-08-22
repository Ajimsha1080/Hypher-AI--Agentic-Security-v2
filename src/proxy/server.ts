/**
 * MCP Security Gateway — Production Server v3.3.0
 * All 4 sprint features wired. Full enterprise capability.
 *
 * Sprint 1: [S1-1] slugResolverPlugin [S1-2] a2aPlugin [S1-3] siemPlugin
 * Sprint 2: All UI sections have backend routes
 * Sprint 3: [S3-1] ipAllowlistPlugin [S3-2] teamPlugin [S3-3] ssoGroupPlugin
 *           [S3-4] slaPlugin [S3-5] complianceExtPlugin
 *           [S3-6] HITL timeout sweep cron [S3-7] retention enforcer [S3-8] per-plan rate limit
 * Sprint 4: [S4-1] scimPlugin [S4-2] retentionPlugin [S4-3] brandingPlugin
 *           [S4-4] hash-chained audit log for enterprise tenants
 */

import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';
import axios from 'axios';

// v2 imports
import { authMiddleware, AuthenticatedUser } from '../auth/oauth';
import { authRoutes } from '../auth/routes';
import { inspectToolCall } from '../middleware/inspection';
import { healthPlugin, registerGracefulShutdown } from '../middleware/health';
import { dashboardPlugin } from '../dashboard/plugin';
import { adminPlugin } from '../admin/admin';
import { billingPlugin } from '../billing/billing';
import { analyticsPlugin, detectIntegrationMethod, trackUsageEvent } from '../analytics/usage';
import { alertPlugin, dispatchAlert } from '../webhooks/alerting';
import { registryPlugin, checkRegistryTrust } from '../registry/registry';
import { tenantPlugin, resolveTenant, checkAndMeterUsage } from '../tenant/tenant';
import { detectAnomaly } from '../anomaly/detector';
import { emailPlugin } from '../email/mailer';
import { soc2Plugin } from '../soc2/reports';
import { soc2AutomationPlugin } from '../soc2-automation/controls';
import { compliancePlugin } from '../compliance/soc2';
import { validateUcpCall, ucpPlugin } from '../security/ucp_shield';
import { ucpConnectionPlugin } from '../security/ucp_connections';
import { startCronJobs } from '../cron/scheduler';
import { scanRequest, scanResponse, dlpPlugin } from '../dlp/scanner';
import { shadowPlugin } from '../shadow/discovery';
import { hitlPlugin, classifyRisk, createApproval } from '../hitl/approval';
import { wsPlugin, createWsPublisher } from '../websocket/realtime';
import { cloudPlugin } from '../cloud/provision';
import { a2aPlugin } from '../a2a/protocol';
import { siemPlugin } from '../siem/siem';
import { multiRegionPlugin } from '../multiregion/regions';
import { policyAssistantPlugin } from '../policy-assistant/assistant';
// Sprint 1-4 imports
import { slugResolverPlugin } from '../cloud/slug-resolver';
import { checkIpAllowlist, ipAllowlistPlugin } from '../security/ip-allowlist';
import { teamPlugin } from '../team/roles';
import { ssoGroupPlugin } from '../auth/sso-groups';
import { slaPlugin } from '../sla/sla';
import { complianceExtPlugin } from '../compliance/compliance-ext';
import { scimPlugin } from '../scim/scim';
import { retentionPlugin, brandingPlugin } from '../enterprise/retention-branding';
import { appendHashChainedLog } from '../audit/hash-chain';
import { sweepHitlTimeouts, enforceRetentionPolicies, getPlanRateLimit } from '../hitl/timeout-cron';
import { metricsPlugin, incCounter, recordHistogram } from '../observability/metrics';
import { mlAnomalyPlugin, detectAnomalyML, rebuildMLProfiles } from '../anomaly/ml-engine';
import { policyVersionsPlugin, anomalyExplainPlugin, replayPlugin } from '../features/policy-versions-replay';
import { webhookDeliveryPlugin, argSchemaPlugin, keyRotationPlugin, budgetPlugin, policyTemplatesPlugin } from '../features/future-features';
// F11-F20
import { checkToolRateLimit, toolRateLimitPlugin } from '../features/f11-rate-limiting';
import { checkGeoBlock, geoBlockPlugin } from '../features/f12-geo-blocking';
import { inspectToolCallDebug, injectionDebugPlugin, anomalyFeedbackPlugin, policyDryRunPlugin, auditExportPlugin, slackHitlPlugin, agentGraphPlugin, otelPlugin, retryWebhookDeliveries, webhookRetryPlugin, startSpan, finishSpan } from '../features/f13-f20-features';
import { incrementViolation } from '../security/quarantine';

export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000,
});

export const redis = new Redis(process.env.REDIS_URL!, {
  maxRetriesPerRequest: 3, lazyConnect: true,
});

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV !== 'production' ? { target: 'pino-pretty' } : undefined,
  },
  trustProxy: true,
});

async function bootstrap() {
  if (process.env.FAIL_MODE === 'fail_closed') {
    try {
      await db.query('SELECT 1');
      await redis.connect();
      const pc = await db.query('SELECT COUNT(*) FROM policies WHERE active=true');
      if (parseInt(pc.rows[0].count, 10) === 0) {
        fastify.log.fatal('FAIL-CLOSED: No active policies. Refusing to start.');
        process.exit(1);
      }
    } catch (err) {
      fastify.log.fatal({ err }, 'FAIL-CLOSED: Dependency unavailable.');
      process.exit(1);
    }
  } else {
    await redis.connect();
  }

  await ensurePolicyCompatibilitySchema();

  await fastify.register(helmet, { contentSecurityPolicy: false });
  await fastify.register(cors, {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
    credentials: true,
  });

  // [S3-8] Per-plan rate limiting
  await fastify.register(rateLimit, {
    redis,
    max: async (req: any) => getPlanRateLimit((req as any).tenant?.plan),
    timeWindow: '1 minute',
    keyGenerator: (req) => (req.headers['x-agent-id'] as string) || req.ip,
  });

  fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    try {
      (req as any).rawBody = body;
      const raw = body.toString().trim();
      done(null, raw ? JSON.parse(raw) : {});
    }
    catch (err) { done(err as Error, undefined); }
  });

  // [S1-1] Cloud slug resolver — FIRST, before all routes
  await fastify.register(slugResolverPlugin, { db });

  // Plugin registration
  await fastify.register(healthPlugin, { db, redis });
  await fastify.register(authRoutes, { db });
  await fastify.register(emailPlugin, { db });
  await fastify.register(tenantPlugin, { db, redis });
  await fastify.register(registryPlugin, { db, redis });
  await fastify.register(alertPlugin, { db });
  await fastify.register(analyticsPlugin, { db, redis });
  await fastify.register(billingPlugin, { db, redis });
  await fastify.register(adminPlugin, { db, redis });
  await fastify.register(soc2Plugin, { db });
  await fastify.register(soc2AutomationPlugin, { db });
  await fastify.register(compliancePlugin, { db });
  await fastify.register(dlpPlugin, { db });
  // [P0-FIX] DLP plugin registered — scan is active in /mcp pipeline via scanRequest/scanResponse
  await fastify.register(shadowPlugin, { db, redis });
  await fastify.register(hitlPlugin, { db, redis });
  await fastify.register(cloudPlugin, { db, redis });
  await fastify.register(a2aPlugin, { db, redis });
  await fastify.register(siemPlugin, { db });
  await fastify.register(multiRegionPlugin, { db });
  await fastify.register(policyAssistantPlugin, { db });
  await fastify.register(ipAllowlistPlugin, { db, redis });
  await fastify.register(teamPlugin, { db });
  await fastify.register(ssoGroupPlugin, { db });
  await fastify.register(slaPlugin, { db });
  await fastify.register(complianceExtPlugin, { db });
  await fastify.register(scimPlugin, { db });
  await fastify.register(retentionPlugin, { db });
  await fastify.register(brandingPlugin, { db });
  await fastify.register(metricsPlugin, { db, redis });
  await fastify.register(mlAnomalyPlugin, { db, redis });
  await fastify.register(policyVersionsPlugin, { db });
  await fastify.register(anomalyExplainPlugin, { db });
  await fastify.register(replayPlugin, { db });
  await fastify.register(webhookDeliveryPlugin, { db });

  await fastify.register(argSchemaPlugin, { db });
  await fastify.register(keyRotationPlugin, { db });
  await fastify.register(budgetPlugin, { db });
  await fastify.register(policyTemplatesPlugin, { db });
  // F11-F20 plugins
  await fastify.register(toolRateLimitPlugin, { db, redis });
  await fastify.register(geoBlockPlugin, { db, redis });
  await fastify.register(injectionDebugPlugin, { db });
  await fastify.register(anomalyFeedbackPlugin, { db });
  await fastify.register(policyDryRunPlugin, { db });
  await fastify.register(auditExportPlugin, { db });
  await fastify.register(slackHitlPlugin, { db, redis });
  await fastify.register(agentGraphPlugin, { db });
  await fastify.register(otelPlugin, { db });
  await fastify.register(webhookRetryPlugin, { db });
  await fastify.register(ucpPlugin, { db });
  await fastify.register(ucpConnectionPlugin, { db });

  if (process.env.ENABLE_WEBSOCKET !== 'false') {
    await fastify.register(require('@fastify/websocket'));
    await fastify.register(wsPlugin, { db, redis });
  }


  fastify.get('/benchmarks', async (_req, reply) => {
    const fs = await import('fs');
    const path = await import('path');
    const candidates = [
      path.join(__dirname, '../public/benchmarks.html'),
      path.join(__dirname, '../../public/benchmarks.html'),
    ];
    const file = candidates.find((candidate) => fs.existsSync(candidate));
    if (!file) return reply.code(404).type('text/plain').send('Benchmarks page not found');
    reply.type('text/html').send(fs.readFileSync(file, 'utf-8'));
  });

  fastify.get('/api/benchmarks/live', async () => {
    const fs = await import('fs');
    const path = await import('path');
    const now = new Date();
    const started = Date.now();
    let dbLatencyMs: number | null = null;
    let redisLatencyMs: number | null = null;
    let dbStatus: 'ok' | 'error' = 'ok';
    let redisStatus: 'ok' | 'error' = 'ok';

    const dbStart = Date.now();
    try {
      await db.query('SELECT 1');
      dbLatencyMs = Date.now() - dbStart;
    } catch {
      dbStatus = 'error';
    }

    const redisStart = Date.now();
    try {
      await redis.ping();
      redisLatencyMs = Date.now() - redisStart;
    } catch {
      redisStatus = 'error';
    }

    const latency = await db.query(`
      SELECT
        COUNT(*)::int AS calls,
        COUNT(*) FILTER (WHERE decision='DENY')::int AS denied,
        ROUND(AVG(execution_time_ms))::int AS avg_ms,
        ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY execution_time_ms))::int AS p50_ms,
        ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY execution_time_ms))::int AS p95_ms,
        ROUND(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY execution_time_ms))::int AS p99_ms,
        MAX(created_at) AS last_call_at
      FROM audit_log
      WHERE created_at > NOW() - INTERVAL '24 hours'
        AND execution_time_ms IS NOT NULL
    `).catch(() => ({ rows: [{ calls: 0, denied: 0, avg_ms: null, p50_ms: null, p95_ms: null, p99_ms: null, last_call_at: null }] }));

    const traffic = await db.query(`
      SELECT
        COUNT(*)::int AS calls_24h,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour')::int AS calls_1h,
        COUNT(DISTINCT agent_id)::int AS active_agents_24h,
        COUNT(*) FILTER (WHERE decision='DENY')::int AS blocked_24h
      FROM audit_log
      WHERE created_at > NOW() - INTERVAL '24 hours'
    `).catch(() => ({ rows: [{ calls_24h: 0, calls_1h: 0, active_agents_24h: 0, blocked_24h: 0 }] }));

    const reportCandidates = [
      path.join(process.cwd(), 'benchmark-results.json'),
      path.join(__dirname, '../../benchmark-results.json'),
    ];
    const reportFile = reportCandidates.find((candidate) => fs.existsSync(candidate));
    let savedReport: any = null;
    if (reportFile) {
      try { savedReport = JSON.parse(fs.readFileSync(reportFile, 'utf-8')); } catch { savedReport = null; }
    }

    const row: any = latency.rows[0] || {};
    const trafficRow: any = traffic.rows[0] || {};
    const hasLiveLatency = Number(row.calls || 0) > 0;
    return {
      mode: hasLiveLatency ? 'live_traffic' : savedReport ? 'saved_benchmark' : 'no_traffic_yet',
      generatedAt: now.toISOString(),
      gatewayVersion: '3.3.0',
      uptimeSeconds: Math.round(process.uptime()),
      health: {
        status: dbStatus === 'ok' && redisStatus === 'ok' ? 'healthy' : 'degraded',
        apiLatencyMs: Date.now() - started,
        db: { status: dbStatus, latencyMs: dbLatencyMs },
        redis: { status: redisStatus, latencyMs: redisLatencyMs },
      },
      traffic: {
        calls1h: Number(trafficRow.calls_1h || 0),
        calls24h: Number(trafficRow.calls_24h || 0),
        blocked24h: Number(trafficRow.blocked_24h || 0),
        activeAgents24h: Number(trafficRow.active_agents_24h || 0),
      },
      latency: {
        source: hasLiveLatency ? 'audit_log.execution_time_ms' : savedReport ? 'benchmark-results.json' : 'none',
        samples24h: Number(row.calls || 0),
        p50Ms: hasLiveLatency ? Number(row.p50_ms || 0) : savedReport?.endToEnd?.p50 ?? null,
        p95Ms: hasLiveLatency ? Number(row.p95_ms || 0) : savedReport?.endToEnd?.p95 ?? null,
        p99Ms: hasLiveLatency ? Number(row.p99_ms || 0) : savedReport?.endToEnd?.p99 ?? null,
        avgMs: hasLiveLatency ? Number(row.avg_ms || 0) : savedReport?.endToEnd?.mean ?? null,
        lastCallAt: row.last_call_at || null,
      },
      publishedReference: {
        p50Ms: 4.2,
        p95Ms: 7.8,
        p99Ms: 12.1,
        throughputRps: 340,
        label: 'Published reference run, single t3.small instance',
      },
    };
  });

  if (process.env.ENABLE_DASHBOARD === 'true') {
    await fastify.register(dashboardPlugin, { db, redis });
  }

  fastify.get('/local-mcp-upstream/health', async () => ({
    status: 'ok',
    upstream: 'local-mcp-upstream',
  }));

  fastify.post('/local-mcp-upstream', async (request, reply) => {
    const body = request.body as any;
    const id = body?.id ?? null;
    const method = body?.method;

    if (method === 'tools/list') {
      return reply.send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [{
            name: 'echo',
            description: 'Echoes the provided arguments for local gateway testing',
            inputSchema: {
              type: 'object',
              properties: { message: { type: 'string' } },
            },
          }],
        },
      });
    }

    if (method === 'tools/call') {
      const name = body?.params?.name;
      const args = body?.params?.arguments || {};
      return reply.send({
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: `${name || 'tool'}: ${JSON.stringify(args)}` }],
          isError: false,
        },
      });
    }

    return reply.send({
      jsonrpc: '2.0',
      id,
      error: { code: -32601, message: `Method not found: ${method}` },
    });
  });




  // ── Main MCP proxy — all 10 layers + F11-F20 features ──────────────
  fastify.post('/mcp', async (request, reply) => {
    const startMs = Date.now();
    const traceId = crypto.randomBytes(16).toString('hex');

    let user: AuthenticatedUser;
    try {
      user = await authMiddleware(request, reply, db, redis);
      if (user.tenantId) (request as any).authenticatedTenantId = user.tenantId;
    }
    catch { return; }

    const body = request.body as any;
    const toolName: string = body?.params?.name || body?.method || 'unknown';
    const args: Record<string, unknown> = body?.params?.arguments || {};
    const argsLength = JSON.stringify(args).length;
    const integrationMethod = detectIntegrationMethod(request);
    const sourceIp = request.ip;
    const rawAuditContext = buildAuditContext(request.headers, body, args);
    let audit = (entry: Parameters<typeof logAudit>[0]) =>
      logAudit({ ...rawAuditContext, ...entry });

    // [Feature 19: Distributed APM Tracing] Root span for this request
    const rootSpan = startSpan(traceId, 'mcp.request', { toolName, sourceIp, agentId: user.agentId });

    let tenant: any;
    try {
      tenant = await resolveTenant(request, db, redis);
      await checkAndMeterUsage(tenant.id, db, redis);
      const promptAudit = await getPromptAuditSettings(tenant.id);
      const auditContext = applyPromptAuditSettings(rawAuditContext, promptAudit);
      audit = (entry: Parameters<typeof logAudit>[0]) =>
        logAudit(promptAudit.mode === 'OFF'
          ? { ...auditContext, ...entry, userCommand: undefined, toolArguments: undefined, responseSummary: undefined }
          : { ...auditContext, ...entry });
    } catch (err: any) {
      incCounter('mcp_requests_total', { tenant: 'unknown', decision: 'DENY', tool: toolName });
      return reply.code(403).send({ error: err.message });
    }

    // [S3-1] IP allowlist check
    const ipSpan = startSpan(traceId, 'mcp.ip_allowlist', {}, rootSpan.spanId);
    const ipCheck = await checkIpAllowlist(tenant.id, sourceIp, db, redis);
    await finishSpan(ipSpan, db, tenant.id, ipCheck.allowed ? 'ok' : 'error', { allowed: ipCheck.allowed });
    if (!ipCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `ip_blocked:${ipCheck.reason}`,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp });
      return reply.code(403).send({ error: 'IP not in allowlist', reason: ipCheck.reason });
    }

    // [F12] Geo-blocking check
    const geoSpan = startSpan(traceId, 'mcp.geo_block', {}, rootSpan.spanId);
    const geoCheck = await checkGeoBlock(tenant.id, sourceIp, db, redis);
    await finishSpan(geoSpan, db, tenant.id, geoCheck.allowed ? 'ok' : 'error', { country: geoCheck.country || 'unknown' });
    if (!geoCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: geoCheck.reason!,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp });
      return reply.code(403).send({ error: 'Request blocked by geo policy', country: geoCheck.country });
    }

    // [F7] Budget & cost control — check per-agent monthly call limit
    // [BUG #4 FIX] Previously: .catch(() => null) silently disabled budget enforcement on
    // any DB error. Also: COUNT from audit_log is one behind because the current request
    // hasn't been logged yet — fix uses (count + 1) to represent the call-in-flight.
    let budgetRow: any = null;
    try {
      const budgetResult = await db.query(
        `SELECT monthly_call_limit, action_on_exceed,
                (SELECT COUNT(*) FROM audit_log
                 WHERE agent_id=$1 AND tenant_id=$2
                   AND created_at >= date_trunc('month', NOW())) AS calls_this_month
         FROM agent_budgets WHERE agent_id=$1 AND tenant_id=$2`,
        [user.agentId, tenant.id]
      );
      budgetRow = budgetResult.rows[0] ?? null;
    } catch (budgetErr: any) {
      fastify.log.error({ budgetErr, agentId: user.agentId }, 'Budget query failed — enforcing block as fail-safe');
      // Fail-safe: if we can't check the budget, deny rather than silently allow
      return reply.code(503).send({ error: 'Budget enforcement unavailable, request denied (fail-safe)' });
    }
    if (budgetRow) {
      // +1 accounts for the current in-flight request not yet written to audit_log
      const callsUsed = parseInt(budgetRow.calls_this_month, 10) + 1;
      const callLimit = parseInt(budgetRow.monthly_call_limit, 10);
      if (callsUsed > callLimit) {
        if (budgetRow.action_on_exceed === 'block') {
          incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
          await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
            decision: 'DENY', reason: `budget_exceeded:used=${callsUsed}:limit=${callLimit}`,
            executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp, argsLength });
          return reply.code(429).send({ error: 'Monthly call budget exceeded', used: callsUsed, limit: callLimit });
        }
        if (budgetRow.action_on_exceed === 'require_hitl') {
          const approval = await createApproval(tenant.id, user.agentId, toolName, args, 'require_approval', 'budget_exceeded', db, redis);
          return reply.code(202).send({ status: 'pending_approval', approvalId: approval.approvalId,
            message: 'Budget limit reached — manual approval required' });
        }
        // 'throttle' — 2s delay to discourage overuse without hard-blocking
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    // [F11] Per-tool rate limit check
    const toolRlSpan = startSpan(traceId, 'mcp.tool_rate_limit', { toolName }, rootSpan.spanId);
    const toolRlCheck = await checkToolRateLimit(tenant.id, user.agentId, toolName, db, redis);
    await finishSpan(toolRlSpan, db, tenant.id, toolRlCheck.allowed ? 'ok' : 'error',
      { count: toolRlCheck.currentCount, limit: toolRlCheck.limit });
    if (!toolRlCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: toolRlCheck.reason!,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp });
      return reply.code(429).send({
        error: 'Tool rate limit exceeded', tool: toolName,
        retryAfterSeconds: toolRlCheck.retryAfterSeconds,
      });
    }

    // [Feature 13: Threat Shield] Prompt injection inspection with visual debugger
    const inspectSpan = startSpan(traceId, 'mcp.inspect', { toolName }, rootSpan.spanId);
    const inspection = await inspectToolCallDebug(toolName, args, db, tenant.id, user.agentId);
    await finishSpan(inspectSpan, db, tenant.id, inspection.allowed ? 'ok' : 'error',
      { reason: inspection.reason || 'clean', pattern: inspection.debug?.patternName });
    if (!inspection.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: inspection.reason,
        executionTimeMs: Date.now()-startMs, authProvider: user.provider, sourceIp });
      fireAlert(tenant.id, 'injection_detected', inspection.reason!, db);
      await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'Prompt Injection Detected', db, redis);
      // [Feature 13: Threat Shield] Return rich debug info to dashboard/SOC team
      return reply.code(403).send({
        error: 'Blocked by inspection',
        reason: inspection.reason,
        debug: inspection.debug,  // patternName, argKey, matchedText, patternRegex
      });
    }

    const dlpSpan = startSpan(traceId, 'mcp.dlp', { toolName }, rootSpan.spanId);
    const dlpScan = await scanRequest(args, tenant.id, user.agentId, toolName, db);
    await finishSpan(dlpSpan, db, tenant.id, dlpScan.blocked ? 'error' : 'ok',
      { blocked: dlpScan.blocked, detectionCount: dlpScan.detections?.length ?? 0 });
    if (dlpScan.blocked) {
      incCounter('mcp_dlp_detections_total', { tenant: tenant.id, pii_type: dlpScan.detections[0]?.type || 'unknown' });
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `dlp_blocked:${dlpScan.detections.map((d:any)=>d.type).join(',')}`,
        executionTimeMs: Date.now()-startMs, authProvider: user.provider, sourceIp });
      await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'DLP Block', db, redis);
      return reply.code(403).send({ error: 'Request blocked by DLP', types: dlpScan.detections.map((d:any)=>d.type) });
    }
    const sanitizedArgs = dlpScan.sanitizedArgs || args;

    // [UCP SHIELD CHECK]
    const ucpResult = await validateUcpCall(tenant.id, user.agentId, toolName, sanitizedArgs, db);
    if (ucpResult.decision === 'block') {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: ucpResult.reason || 'ucp_blocked',
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp });
      await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'UCP Blocked', db, redis);
      return reply.code(403).send({ error: 'UCP Shield Blocked Request', reason: ucpResult.reason });
    }
    if (ucpResult.decision === 'hitl') {
      const approval = await createApproval(tenant.id, user.agentId, toolName, sanitizedArgs, 'require_approval', ucpResult.reason || 'ucp_approval_required', db, redis);
      incCounter('mcp_hitl_pending', { tenant: tenant.id });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `hitl_pending:${approval.approvalId}`,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod, toolArguments: sanitizeForAudit(sanitizedArgs),
        responseSummary: `pending_approval:${approval.approvalId}` });
      return reply.code(202).send({ status: 'pending_approval', approvalId: approval.approvalId,
        message: ucpResult.reason || 'UCP transaction requires manual approval' });
    }

    const { risk: hitlRisk, reason: hitlReason } = classifyRisk(toolName, sanitizedArgs);
    if (hitlRisk === 'auto_deny') {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `hitl_auto_deny:${hitlReason}`,
        executionTimeMs: Date.now()-startMs, authProvider: user.provider, sourceIp });
      await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'Risk Auto-Deny', db, redis);
      return reply.code(403).send({ error: 'Auto-denied by risk policy', reason: hitlReason });
    }
    if (hitlRisk === 'require_approval') {
      const hitlEnabled = (await db.query(
        `SELECT enabled FROM tenant_feature_flags WHERE tenant_id=$1 AND flag_name='hitl_approvals'`,
        [tenant.id]
      ).catch(()=>({rows:[]}))).rows[0]?.enabled;
      if (hitlEnabled) {
        const approval = await createApproval(tenant.id, user.agentId, toolName, sanitizedArgs, hitlRisk, hitlReason, db, redis);
        incCounter('mcp_hitl_pending', { tenant: tenant.id });
        await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
          decision: 'DENY', reason: `hitl_pending:${approval.approvalId}`,
          executionTimeMs: Date.now()-startMs, authProvider: user.provider, sourceIp,
          integrationMethod, toolArguments: sanitizeForAudit(sanitizedArgs),
          responseSummary: `pending_approval:${approval.approvalId}` });
        return reply.code(202).send({ status: 'pending_approval', approvalId: approval.approvalId,
          message: `Approval required. Poll GET /api/hitl/${approval.approvalId}` });
      }
    }

    const tenantUpstreamUrl = tenant?.metadata?.mcpServerUrl;
    const tenantUpstreamToken = tenant?.metadata?.mcpProxyAuthToken;
    const forwardSpan = startSpan(traceId, 'mcp.upstream', { toolName }, rootSpan.spanId);
    const upstreamResponse = await forwardToMCP(
      { ...body, params: { ...body?.params, arguments: sanitizedArgs } },
      tenantUpstreamUrl,
      tenantUpstreamToken
    );
    const respScan = await scanResponse(upstreamResponse, tenant.id, user.agentId, toolName, db);
    const finalResponse = respScan.clean ? upstreamResponse : (respScan.sanitizedResponse || upstreamResponse);
    const execMs = Date.now() - startMs;
    const upstreamFailed = Boolean((finalResponse as any)?.error || (finalResponse as any)?.result?.isError);
    const finalDecision: 'ALLOW' | 'DENY' = upstreamFailed ? 'DENY' : 'ALLOW';
    const finalReason = upstreamFailed
      ? `upstream_error:${(finalResponse as any)?.error?.message || 'tool_returned_error'}`
      : undefined;
    await finishSpan(forwardSpan, db, tenant.id, upstreamFailed ? 'error' : 'ok', { latencyMs: execMs });

    // [Feature 19: Distributed APM Tracing] Finish root span
    await finishSpan(rootSpan, db, tenant.id, upstreamFailed ? 'error' : 'ok', { latencyMs: execMs, decision: finalDecision });

    await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
      decision: finalDecision, reason: finalReason,
      executionTimeMs: execMs, authProvider: user.provider, sourceIp,
      integrationMethod, toolArguments: sanitizeForAudit(sanitizedArgs),
      responseSummary: summarizeResponse(finalResponse) });

    // [S4-4] Hash-chained audit for enterprise
    if (tenant.plan === 'enterprise') {
      appendHashChainedLog(db, { tenantId: tenant.id, agentId: user.agentId, toolName,
        decision: finalDecision, reason: finalReason || 'policy_allowed',
        argsHash: crypto.createHash('sha256').update(JSON.stringify(sanitizedArgs)).digest('hex').slice(0,16),
      }).catch(()=>{});
    }

    // [Feature 19: Distributed APM Tracing] Prometheus metrics — now actually incremented
    incCounter('mcp_requests_total', { tenant: tenant.id, decision: finalDecision, tool: toolName });
    recordHistogram('mcp_request_duration_ms', execMs, { tenant: tenant.id, tool: toolName });

    await trackUsageEvent({ tenantId: tenant.id, agentId: user.agentId, toolName,
      decision: finalDecision, integrationMethod, latencyMs: execMs, sourceIp, db, redis });

    createWsPublisher(redis).auditEvent(tenant.id, {
      agentId: user.agentId, toolName, decision: finalDecision,
      executionTimeMs: execMs, authProvider: user.provider, dlpTriggered: !dlpScan.clean,
    }).catch(()=>{});

    return reply.send(finalResponse);
  });

  // Non-MCP Agent API preflight.
  //
  // Enterprise custom agents often use REST APIs, LangChain tools, or internal SDKs
  // instead of MCP. This endpoint lets those agents ask the gateway for an
  // allow/deny/pending decision before executing their own tool.
  fastify.post('/api/agent/tool-call', async (request, reply) => {
    const startMs = Date.now();
    const traceId = crypto.randomBytes(16).toString('hex');

    let user: AuthenticatedUser;
    try {
      user = await authMiddleware(request, reply, db, redis);
      if (user.tenantId) (request as any).authenticatedTenantId = user.tenantId;
    } catch {
      return;
    }

    const body = (request.body || {}) as any;
    const toolName = stringValue(body.tool || body.toolName || body.action || body.name);
    if (!toolName) {
      return reply.code(400).send({
        error: 'Missing tool name',
        expected: 'Body must include tool, toolName, action, or name',
      });
    }

    const args = normalizeAgentApiArguments(body.arguments ?? body.args ?? body.input ?? {});
    const argsLength = JSON.stringify(args).length;
    const sourceIp = request.ip;
    const integrationMethod = `agent_api:${detectIntegrationMethod(request)}`;
    const rawAuditContext = buildAuditContext(request.headers, {
      ...body,
      id: body.requestId || body.id,
      metadata: body.metadata,
    }, args);
    let audit = (entry: Parameters<typeof logAudit>[0]) =>
      logAudit({ ...rawAuditContext, ...entry });

    const rootSpan = startSpan(traceId, 'agent_api.preflight', {
      toolName,
      sourceIp,
      agentId: user.agentId,
    });

    let tenant: any;
    try {
      tenant = await resolveTenant(request, db, redis);
      await checkAndMeterUsage(tenant.id, db, redis);
      const promptAudit = await getPromptAuditSettings(tenant.id);
      const auditContext = applyPromptAuditSettings(rawAuditContext, promptAudit);
      audit = (entry: Parameters<typeof logAudit>[0]) =>
        logAudit(promptAudit.mode === 'OFF'
          ? { ...auditContext, ...entry, userCommand: undefined, toolArguments: undefined, responseSummary: undefined }
          : { ...auditContext, ...entry });
    } catch (err: any) {
      incCounter('mcp_requests_total', { tenant: 'unknown', decision: 'DENY', tool: toolName });
      return reply.code(403).send({ error: err.message });
    }

    const ipSpan = startSpan(traceId, 'agent_api.ip_allowlist', {}, rootSpan.spanId);
    const ipCheck = await checkIpAllowlist(tenant.id, sourceIp, db, redis);
    await finishSpan(ipSpan, db, tenant.id, ipCheck.allowed ? 'ok' : 'error', { allowed: ipCheck.allowed });
    if (!ipCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `ip_blocked:${ipCheck.reason}`,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(403).send({ error: 'IP not in allowlist', reason: ipCheck.reason });
    }

    const geoSpan = startSpan(traceId, 'agent_api.geo_block', {}, rootSpan.spanId);
    const geoCheck = await checkGeoBlock(tenant.id, sourceIp, db, redis);
    await finishSpan(geoSpan, db, tenant.id, geoCheck.allowed ? 'ok' : 'error', { country: geoCheck.country || 'unknown' });
    if (!geoCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: geoCheck.reason!,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(403).send({ error: 'Request blocked by geo policy', country: geoCheck.country });
    }

    let budgetRow: any = null;
    try {
      const budgetResult = await db.query(
        `SELECT monthly_call_limit, action_on_exceed,
                (SELECT COUNT(*) FROM audit_log
                 WHERE agent_id=$1 AND tenant_id=$2
                   AND created_at >= date_trunc('month', NOW())) AS calls_this_month
         FROM agent_budgets WHERE agent_id=$1 AND tenant_id=$2`,
        [user.agentId, tenant.id]
      );
      budgetRow = budgetResult.rows[0] ?? null;
    } catch (budgetErr: any) {
      fastify.log.error({ budgetErr, agentId: user.agentId }, 'Agent API budget query failed - enforcing block as fail-safe');
      return reply.code(503).send({ error: 'Budget enforcement unavailable, request denied (fail-safe)' });
    }
    if (budgetRow) {
      const callsUsed = parseInt(budgetRow.calls_this_month, 10) + 1;
      const callLimit = parseInt(budgetRow.monthly_call_limit, 10);
      if (callsUsed > callLimit) {
        if (budgetRow.action_on_exceed === 'block') {
          incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
          await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
            decision: 'DENY', reason: `budget_exceeded:used=${callsUsed}:limit=${callLimit}`,
            executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
            integrationMethod, argsLength });
          return reply.code(429).send({ error: 'Monthly call budget exceeded', used: callsUsed, limit: callLimit });
        }
        if (budgetRow.action_on_exceed === 'require_hitl') {
          const approval = await createApproval(tenant.id, user.agentId, toolName, args, 'require_approval', 'budget_exceeded', db, redis);
          return reply.code(202).send({ decision: 'PENDING_APPROVAL', allowed: false, approvalId: approval.approvalId,
            message: 'Budget limit reached - manual approval required' });
        }
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    const toolRlSpan = startSpan(traceId, 'agent_api.tool_rate_limit', { toolName }, rootSpan.spanId);
    const toolRlCheck = await checkToolRateLimit(tenant.id, user.agentId, toolName, db, redis);
    await finishSpan(toolRlSpan, db, tenant.id, toolRlCheck.allowed ? 'ok' : 'error',
      { count: toolRlCheck.currentCount, limit: toolRlCheck.limit });
    if (!toolRlCheck.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: toolRlCheck.reason!,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(429).send({ error: 'Tool rate limit exceeded', tool: toolName,
        retryAfterSeconds: toolRlCheck.retryAfterSeconds });
    }

    const inspectSpan = startSpan(traceId, 'agent_api.inspect', { toolName }, rootSpan.spanId);
    const inspection = await inspectToolCallDebug(toolName, args, db, tenant.id, user.agentId);
    await finishSpan(inspectSpan, db, tenant.id, inspection.allowed ? 'ok' : 'error',
      { reason: inspection.reason || 'clean', pattern: inspection.debug?.patternName });
    if (!inspection.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: inspection.reason,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      fireAlert(tenant.id, 'injection_detected', inspection.reason!, db);
      return reply.code(403).send({ decision: 'DENY', allowed: false,
        error: 'Blocked by inspection', reason: inspection.reason, debug: inspection.debug });
    }

    const dlpSpan = startSpan(traceId, 'agent_api.dlp', { toolName }, rootSpan.spanId);
    const dlpScan = await scanRequest(args, tenant.id, user.agentId, toolName, db);
    await finishSpan(dlpSpan, db, tenant.id, dlpScan.blocked ? 'error' : 'ok',
      { blocked: dlpScan.blocked, detectionCount: dlpScan.detections?.length ?? 0 });
    if (dlpScan.blocked) {
      incCounter('mcp_dlp_detections_total', { tenant: tenant.id, pii_type: dlpScan.detections[0]?.type || 'unknown' });
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `dlp_blocked:${dlpScan.detections.map((d: any) => d.type).join(',')}`,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(403).send({ decision: 'DENY', allowed: false,
        error: 'Request blocked by DLP', types: dlpScan.detections.map((d: any) => d.type) });
    }
    const sanitizedArgs = dlpScan.sanitizedArgs || args;

    const { risk: hitlRisk, reason: hitlReason } = classifyRisk(toolName, sanitizedArgs);
    if (hitlRisk === 'auto_deny') {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: `hitl_auto_deny:${hitlReason}`,
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(403).send({ decision: 'DENY', allowed: false,
        error: 'Auto-denied by risk policy', reason: hitlReason });
    }
    if (hitlRisk === 'require_approval') {
      const hitlEnabled = (await db.query(
        `SELECT enabled FROM tenant_feature_flags WHERE tenant_id=$1 AND flag_name='hitl_approvals'`,
        [tenant.id]
      ).catch(() => ({ rows: [] }))).rows[0]?.enabled;
      if (hitlEnabled) {
        const approval = await createApproval(tenant.id, user.agentId, toolName, sanitizedArgs, hitlRisk, hitlReason, db, redis);
        incCounter('mcp_hitl_pending', { tenant: tenant.id });
        await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
          decision: 'DENY', reason: `hitl_pending:${approval.approvalId}`,
          executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
          integrationMethod, toolArguments: sanitizeForAudit(sanitizedArgs),
          responseSummary: `pending_approval:${approval.approvalId}` });
        return reply.code(202).send({ decision: 'PENDING_APPROVAL', allowed: false,
          approvalId: approval.approvalId,
          message: `Approval required. Poll GET /api/hitl/${approval.approvalId}` });
      }
    }

    const policySpan = startSpan(traceId, 'agent_api.rbac', { toolName, agentId: user.agentId }, rootSpan.spanId);
    const policy = await checkPolicy(user.agentId, toolName, tenant.id);
    await finishSpan(policySpan, db, tenant.id, policy.allowed ? 'ok' : 'error', { reason: policy.reason });
    if (!policy.allowed) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: policy.reason || 'no_matching_policy',
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(403).send({ decision: 'DENY', allowed: false,
        error: 'Tool call not permitted', reason: policy.reason });
    }

    const anomalySpan = startSpan(traceId, 'agent_api.anomaly', { toolName }, rootSpan.spanId);
    const prevTool = await redis.get(`prev_tool:${tenant.id}:${user.agentId}`);
    const mlResult = await detectAnomalyML(user.agentId, tenant.id, toolName, sanitizedArgs, prevTool, db, redis);
    await redis.setex(`prev_tool:${tenant.id}:${user.agentId}`, 3600, toolName);
    await finishSpan(anomalySpan, db, tenant.id, mlResult.isAnomaly ? 'error' : 'ok',
      { score: mlResult.score, confidence: mlResult.confidence, action: mlResult.action });

    let anomalyBlocked = false;
    if (mlResult.isAnomaly || mlResult.score >= 35) {
      incCounter('mcp_anomaly_flags_total', { tenant: tenant.id });
      fireAlert(tenant.id, 'anomaly_detected',
        mlResult.reasons.map(r => r.description).join('; '), db);
      db.query(
        `INSERT INTO anomaly_events (tenant_id,agent_id,tool_name,score,confidence,action,reasons_json,profile_age,arg_length,call_hour,prev_tool)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [tenant.id, user.agentId, toolName, mlResult.score, mlResult.confidence,
         mlResult.action, JSON.stringify(mlResult.reasons), mlResult.profileAge,
         JSON.stringify(sanitizedArgs).length, new Date().getUTCHours(), prevTool || null]
      ).catch(() => {});
      if (mlResult.action === 'block') {
        anomalyBlocked = true;
        incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
        await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
          decision: 'DENY', reason: `ml_anomaly:score=${mlResult.score}:${mlResult.reasons[0]?.description || ''}`,
          executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
          integrationMethod });
        await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'ML Anomaly Block', db, redis);
        return reply.code(403).send({ decision: 'DENY', allowed: false,
          error: 'Anomaly detected', score: mlResult.score, reasons: mlResult.reasons });
      }
    }

    if (mlResult.confidence === 'low') {
      const anomaly = await detectAnomaly(user.agentId, tenant.id, toolName, sanitizedArgs, db, redis);
      if (anomaly.isAnomaly && !anomalyBlocked) {
        incCounter('mcp_anomaly_flags_total', { tenant: tenant.id });
        fireAlert(tenant.id, 'anomaly_detected', anomaly.reasons[0] || 'zscore_bootstrap_anomaly', db);
        db.query(
          `INSERT INTO anomaly_events
             (tenant_id, agent_id, tool_name, score, confidence, action, reasons_json, profile_age, arg_length, call_hour)
           VALUES ($1,$2,$3,$4,'low',$5,$6,0,$7,$8)`,
          [tenant.id, user.agentId, toolName, anomaly.score, anomaly.action,
           JSON.stringify(anomaly.reasons.map(r => ({ description: r }))),
           JSON.stringify(sanitizedArgs).length, new Date().getUTCHours()]
        ).catch(() => {});
        if (anomaly.action === 'block') {
          anomalyBlocked = true;
          incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
          await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
            decision: 'DENY', reason: `bootstrap_anomaly:score=${anomaly.score}:${anomaly.reasons[0] || ''}`,
            executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
            integrationMethod });
          await incrementViolation(tenant.id, user.agentId, request.headers.authorization, 'Bootstrap Anomaly Block', db, redis);
          return reply.code(403).send({ decision: 'DENY', allowed: false,
            error: 'Anomaly detected during bootstrap', score: anomaly.score, reasons: anomaly.reasons });
        }
      }
    }

    const requestKey = String(body.requestId || body.id || '');
    const reqHash = crypto.createHash('sha256')
      .update(`${user.agentId}:${toolName}:${requestKey}:${JSON.stringify(sanitizedArgs)}`).digest('hex');
    const seen = await redis.set(`replay:${reqHash}`, '1', 'EX', 300, 'NX');
    if (!seen) {
      incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'DENY', tool: toolName });
      await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
        decision: 'DENY', reason: 'replay_detected',
        executionTimeMs: Date.now() - startMs, authProvider: user.provider, sourceIp,
        integrationMethod });
      return reply.code(429).send({ decision: 'DENY', allowed: false,
        error: 'Duplicate request detected' });
    }

    const execMs = Date.now() - startMs;
    await finishSpan(rootSpan, db, tenant.id, 'ok', { latencyMs: execMs, decision: 'ALLOW' });
    await audit({ agentId: user.agentId, toolName, tenantId: tenant.id,
      decision: 'ALLOW', reason: 'agent_api_preflight_allowed',
      executionTimeMs: execMs, authProvider: user.provider, sourceIp,
      integrationMethod, argsLength, toolArguments: sanitizeForAudit(sanitizedArgs),
      responseSummary: 'preflight_allowed:agent_executes_tool' });
    if (tenant.plan === 'enterprise') {
      appendHashChainedLog(db, { tenantId: tenant.id, agentId: user.agentId, toolName,
        decision: 'ALLOW', reason: 'agent_api_preflight_allowed',
        argsHash: crypto.createHash('sha256').update(JSON.stringify(sanitizedArgs)).digest('hex').slice(0, 16),
      }).catch(() => {});
    }
    incCounter('mcp_requests_total', { tenant: tenant.id, decision: 'ALLOW', tool: toolName });
    recordHistogram('mcp_request_duration_ms', execMs, { tenant: tenant.id, tool: toolName });
    await trackUsageEvent({ tenantId: tenant.id, agentId: user.agentId, toolName,
      decision: 'ALLOW', integrationMethod, latencyMs: execMs, sourceIp, db, redis });
    createWsPublisher(redis).auditEvent(tenant.id, {
      agentId: user.agentId, toolName, decision: 'ALLOW',
      executionTimeMs: execMs, authProvider: user.provider, dlpTriggered: !dlpScan.clean,
    }).catch(() => {});

    return reply.send({
      decision: 'ALLOW',
      allowed: true,
      mode: 'preflight',
      toolName,
      sanitizedArguments: sanitizedArgs,
      dlpDetections: dlpScan.detections.map((d: any) => d.type),
      message: 'Allowed. Execute the tool in the external agent runtime, not inside the gateway.',
    });
  });

  // Secure Agent Runtime API forwarding (/api/v1/*) to Python agent service
  fastify.all('/api/v1/*', async (request, reply) => {
    const agentRuntimeUrl = process.env.AGENT_RUNTIME_URL || 'http://localhost:8000';
    try {
      const url = `${agentRuntimeUrl}${request.url}`;
      const response = await axios({
        method: request.method as any,
        url,
        data: request.body,
        headers: {
          'content-type': 'application/json',
          'x-tenant-id': (request.headers['x-tenant-id'] as string) || 'tenant_default',
          'x-user-id': (request.headers['x-user-id'] as string) || 'user_default',
          'authorization': request.headers.authorization || '',
        },
        timeout: 60000,
      });
      return reply.code(response.status).send(response.data);
    } catch (error: any) {
      if (error.response) {
        return reply.code(error.response.status).send(error.response.data);
      }
      return reply.code(503).send({
        error: 'Agent Runtime service unavailable',
        details: error.message,
      });
    }
  });

  startCronJobs(db, redis, fastify.log);

  // ML profile rebuild every 2 hours
  setInterval(async () => {
    try { await rebuildMLProfiles(db); fastify.log.info('ML anomaly profiles rebuilt'); }
    catch (e) { fastify.log.error({ e }, 'ML profile rebuild failed'); }
  }, 2 * 60 * 60 * 1000);

  setInterval(() => sweepHitlTimeouts(db, redis, fastify.log), 60_000);

  const msToMidnight = new Date(new Date().setHours(24,0,0,0)).getTime() - Date.now();
  setTimeout(() => {
    enforceRetentionPolicies(db, fastify.log);
    setInterval(() => enforceRetentionPolicies(db, fastify.log), 86400_000);
  }, msToMidnight);

  // [Feature 20: Webhook Retry] Webhook auto-retry with exponential backoff — every 60s
  setInterval(async () => {
    try { await retryWebhookDeliveries(db); }
    catch (e) { fastify.log.error({ e }, 'Webhook retry sweep failed'); }
  }, 60_000);

  // [Feature 18: Agentic Graph] Agent dependency graph rebuild — every 6 hours
  setInterval(async () => {
    try {
      const tenants = await db.query(`SELECT id FROM tenants WHERE active=TRUE`);
      for (const t of tenants.rows) {
        await db.query(
          `INSERT INTO agent_tool_cooccurrence (tenant_id,agent_id,tool_a,tool_b,co_count,last_seen)
           SELECT $1,a.agent_id,a.tool_name,b.tool_name,COUNT(*),NOW()
           FROM audit_log a JOIN audit_log b
             ON a.agent_id=b.agent_id AND a.tenant_id=b.tenant_id
             AND a.tool_name<b.tool_name
             AND ABS(EXTRACT(EPOCH FROM (a.created_at-b.created_at)))<300
           WHERE a.tenant_id=$1 AND a.created_at>NOW()-INTERVAL '7 days'
             AND a.decision='ALLOW' AND b.decision='ALLOW'
           GROUP BY a.agent_id,a.tool_name,b.tool_name
           ON CONFLICT(tenant_id,agent_id,tool_a,tool_b)
           DO UPDATE SET co_count=EXCLUDED.co_count,last_seen=NOW()`,
          [t.id]
        ).catch(() => {});
      }
      fastify.log.info('Agent dependency graphs rebuilt');
    } catch (e) { fastify.log.error({ e }, 'Graph rebuild failed'); }
  }, 6 * 60 * 60 * 1000);

  registerGracefulShutdown(fastify, db, redis);
  const port = parseInt(process.env.PORT || '3000', 10);
  await fastify.listen({ port, host: '0.0.0.0' });
  fastify.log.info(`Hypher AI Gateway v3.3.0 on :${port} (enterprise controls active)`);
}

async function checkPolicy(agentId: string, toolName: string, tenantId: string) {
  const discoveryMethods = new Set([
    'initialize',
    'ping',
    'tools/list',
    'resources/list',
    'prompts/list',
    'notifications/initialized',
  ]);
  if (discoveryMethods.has(toolName)) {
    return { allowed: true, reason: 'authenticated_mcp_discovery' };
  }

  const r = await db.query(
    `SELECT id FROM policies WHERE agent_id=$1 AND tenant_id=$2
     AND active=true
     AND (
       (action='allow' AND (tool_name=$3 OR tool_name='*'))
       OR (allowed_tools @> ARRAY[$3::text] OR allowed_tools=ARRAY['*'])
     )
     LIMIT 1`,
    [agentId, tenantId, toolName]
  );
  return r.rows.length > 0 ? { allowed: true } : { allowed: false, reason: 'no_matching_policy' };
}

async function ensurePolicyCompatibilitySchema() {
  await db.query(`
    ALTER TABLE policies
      ADD COLUMN IF NOT EXISTS allowed_tools TEXT[]
  `);
  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_policies_allowed_tools
      ON policies USING GIN (allowed_tools)
  `);
}

export async function logAudit(entry: {
  agentId: string; toolName: string; tenantId?: string; decision: 'ALLOW'|'DENY';
  reason?: string; inspectionResult?: object; executionTimeMs?: number;
  authProvider?: string; sourceIp?: string; integrationMethod?: string;
  argsLength?: number;
  userId?: string; sessionId?: string; conversationId?: string; requestId?: string;
  userCommand?: string; toolArguments?: unknown; responseSummary?: string;
}) {
  try {
    await db.query(
      `INSERT INTO audit_log (agent_id,tenant_id,tool_name,decision,reason,inspection_result,
       execution_time_ms,auth_provider,source_ip,integration_method,args_length,
       user_id,session_id,conversation_id,request_id,user_command,tool_arguments,response_summary,created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())`,
      [entry.agentId, entry.tenantId||null, entry.toolName, entry.decision, entry.reason||null,
       entry.inspectionResult ? JSON.stringify(entry.inspectionResult) : null,
       entry.executionTimeMs||null, entry.authProvider||'bearer',
       entry.sourceIp||null, entry.integrationMethod||null,
       entry.argsLength ?? null, entry.userId || null, entry.sessionId || null,
       entry.conversationId || null, entry.requestId || null, entry.userCommand || null,
       entry.toolArguments ? JSON.stringify(entry.toolArguments) : null,
       entry.responseSummary || null]
    );
    if (entry.tenantId) purgeExpiredPromptAudit(entry.tenantId).catch(() => {});
  } catch (e) {
    fastify.log.error({ e }, 'CRITICAL: audit log write failed');
    if (process.env.FAIL_MODE === 'fail_closed') process.exit(1);
  }
}

async function purgeExpiredPromptAudit(tenantId: string) {
  const r = await db.query(
    `SELECT retention_days FROM prompt_audit_settings WHERE tenant_id=$1`,
    [tenantId]
  );
  const days = parseInt(r.rows[0]?.retention_days, 10) || 30;
  await db.query(
    `UPDATE audit_log
     SET user_command=NULL, tool_arguments=NULL, response_summary=NULL
     WHERE tenant_id=$1 AND created_at < NOW() - ($2::text || ' days')::interval
       AND (user_command IS NOT NULL OR tool_arguments IS NOT NULL OR response_summary IS NOT NULL)`,
    [tenantId, days]
  );
}

export function buildAuditContext(headers: Record<string, any>, body: any, args: Record<string, unknown>) {
  return {
    userId: headerValue(headers, 'x-user-id') || stringValue(args.user_id) || stringValue(args.userId),
    sessionId: headerValue(headers, 'x-session-id') || stringValue(args.session_id) || stringValue(args.sessionId),
    conversationId: headerValue(headers, 'x-conversation-id') || stringValue(args.conversation_id) || stringValue(args.conversationId),
    requestId: headerValue(headers, 'x-request-id') || stringValue(body?.id),
    userCommand: truncateAuditText(
      headerValue(headers, 'x-user-command') ||
      stringValue(args.user_command) ||
      stringValue(args.userCommand) ||
      stringValue(body?.metadata?.user_command) ||
      stringValue(body?.metadata?.userCommand),
      2000
    ),
    toolArguments: sanitizeForAudit(args),
    argsLength: JSON.stringify(args).length,
  };
}

type PromptAuditMode = 'OFF' | 'SUMMARY_ONLY' | 'FULL_REDACTED' | 'FULL_RAW';

export async function getPromptAuditSettings(tenantId: string): Promise<{ mode: PromptAuditMode; retentionDays: number }> {
  try {
    const r = await db.query(
      `SELECT mode, retention_days FROM prompt_audit_settings WHERE tenant_id=$1`,
      [tenantId]
    );
    if (r.rows[0]) {
      return {
        mode: r.rows[0].mode,
        retentionDays: parseInt(r.rows[0].retention_days, 10) || 30,
      };
    }
    await db.query(
      `INSERT INTO prompt_audit_settings (tenant_id, mode, retention_days)
       VALUES ($1, 'SUMMARY_ONLY', 30) ON CONFLICT DO NOTHING`,
      [tenantId]
    );
  } catch {
    // Safe default: keep only summaries/redacted data if settings are unavailable.
  }
  return { mode: 'SUMMARY_ONLY', retentionDays: 30 };
}

export function applyPromptAuditSettings(
  context: ReturnType<typeof buildAuditContext>,
  settings: { mode: PromptAuditMode }
): ReturnType<typeof buildAuditContext> {
  if (settings.mode === 'OFF') {
    return {
      ...context,
      userCommand: undefined,
      toolArguments: undefined,
    };
  }

  if (settings.mode === 'FULL_RAW') return context;

  const redactedCommand = redactSensitiveText(context.userCommand);
  return {
    ...context,
    userCommand: settings.mode === 'SUMMARY_ONLY'
      ? truncateAuditText(redactedCommand, 500)
      : truncateAuditText(redactedCommand, 2000),
    toolArguments: sanitizeForAudit(context.toolArguments),
  };
}

function headerValue(headers: Record<string, any>, name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? stringValue(value[0]) : stringValue(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function normalizeAgentApiArguments(value: unknown): Record<string, unknown> {
  if (value === undefined || value === null) {
    return {};
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    return { value };
  }
  return value as Record<string, unknown>;
}

function truncateAuditText(value: string | undefined, max: number): string | undefined {
  if (!value) return undefined;
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

export function sanitizeForAudit(value: unknown, depth = 0): unknown {
  if (depth > 5) return '[Max depth]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return truncateAuditText(redactSensitiveText(value), 1000);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map(v => sanitizeForAudit(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 80)) {
      out[key] = /token|secret|password|key|authorization|credential/i.test(key)
        ? '[REDACTED]'
        : /content|text|body|source|diff|patch|file_data|filedata/i.test(key)
          ? summarizeAuditPayload(item)
        : sanitizeForAudit(item, depth + 1);
    }
    return out;
  }
  return String(value);
}

function summarizeAuditPayload(value: unknown): unknown {
  if (typeof value === 'string') {
    return `[REDACTED_CONTENT:${value.length}_chars]`;
  }
  if (Array.isArray(value)) {
    return `[REDACTED_CONTENT_ARRAY:${value.length}_items]`;
  }
  if (value && typeof value === 'object') {
    return '[REDACTED_CONTENT_OBJECT]';
  }
  return value;
}

function summarizeResponse(value: unknown): string {
  const response = value as any;
  if (response?.error) {
    return truncateAuditText(redactSensitiveText(`error:${response.error.code ?? 'unknown'}:${response.error.message ?? ''}`), 500) || 'error';
  }

  const result = response?.result;
  if (result && typeof result === 'object') {
    const content = Array.isArray(result.content) ? result.content : undefined;
    const textChars = content
      ? content.reduce((total: number, item: any) => total + (typeof item?.text === 'string' ? item.text.length : 0), 0)
      : 0;
    return `ok; isError=${Boolean(result.isError)}; content_items=${content?.length ?? 0}; text_chars=${textChars}`;
  }

  return 'ok';
}

function redactSensitiveText(value: string | undefined): string | undefined {
  if (!value) return value;
  return value
    .replace(/\b(api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|authorization|secret|password|credential)\s*[:=]\s*("[^"]+"|'[^']+'|[^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/(sk-[A-Za-z0-9_-]{20,})/g, '[REDACTED_OPENAI_KEY]')
    .replace(/(AKIA[0-9A-Z]{16})/g, '[REDACTED_AWS_KEY]')
    .replace(/(ghp_[A-Za-z0-9_]{20,})/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '[REDACTED_JWT]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/\b(?:\d[ -]*?){13,19}\b/g, '[REDACTED_CARD]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]');
}

async function forwardToMCP(body: unknown, tenantUpstreamUrl?: string, tenantUpstreamToken?: string) {
  const url = tenantUpstreamUrl || process.env.MCP_SERVER_URL;
  if (!url) {
    throw new Error('No upstream MCP server URL configured');
  }

  const token = tenantUpstreamToken || process.env.MCP_PROXY_AUTH_TOKEN;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Forwarded-By': 'mcp-security-gateway'
  };
  if (token) {
    headers['X-MCP-Proxy-Auth'] = `Bearer ${token}`;
  }

  const timeout = parseInt(process.env.MCP_TIMEOUT_MS || '30000', 10);

  try {
    const response = await axios.post(url, body, {
      headers,
      timeout,
    });
    return response.data;
  } catch (error: any) {
    const errMsg = error.response?.data
      ? (typeof error.response.data === 'object' ? JSON.stringify(error.response.data) : String(error.response.data))
      : error.message;
    throw new Error(`Upstream server connection failed: ${errMsg}`);
  }
}

export function fireAlert(tenantId: string, eventType: string, reason: string, dbPool: Pool) {
  dbPool.query(`SELECT id FROM alert_rules WHERE tenant_id=$1 AND event_type=$2 AND active=true LIMIT 1`,
    [tenantId, eventType]).then(r => {
      if (!r.rows.length) return;
      dispatchAlert({ tenantId, ruleId: r.rows[0].id, ruleName: eventType, severity: 'critical',
        eventType, message: reason, details: { reason }, triggeredAt: new Date() }, dbPool).catch(()=>{});
    }).catch(()=>{});
}

bootstrap().catch(err => { console.error('Fatal startup error:', err); process.exit(1); });
