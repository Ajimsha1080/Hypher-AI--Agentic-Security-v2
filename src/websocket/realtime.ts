/**
 * Real-Time WebSocket Dashboard
 *
 * Replaces 15-second polling with live push via WebSocket.
 * Uses @fastify/websocket + Redis pub/sub so events flow:
 *
 *   MCP Request → proxy pipeline → Redis PUBLISH → WS server → browser
 *
 * Channels:
 *   audit:{tenantId}      — every allow/deny event in real time
 *   alerts:{tenantId}     — security alerts as they fire
 *   metrics:{tenantId}    — rolling 1-minute metric updates
 *   hitl:{tenantId}       — new HITL approval requests
 *   dlp:{tenantId}        — DLP detections
 *
 * Client usage (browser):
 *   const ws = new WebSocket('wss://your-gateway.com/ws?token=...');
 *   ws.onmessage = (e) => { const event = JSON.parse(e.data); ... };
 *
 * Event shape:
 *   { channel: 'audit', tenantId, payload: { ... } }
 */

import { FastifyInstance } from 'fastify';
import { Pool } from 'pg';
import Redis from 'ioredis';
import crypto from 'crypto';

export interface WsEvent {
  channel: 'audit' | 'alert' | 'metrics' | 'hitl' | 'dlp';
  tenantId: string;
  payload: Record<string, unknown>;
  ts: string;
}

// ── Publisher — called from proxy pipeline after every event ──────────

export async function publishAuditEvent(
  redis: Redis,
  tenantId: string,
  event: {
    agentId: string; toolName: string; decision: string;
    reason?: string; executionTimeMs?: number; authProvider?: string;
    dlpTriggered?: boolean; hitlRequired?: boolean;
  }
): Promise<void> {
  const msg: WsEvent = {
    channel: 'audit',
    tenantId,
    payload: { ...event, ts: new Date().toISOString() },
    ts: new Date().toISOString(),
  };
  await redis.publish(`ws:audit:${tenantId}`, JSON.stringify(msg)).catch(() => {});
}

export async function publishAlert(
  redis: Redis,
  tenantId: string,
  alert: { severity: string; eventType: string; message: string; details: Record<string, unknown> }
): Promise<void> {
  const msg: WsEvent = {
    channel: 'alert',
    tenantId,
    payload: alert,
    ts: new Date().toISOString(),
  };
  await redis.publish(`ws:alert:${tenantId}`, JSON.stringify(msg)).catch(() => {});
}

export async function publishDlpEvent(
  redis: Redis,
  tenantId: string,
  event: { agentId: string; toolName: string; types: string[]; blocked: boolean; direction: string }
): Promise<void> {
  const msg: WsEvent = {
    channel: 'dlp',
    tenantId,
    payload: event,
    ts: new Date().toISOString(),
  };
  await redis.publish(`ws:dlp:${tenantId}`, JSON.stringify(msg)).catch(() => {});
}

export async function publishHitlRequest(
  redis: Redis,
  tenantId: string,
  approval: { approvalId: string; agentId: string; toolName: string; riskReason: string; expiresAt: Date }
): Promise<void> {
  const msg: WsEvent = {
    channel: 'hitl',
    tenantId,
    payload: { ...approval, expiresAt: approval.expiresAt.toISOString() },
    ts: new Date().toISOString(),
  };
  await redis.publish(`ws:hitl:${tenantId}`, JSON.stringify(msg)).catch(() => {});
}

// ── WebSocket Fastify plugin ──────────────────────────────────────────

export async function wsPlugin(
  fastify: FastifyInstance,
  opts: { db: Pool; redis: Redis }
): Promise<void> {
  const { db, redis } = opts;

  // Each WS connection gets its own Redis subscriber
  // (subscriber must be a separate Redis connection from the publisher)

  fastify.get('/ws', { websocket: true } as any, async (connection: any, req: any) => {
    const socket = connection.socket;
    let tenantId: string | null = null;
    let subscriber: Redis | null = null;
    let metricsInterval: NodeJS.Timeout | null = null;

    // ── Auth handshake ───────────────────────────────────────────────
    const token = new URL(req.url, 'http://localhost').searchParams.get('token');
    if (!token) {
      socket.send(JSON.stringify({ error: 'Missing token' }));
      socket.close();
      return;
    }

    try {
      // Validate session token (same as REST API auth)
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const session = await redis.get(`session:${tokenHash}`);
      if (!session) {
        socket.send(JSON.stringify({ error: 'Invalid or expired token' }));
        socket.close();
        return;
      }
      const sessionData = JSON.parse(session);
      tenantId = sessionData.tenantId;
    } catch {
      socket.send(JSON.stringify({ error: 'Auth failed' }));
      socket.close();
      return;
    }

    // ── Connected ────────────────────────────────────────────────────
    socket.send(JSON.stringify({
      type: 'connected',
      tenantId,
      message: 'Real-time stream active',
      channels: ['audit', 'alert', 'metrics', 'hitl', 'dlp'],
    }));

    // ── Subscribe to Redis channels for this tenant ──────────────────
    subscriber = new Redis(process.env.REDIS_URL!, { maxRetriesPerRequest: 3 });

    const channels = [
      `ws:audit:${tenantId}`,
      `ws:alert:${tenantId}`,
      `ws:dlp:${tenantId}`,
      `ws:hitl:${tenantId}`,
    ];

    await subscriber.subscribe(...channels);

    subscriber.on('message', (channel: string, message: string) => {
      if (socket.readyState === 1 /* OPEN */) {
        socket.send(message);
      }
    });

    // ── Rolling metrics push every 30s ───────────────────────────────
    metricsInterval = setInterval(async () => {
      if (socket.readyState !== 1 || !tenantId) return;
      try {
        const r = await db.query(`
          SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE decision='DENY') as denied,
            AVG(execution_time_ms) as avg_ms,
            COUNT(DISTINCT agent_id) as agents
          FROM audit_log
          WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '1 minute'`,
          [tenantId]
        );
        const s = r.rows[0];
        socket.send(JSON.stringify({
          type: 'metrics',
          tenantId,
          payload: {
            calls1m: parseInt(s.total, 10) || 0,
            denials1m: parseInt(s.denied, 10) || 0,
            avgMs: Math.round(parseFloat(s.avg_ms) || 0),
            activeAgents: parseInt(s.agents, 10) || 0,
          },
          ts: new Date().toISOString(),
        }));
      } catch { /* non-fatal */ }
    }, 30_000);

    // ── Send initial snapshot on connect ─────────────────────────────
    try {
      const [metrics, recent] = await Promise.all([
        db.query(`
          SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE decision='DENY') as denied,
                 AVG(execution_time_ms) as avg_ms, COUNT(DISTINCT agent_id) as agents
          FROM audit_log WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '1h'`,
          [tenantId]
        ),
        db.query(`
          SELECT agent_id, tool_name, decision, reason, execution_time_ms, created_at
          FROM audit_log WHERE tenant_id=$1
          ORDER BY created_at DESC LIMIT 20`,
          [tenantId]
        ),
      ]);
      socket.send(JSON.stringify({
        type: 'snapshot',
        tenantId,
        payload: {
          metrics: metrics.rows[0],
          recentEvents: recent.rows,
        },
        ts: new Date().toISOString(),
      }));
    } catch { /* non-fatal */ }

    // ── Handle client messages (ping, filter changes) ─────────────────
    socket.on('message', (data: Buffer) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'ping') {
          socket.send(JSON.stringify({ type: 'pong', ts: new Date().toISOString() }));
        }
      } catch { /* ignore malformed */ }
    });

    // ── Cleanup on disconnect ─────────────────────────────────────────
    socket.on('close', () => {
      if (metricsInterval) clearInterval(metricsInterval);
      if (subscriber) {
        subscriber.unsubscribe(...channels).then(() => subscriber!.quit()).catch(() => {});
      }
    });

    socket.on('error', () => {
      if (metricsInterval) clearInterval(metricsInterval);
      if (subscriber) subscriber.quit().catch(() => {});
    });
  });
}

// ── Helper: broadcast from anywhere in the app ─────────────────────────

export function createWsPublisher(redis: Redis) {
  return {
    auditEvent: (tenantId: string, event: Parameters<typeof publishAuditEvent>[2]) =>
      publishAuditEvent(redis, tenantId, event),
    alert: (tenantId: string, alert: Parameters<typeof publishAlert>[2]) =>
      publishAlert(redis, tenantId, alert),
    dlpEvent: (tenantId: string, event: Parameters<typeof publishDlpEvent>[2]) =>
      publishDlpEvent(redis, tenantId, event),
    hitlRequest: (tenantId: string, approval: Parameters<typeof publishHitlRequest>[2]) =>
      publishHitlRequest(redis, tenantId, approval),
  };
}
