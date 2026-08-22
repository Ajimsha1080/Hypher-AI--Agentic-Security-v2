import { Pool } from 'pg';
import crypto from 'crypto';
import { FastifyInstance } from 'fastify';
import { requestTenantId } from '../utils/request-context';

function redactUcpPiiRecursive(obj: any): boolean {
  let redacted = false;
  if (!obj || typeof obj !== 'object') return false;

  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === 'string') {
      // Credit card check
      const cardPattern = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g;
      if (cardPattern.test(val)) {
        obj[key] = '[REDACTED_UCP_CARD]';
        redacted = true;
      }
      // SSN check
      const ssnPattern = /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g;
      if (ssnPattern.test(val)) {
        obj[key] = '[REDACTED_UCP_SSN]';
        redacted = true;
      }
    } else if (typeof val === 'object' && val !== null) {
      if (redactUcpPiiRecursive(val)) {
        redacted = true;
      }
    }
  }
  return redacted;
}


interface UcpItem {
  id?: string;
  name: string;
  price: number; // In standard currency units (e.g. Dollars)
  quantity: number;
}

export async function validateUcpCall(
  tenantId: string,
  agentId: string,
  method: string,
  params: any,
  db: Pool
): Promise<{ decision: 'allow' | 'block' | 'hitl'; reason?: string }> {
  // Normalize method
  const m = method.toLowerCase();

  // 1. Handle Cart Management calls
  if (m.includes('cart/add') || m.includes('cart/update') || m.includes('cart/item')) {
    // Expecting params.items to be an array of UcpItem
    const items: UcpItem[] = params?.items || (params?.item ? [params.item] : []);

    try {
      const selectRes = await db.query(
        'SELECT session_id, items_json FROM ucp_cart_sessions WHERE tenant_id = $1 AND agent_id = $2',
        [tenantId, agentId]
      );

      if (selectRes.rows.length > 0) {
        const sessionId = selectRes.rows[0].session_id;
        // Merge or replace items based on update method
        await db.query(
          'UPDATE ucp_cart_sessions SET items_json = $1, updated_at = NOW() WHERE session_id = $2',
          [JSON.stringify(items), sessionId]
        );
      } else {
        const sessionId = crypto.randomUUID();
        await db.query(
          'INSERT INTO ucp_cart_sessions (session_id, tenant_id, agent_id, items_json) VALUES ($1, $2, $3, $4)',
          [sessionId, tenantId, agentId, JSON.stringify(items)]
        );
      }
    } catch (err: any) {
      return { decision: 'block', reason: `UCP Shield DB Error: ${err.message}` };
    }
    return { decision: 'allow' };
  }

  // 2. Handle Checkout and Payment calls
  if (m.includes('checkout') || m.includes('payment')) {
    // Total price requested in this checkout transaction
    const checkoutAmount = parseFloat(params?.amount || params?.totalPrice || '0');
    const checkoutItems: UcpItem[] = params?.items || [];

    try {
      // Retrieve stored cart session for validation
      const cartRes = await db.query(
        'SELECT items_json FROM ucp_cart_sessions WHERE tenant_id = $1 AND agent_id = $2',
        [tenantId, agentId]
      );

      const savedCart: UcpItem[] = cartRes.rows.length > 0 ? cartRes.rows[0].items_json : [];

      // A. Cart Integrity: Check if pricing/items match the cart
      if (savedCart.length > 0) {
        let expectedTotal = 0;
        for (const item of savedCart) {
          expectedTotal += (item.price || 0) * (item.quantity || 1);
        }

        // If checkout total differs by more than 1 cent from expected cart sum, flag as tamper/injection
        if (Math.abs(expectedTotal - checkoutAmount) > 0.01) {
          return {
            decision: 'block',
            reason: `UCP Shield: Cart price mismatch. Expected: $${expectedTotal.toFixed(2)}, Requested: $${checkoutAmount.toFixed(2)}`
          };
        }
      }

      // B. Budget Limits: Get limits for this agent
      const limitRes = await db.query(
        'SELECT * FROM ucp_spending_limits WHERE tenant_id = $1 AND agent_id = $2',
        [tenantId, agentId]
      );

      // Default limits: max $50 per purchase, max $200 per day
      let maxPerTx = 50.00;
      let dailyLimit = 200.00;
      let currentDailySpend = 0.00;
      let hasLimitRow = false;

      if (limitRes.rows.length > 0) {
        hasLimitRow = true;
        const row = limitRes.rows[0];
        maxPerTx = parseFloat(row.max_per_transaction);
        dailyLimit = parseFloat(row.daily_limit);
        currentDailySpend = parseFloat(row.current_daily_spend);

        // Check if daily reset is needed (if last_reset_at is before today)
        const lastReset = new Date(row.last_reset_at);
        const startOfToday = new Date();
        startOfToday.setHours(0, 0, 0, 0);

        if (lastReset < startOfToday) {
          currentDailySpend = 0.00;
          await db.query(
            'UPDATE ucp_spending_limits SET current_daily_spend = 0.00, last_reset_at = NOW() WHERE tenant_id = $1 AND agent_id = $2',
            [tenantId, agentId]
          );
        }
      }

      // Check single transaction limit
      if (checkoutAmount > maxPerTx) {
        return {
          decision: 'hitl',
          reason: `UCP Shield: Purchase ($${checkoutAmount.toFixed(2)}) exceeds single-purchase limit ($${maxPerTx.toFixed(2)})`
        };
      }

      // Check daily cumulative limit
      if (currentDailySpend + checkoutAmount > dailyLimit) {
        return {
          decision: 'hitl',
          reason: `UCP Shield: Daily spend of $${(currentDailySpend + checkoutAmount).toFixed(2)} would exceed daily spending limit ($${dailyLimit.toFixed(2)})`
        };
      }

      // If approved, update cumulative daily spend
      const newDailySpend = currentDailySpend + checkoutAmount;
      if (hasLimitRow) {
        await db.query(
          'UPDATE ucp_spending_limits SET current_daily_spend = $1 WHERE tenant_id = $2 AND agent_id = $3',
          [newDailySpend, tenantId, agentId]
        );
      } else {
        await db.query(
          `INSERT INTO ucp_spending_limits (tenant_id, agent_id, max_per_transaction, daily_limit, current_daily_spend)
           VALUES ($1, $2, $3, $4, $5)`,
          [tenantId, agentId, maxPerTx, dailyLimit, newDailySpend]
        );
      }
    } catch (err: any) {
      return { decision: 'block', reason: `UCP Shield DB Error during checkout: ${err.message}` };
    }
  }

  // 3. Handle Identity and Loyalty calls for Loyalty & Identity DLP
  if (m.includes('identity') || m.includes('loyalty')) {
    let redacted = false;
    if (params) {
      redacted = redactUcpPiiRecursive(params);
    }
    return {
      decision: 'allow',
      reason: redacted ? 'UCP Shield: Sensitive PII redacted from loyalty/identity payload' : undefined
    };
  }

  return { decision: 'allow' };
}

export async function ucpPlugin(fastify: FastifyInstance, opts: { db: Pool }) {
  const { db } = opts;

  // GET /api/ucp/limits — list all agent UCP spending limits
  fastify.get('/api/ucp/limits', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT * FROM ucp_spending_limits WHERE tenant_id = $1 ORDER BY agent_id`,
      [tenantId]
    );
    return { limits: r.rows };
  });

  // POST /api/ucp/limits — set spending limits for agent
  fastify.post('/api/ucp/limits', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId, maxPerTransaction, dailyLimit } = req.body as any;
    if (!agentId || maxPerTransaction === undefined || dailyLimit === undefined) {
      return reply.code(400).send({ error: 'agentId, maxPerTransaction, and dailyLimit are required' });
    }

    const r = await db.query(
      `INSERT INTO ucp_spending_limits (tenant_id, agent_id, max_per_transaction, daily_limit)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, agent_id) DO UPDATE
         SET max_per_transaction = $3, daily_limit = $4, last_reset_at = NOW()
       RETURNING *`,
      [tenantId, agentId, parseFloat(maxPerTransaction), parseFloat(dailyLimit)]
    );
    return { limit: r.rows[0] };
  });

  // DELETE /api/ucp/limits/:agentId
  fastify.delete('/api/ucp/limits/:agentId', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { agentId } = req.params as any;
    await db.query(
      'DELETE FROM ucp_spending_limits WHERE tenant_id = $1 AND agent_id = $2',
      [tenantId, agentId]
    );
    return { removed: true };
  });

  // GET /api/ucp/cart-sessions — list all active cart sessions
  fastify.get('/api/ucp/cart-sessions', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const r = await db.query(
      `SELECT session_id, agent_id, items_json, created_at, updated_at FROM ucp_cart_sessions WHERE tenant_id = $1 ORDER BY updated_at DESC`,
      [tenantId]
    );
    return { sessions: r.rows };
  });

  // DELETE /api/ucp/cart-sessions/:sessionId — clear a cart session
  fastify.delete('/api/ucp/cart-sessions/:sessionId', async (req: any, reply) => {
    const tenantId = requestTenantId(req);
    if (!tenantId) return reply.code(401).send({ error: 'Unauthorized' });

    const { sessionId } = req.params as any;
    await db.query(
      'DELETE FROM ucp_cart_sessions WHERE tenant_id = $1 AND session_id = $2',
      [tenantId, sessionId]
    );
    return { removed: true };
  });
}

