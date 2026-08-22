import { validateUcpCall, ucpPlugin } from '../security/ucp_shield';
import Fastify from 'fastify';

describe('UCP Shield - validateUcpCall', () => {
  let mockDb: any;
  const tenantId = 'c71bee1e-5d56-4f65-9495-b580dafb90f6';
  const agentId = 'agent-shopping-1';

  beforeEach(() => {
    mockDb = {
      query: jest.fn(),
    };
  });

  // 1. Cart Management
  describe('Cart Management', () => {
    it('creates a new cart session if none exists', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // select count
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // insert

      const res = await validateUcpCall(tenantId, agentId, 'cart/add', {
        items: [{ name: 'Laptop', price: 999.99, quantity: 1 }]
      }, mockDb);

      expect(res.decision).toBe('allow');
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT session_id'),
        [tenantId, agentId]
      );
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO ucp_cart_sessions'),
        expect.any(Array)
      );
    });

    it('updates an existing cart session', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [{ session_id: 'session-123', items_json: [] }] }); // select
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // update

      const res = await validateUcpCall(tenantId, agentId, 'cart/update', {
        items: [{ name: 'Phone', price: 499.99, quantity: 2 }]
      }, mockDb);

      expect(res.decision).toBe('allow');
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE ucp_cart_sessions'),
        [expect.any(String), 'session-123']
      );
    });
  });

  // 2. Checkout / Payment Price Integrity
  describe('Checkout / Payment Integrity', () => {
    it('allows checkout if requested total matches stored cart total', async () => {
      // Mock cart items
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          items_json: [
            { name: 'Book', price: 10.00, quantity: 2 },
            { name: 'Pen', price: 2.50, quantity: 1 }
          ]
        }]
      }); // select cart

      // Mock limits (below limit, transaction limit is $50, daily is $200)
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          max_per_transaction: '50.00',
          daily_limit: '200.00',
          current_daily_spend: '0.00',
          last_reset_at: new Date().toISOString()
        }]
      }); // select limits

      mockDb.query.mockResolvedValueOnce({ rows: [] }); // update limits spend

      const res = await validateUcpCall(tenantId, agentId, 'checkout/execute', {
        amount: '22.50'
      }, mockDb);

      expect(res.decision).toBe('allow');
    });

    it('blocks checkout if requested total does not match stored cart total', async () => {
      mockDb.query.mockResolvedValueOnce({
        rows: [{
          items_json: [
            { name: 'Book', price: 10.00, quantity: 2 }
          ]
        }]
      }); // select cart

      const res = await validateUcpCall(tenantId, agentId, 'checkout/execute', {
        amount: '100.00' // Expected 20.00
      }, mockDb);

      expect(res.decision).toBe('block');
      expect(res.reason).toContain('Cart price mismatch');
    });
  });

  // 3. Spending Limits & HITL Transition
  describe('Spending Limits', () => {
    it('redirects to HITL if transaction exceeds single purchase limit', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // select cart empty

      mockDb.query.mockResolvedValueOnce({
        rows: [{
          max_per_transaction: '50.00',
          daily_limit: '200.00',
          current_daily_spend: '0.00',
          last_reset_at: new Date().toISOString()
        }]
      }); // select limits

      const res = await validateUcpCall(tenantId, agentId, 'checkout/execute', {
        amount: '75.00' // Limit is 50.00
      }, mockDb);

      expect(res.decision).toBe('hitl');
      expect(res.reason).toContain('exceeds single-purchase limit');
    });

    it('redirects to HITL if transaction exceeds daily cumulative spend limit', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // select cart empty

      mockDb.query.mockResolvedValueOnce({
        rows: [{
          max_per_transaction: '50.00',
          daily_limit: '200.00',
          current_daily_spend: '180.00',
          last_reset_at: new Date().toISOString()
        }]
      }); // select limits

      const res = await validateUcpCall(tenantId, agentId, 'checkout/execute', {
        amount: '30.00' // 180 + 30 = 210 > 200 daily limit
      }, mockDb);

      expect(res.decision).toBe('hitl');
      expect(res.reason).toContain('would exceed daily spending limit');
    });

    it('resets cumulative daily spend if last reset was before today', async () => {
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // select cart empty

      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      mockDb.query.mockResolvedValueOnce({
        rows: [{
          max_per_transaction: '50.00',
          daily_limit: '200.00',
          current_daily_spend: '180.00',
          last_reset_at: yesterday.toISOString()
        }]
      }); // select limits

      mockDb.query.mockResolvedValueOnce({ rows: [] }); // update reset spend to 0
      mockDb.query.mockResolvedValueOnce({ rows: [] }); // update spend limit for current checkout

      const res = await validateUcpCall(tenantId, agentId, 'checkout/execute', {
        amount: '30.00' // should be allowed as daily spend is reset to 0
      }, mockDb);

      expect(res.decision).toBe('allow');
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE ucp_spending_limits SET current_daily_spend = 0.00'),
        [tenantId, agentId]
      );
    });
  });

  // 4. Loyalty & Identity DLP Checks
  describe('Loyalty & Identity DLP Redaction', () => {
    it('redacts credit card numbers in identity/loyalty payloads', async () => {
      const payload = {
        member: {
          name: 'Alice Smith',
          card: '4111111111111111', // Visa credit card number
          nested: {
            cc: '5105105105105105' // Mastercard
          }
        }
      };

      const res = await validateUcpCall(tenantId, agentId, 'loyalty/register', payload, mockDb);

      expect(res.decision).toBe('allow');
      expect(res.reason).toContain('Sensitive PII redacted');
      expect(payload.member.card).toBe('[REDACTED_UCP_CARD]');
      expect(payload.member.nested.cc).toBe('[REDACTED_UCP_CARD]');
    });

    it('redacts SSNs in identity/loyalty payloads', async () => {
      const payload = {
        profile: {
          name: 'Bob Jones',
          ssn: '000-12-3456'
        }
      };

      const res = await validateUcpCall(tenantId, agentId, 'identity/link', payload, mockDb);

      expect(res.decision).toBe('allow');
      expect(res.reason).toContain('Sensitive PII redacted');
      expect(payload.profile.ssn).toBe('[REDACTED_UCP_SSN]');
    });

    it('does not mutate clean payloads', async () => {
      const payload = {
        profile: {
          name: 'Bob Jones',
          email: 'bob@example.com'
        }
      };

      const res = await validateUcpCall(tenantId, agentId, 'identity/link', payload, mockDb);

      expect(res.decision).toBe('allow');
      expect(res.reason).toBeUndefined();
      expect(payload.profile.name).toBe('Bob Jones');
      expect(payload.profile.email).toBe('bob@example.com');
    });
  });
});

describe('UCP Shield REST APIs - ucpPlugin', () => {
  let fastify: any;
  let mockDb: any;
  const tenantId = 'c71bee1e-5d56-4f65-9495-b580dafb90f6';

  beforeAll(async () => {
    mockDb = {
      query: jest.fn(),
    };

    fastify = Fastify();
    fastify.addHook('onRequest', async (req: any) => {
      req.headers['x-tenant-id'] = tenantId;
    });

    await fastify.register(ucpPlugin, { db: mockDb });
    await fastify.ready();
  });

  afterAll(async () => {
    await fastify.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('GET /api/ucp/limits returns list of limits', async () => {
    const limits = [
      { tenant_id: tenantId, agent_id: 'agent-1', max_per_transaction: '50.00', daily_limit: '200.00' }
    ];
    mockDb.query.mockResolvedValueOnce({ rows: limits });

    const response = await fastify.inject({
      method: 'GET',
      url: '/api/ucp/limits'
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ limits });
    expect(mockDb.query).toHaveBeenCalledWith(
      expect.stringContaining('SELECT * FROM ucp_spending_limits'),
      [tenantId]
    );
  });

  it('POST /api/ucp/limits upserts a limit', async () => {
    const limit = { tenant_id: tenantId, agent_id: 'agent-1', max_per_transaction: 100.00, daily_limit: 500.00 };
    mockDb.query.mockResolvedValueOnce({ rows: [limit] });

    const response = await fastify.inject({
      method: 'POST',
      url: '/api/ucp/limits',
      payload: {
        agentId: 'agent-1',
        maxPerTransaction: 100.00,
        dailyLimit: 500.00
      }
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ limit });
    expect(mockDb.query).toHaveBeenCalledWith(
      expect.stringContaining('INSERT INTO ucp_spending_limits'),
      [tenantId, 'agent-1', 100.00, 500.00]
    );
  });

  it('DELETE /api/ucp/limits/:agentId removes a limit', async () => {
    mockDb.query.mockResolvedValueOnce({ rowCount: 1 });

    const response = await fastify.inject({
      method: 'DELETE',
      url: '/api/ucp/limits/agent-1'
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ removed: true });
    expect(mockDb.query).toHaveBeenCalledWith(
      expect.stringContaining('DELETE FROM ucp_spending_limits'),
      [tenantId, 'agent-1']
    );
  });

  it('GET /api/ucp/cart-sessions returns list of active sessions', async () => {
    const sessions = [
      { session_id: 'session-1', agent_id: 'agent-1', items_json: [], created_at: new Date().toISOString() }
    ];
    mockDb.query.mockResolvedValueOnce({ rows: sessions });

    const response = await fastify.inject({
      method: 'GET',
      url: '/api/ucp/cart-sessions'
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ sessions });
    expect(mockDb.query).toHaveBeenCalledWith(
      expect.stringContaining('SELECT session_id'),
      [tenantId]
    );
  });

  it('DELETE /api/ucp/cart-sessions/:sessionId clears session', async () => {
    mockDb.query.mockResolvedValueOnce({ rowCount: 1 });

    const response = await fastify.inject({
      method: 'DELETE',
      url: '/api/ucp/cart-sessions/session-1'
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.payload)).toEqual({ removed: true });
    expect(mockDb.query).toHaveBeenCalledWith(
      expect.stringContaining('DELETE FROM ucp_cart_sessions'),
      [tenantId, 'session-1']
    );
  });
});
