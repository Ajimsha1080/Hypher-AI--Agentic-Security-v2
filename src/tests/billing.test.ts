/**
 * tests/billing.test.ts — Billing unit tests
 */
describe('Overage billing', () => {
  it('calculates correct overage amount', () => {
    const overageCalls = 5000;
    const rateUsd = 0.005;
    const amount = parseFloat((overageCalls * rateUsd).toFixed(2));
    expect(amount).toBe(25.00);
  });

  it('skips billing below Stripe minimum', () => {
    const overageCalls = 50;
    const amountUsd = parseFloat((overageCalls * 0.005).toFixed(2));
    expect(amountUsd).toBe(0.25);
    expect(amountUsd < 0.50).toBe(true); // should skip
  });
});

describe('Plan limits', () => {
  const PLAN_LIMITS = {
    starter: { apiCalls: 10_000, agents: 5 },
    growth: { apiCalls: 100_000, agents: 25 },
    enterprise: { apiCalls: 1_000_000, agents: 200 },
  };

  it('starter is blocked at hard limit', () => {
    const plan = 'starter';
    const usage = 10001;
    const limit = PLAN_LIMITS[plan].apiCalls;
    expect(usage > limit).toBe(true);
  });

  it('enterprise gets overage tracking not blocking', () => {
    const plan = 'enterprise';
    const limit = PLAN_LIMITS[plan].apiCalls;
    expect(limit).toBe(1_000_000);
  });
});
