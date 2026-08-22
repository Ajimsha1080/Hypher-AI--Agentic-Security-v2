# MCP Security Gateway — Bug Report & Roadmap
**Version:** v3.1.0 → v3.3.0 (all bugs fully fixed)
**Date:** April 2026
**Files Changed:**
- `src/proxy/server.ts` — Bug #1 z-score fallback, Bug #4 budget enforcement, Bug #6 args_length
- `src/anomaly/detector.ts` — Bug #1 bootstrap protection
- `src/auth/oauth.ts` — Bug #5 token expiry at auth time
- `src/cron/scheduler.ts` — Bug #5 key expiry cron (cleanup layer)
- `src/tests/security.test.ts` — 30 new regression tests (sections 13–17)
- `tsconfig.json` — Added (was missing from repository)
- `Dockerfile` — Added (was missing from repository)

---

## Bugs Fixed in v3.3.0

### Bug #1 — Bootstrap anomaly bypass (Critical)
**Files:** `src/anomaly/detector.ts`, `src/proxy/server.ts`

New agents (0-20 calls) had ZERO anomaly protection. The z-score fallback returned
`isAnomaly: false` immediately for any agent without a mature baseline — attackers
could exploit the warm-up window freely.

Fix: Bootstrap burst guard (>30 calls/min flags new agents). Partial baselines
(20-99 samples) now run with relaxed thresholds instead of skipping entirely.
Z-score fallback results now actioned in server.ts (block + audit on flag).

### Bug #2 — fastify.hasRoute() crashed server (Critical)
Removed in Fastify v5. Server would not start at all. Fixed in v3.1.0, verified absent. ✅

### Bug #3 — snake_case vs camelCase mismatch (Critical)
All z-score calculations produced NaN/0. `baseline.topTools` was undefined because
PostgreSQL returns `top_tools` (snake_case) but the interface expected `topTools`.
Full mapping added in v3.1.0, verified with 6 regression tests. ✅

### Bug #4 — Budget enforcement: silent failure + off-by-one (High)
Two issues: (A) `.catch(() => null)` disabled enforcement on any DB error — now
fail-safe blocks with 503. (B) `audit_log` COUNT is one behind the in-flight request
— now uses `callsInLog + 1` before comparing against limit.

### Bug #5 — Expired API keys bypassed auth (High)
`verifyBearerToken()` queried `WHERE active = true` without checking `expires_at`.
Rotated keys remained valid for up to 5 minutes (one cron cycle).
Fix: `AND (expires_at IS NULL OR expires_at > NOW())` added to auth query.

### Bug #6 — args_length column stored wrong value (Medium)
`logAudit()` stored `inspectionResult` JSON length for `args_length` — wrong in every
case. Now computes `JSON.stringify(args).length` at top of `/mcp` handler and passes
it through all 14 `logAudit()` call sites.

---

## Test Suite (v3.3.0) — 17 sections, 85 test cases

| Sections 1-12 (v3.1.0) | 55 tests | Injection, DLP, RBAC, Budget, Keys, Templates |
| Section 13: Bug #1 bootstrap | 5 tests | Burst guard, partial baseline thresholds |
| Section 14: Bug #2 no hasRoute | 2 tests | File scan confirms hasRoute absent |
| Section 15: Bug #3 mapping | 6 tests | Every snake_case→camelCase field |
| Section 16: Bug #4 budget | 5 tests | Off-by-one, parseInt, fail-safe |
| Section 17: Bug #5 token expiry | 6 tests | Query guard, null/past/future expires_at |
| **Total** | **85 tests** | |

---

## Pricing

| Plan | Price | API Calls/mo | Agents | Overage |
|------|-------|--------------|--------|---------|
| Starter | $49/mo | 10,000 | 5 | Hard block |
| Growth | $199/mo | 100,000 | 25 | $0.005/call |
| Enterprise | $999/mo | 1,000,000 | 200 | $0.005/call |

---

*MCP Security Gateway v3.3.0 — Antigravity*
