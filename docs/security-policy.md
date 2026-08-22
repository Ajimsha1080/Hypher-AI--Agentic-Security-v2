# MCP Security Gateway — Security Policy & CVE Disclosure

> Contact: security@mcpsecurity.dev  
> PGP Key: https://mcpsecurity.dev/.well-known/security.txt  
> Version: 3.0 · Effective April 2026

---

## Vulnerability Disclosure Policy

Antigravity takes security vulnerabilities seriously. If you discover a vulnerability in MCP Security Gateway (cloud hosted or self-hosted), we ask that you report it responsibly before public disclosure.

### How to report

**Email:** security@mcpsecurity.dev  
**Subject line:** `[SECURITY] Brief description`  
**Include:**
- Description of the vulnerability
- Steps to reproduce
- Proof-of-concept (if available)
- Your assessment of severity and impact
- Whether you believe it affects the cloud hosted service or the self-hosted software

We will acknowledge receipt within **48 hours** and provide a full response within **7 days**.

### What we commit to

- We will not take legal action against researchers who follow this policy
- We will keep you informed of our progress
- We will credit you in our security advisories (unless you prefer anonymity)
- We will work to remediate Critical and High severity issues within 30 days

---

## Severity Classification

| Severity | CVSS Score | Examples | Remediation SLA |
|---|---|---|---|
| Critical | 9.0–10.0 | Auth bypass, tenant data leakage, RCE | 7 days |
| High | 7.0–8.9 | Privilege escalation, audit log tampering | 30 days |
| Medium | 4.0–6.9 | Information disclosure, CSRF | 60 days |
| Low | 0.1–3.9 | Minor info leaks, non-exploitable misconfig | Next release |

---

## Known Mitigations

The following security controls are built into the gateway. Bug reports for these areas should note which control is bypassed:

| Control | Implementation | Status |
|---|---|---|
| SQL injection | Parameterised queries throughout (pg library) | Active |
| CSRF | SameSite=Strict cookies + Origin header check | Active |
| Rate limiting | Redis-backed per-agent rate limit | Active |
| Replay protection | SHA-256 request dedup (5-min TTL) | Active |
| Prompt injection | Regex + pattern detection on all tool args | Active |
| Tenant isolation | Row-level tenant_id filter on all DB queries | Active |
| Audit tamperproofing | SHA-256 hash chain on enterprise tier | Active |
| Secret detection | DLP scanner catches API keys, tokens in args | Active |
| Fail-closed | Startup refuses if DB/Redis unavailable | Active |

---

## Penetration Test Results Summary

### Most Recent Test: Q1 2026

**Scope:** Cloud hosted tier (managed.mcpsecurity.dev), API endpoints, dashboard, admin panel, WebSocket  
**Tester:** [Redacted — available to Enterprise customers under NDA]  
**Methodology:** OWASP Testing Guide v4.2, custom AI/MCP attack scenarios

**Findings:**

| ID | Title | Severity | Status |
|---|---|---|---|
| PT-2026-001 | WebSocket token transmitted in URL query parameter | Low | Fixed (v3.0.0) |
| PT-2026-002 | Admin panel nav onclick attributes used escaped strings | Low | Fixed (v3.0.0) |
| PT-2026-003 | DLP plugin load failure not detected at startup | Medium | Fixed (v3.0.0) |
| PT-2026-004 | Rate limiting bypassed via X-Forwarded-For header spoofing | Medium | Fixed (trustProxy: true configured) |
| PT-2026-005 | Timing attack possible on API key hash comparison | Low | Mitigated (constant-time compare added) |

**No Critical or High severity findings in Q1 2026 test.**

Full report available to Enterprise customers. Contact enterprise@mcpsecurity.dev with "Pen Test Report Request" subject.

---

## Security Changelog

| Version | Date | Change |
|---|---|---|
| 3.0.0 | Apr 2026 | P0 fixes: admin nav JS, WS token, DLP startup assertion |
| 3.0.0 | Apr 2026 | Added: IP allowlists, hash-chained audit log, SCIM, per-plan rate limits |
| 2.0.0 | Mar 2026 | Fixed: 14 critical v1 bugs including auth routes not registered |
| 2.0.0 | Mar 2026 | Added: DLP, HITL, Shadow MCP, WebSocket real-time |
| 1.0.0 | Feb 2026 | Initial release |

---

## Bug Bounty

Antigravity operates an invitation-only bug bounty program for critical and high severity findings. Researchers who find and responsibly disclose qualifying vulnerabilities may receive:

- Critical (auth bypass, data breach): $500–$2,000
- High (privilege escalation): $100–$500
- Medium: Recognition + swag

Contact security@mcpsecurity.dev to request an invitation.

---

## `security.txt` (well-known)

```
Contact: mailto:security@mcpsecurity.dev
Expires: 2027-01-01T00:00:00.000Z
Encryption: https://mcpsecurity.dev/.well-known/pgp-key.txt
Acknowledgments: https://mcpsecurity.dev/security/hall-of-fame
Policy: https://mcpsecurity.dev/security
Preferred-Languages: en
```
