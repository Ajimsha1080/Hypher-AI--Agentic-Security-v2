# MCP Security Gateway — Shared Responsibility Model

> Required by enterprise legal and procurement teams before contract sign-off.
> Version 3.0 · Effective April 2026

---

## Overview

Security of AI agent infrastructure is a shared responsibility between Antigravity (the service provider) and the Customer. This document defines what Antigravity is responsible for, what the Customer is responsible for, and what is jointly managed.

---

## Cloud Hosted Tier (*.mcpsecurity.dev)

### Antigravity is responsible for:

| Area | Responsibility |
|---|---|
| **Infrastructure security** | Physical security of data centres (AWS), network segmentation, DDoS protection |
| **Platform availability** | 99.9% uptime SLA, automatic failover, health monitoring |
| **Software security** | Vulnerability patching of the gateway codebase within 30 days of CVE disclosure |
| **Data encryption** | Encryption at rest (AES-256) and in transit (TLS 1.3) for all customer data |
| **Tenant isolation** | Row-level security ensuring tenant A cannot access tenant B's data |
| **Audit log integrity** | Hash-chained tamper-evident logs; Antigravity cannot alter logs retroactively |
| **SOC 2 Type II compliance** | Annual SOC 2 audit of the shared platform |
| **Incident response** | Notification within 72 hours of any data breach per GDPR Article 33 |
| **Backups** | Daily automated backups with 30-day retention; restore capability within 4 hours |
| **GDPR data processing** | Acting as Data Processor; processing data only per Customer instructions |

### Customer is responsible for:

| Area | Responsibility |
|---|---|
| **Agent identity management** | Rotating API keys, revoking compromised tokens |
| **Policy configuration** | Setting appropriate RBAC policies for each agent |
| **End-user access control** | Who in your org can access the dashboard and admin panel |
| **MCP server security** | Security of the upstream MCP tool servers your agents connect to |
| **Compliance with applicable law** | HIPAA, CCPA, GDPR as Data Controller; obtaining end-user consent |
| **Secret handling** | Not embedding API keys in agent prompts or tool arguments |
| **Alert rule configuration** | Setting up Slack/PagerDuty alerts appropriate for your risk tolerance |
| **SSO IdP security** | Security of your Okta/Azure AD identity provider |

---

## Self-Hosted / VPC Tier

When Customer deploys MCP Security Gateway in their own VPC:

### Antigravity is responsible for:

| Area | Responsibility |
|---|---|
| **Software quality** | Gateway codebase, security of the application layer |
| **Security updates** | Releasing patches for discovered vulnerabilities; notifying customers within 48h |
| **Documentation** | Deployment guides, security configuration documentation |
| **Support** | Responding to security questions within SLA |

### Customer is responsible for:

**Everything in the cloud tier Customer responsibilities PLUS:**

| Area | Responsibility |
|---|---|
| **Infrastructure security** | VPC configuration, security groups, NACLs |
| **Patching** | Applying Antigravity-released updates in a timely manner |
| **Database security** | RDS/PostgreSQL access controls, encryption configuration |
| **Network security** | Ensuring the gateway is not exposed to the public internet (if not intended) |
| **Backup and recovery** | Database backup strategy and tested restore procedures |
| **Availability** | Multi-AZ deployment, auto-scaling configuration |
| **Certificate management** | TLS certificate rotation for your custom domain |

---

## Data Classification

| Data Type | Location | Controller | Processor | Retention |
|---|---|---|---|---|
| Audit logs (tool calls, decisions) | Customer's DB | Customer | Antigravity (hosted) / Customer (VPC) | Configurable (7–365 days) |
| Agent API keys (hashed) | Customer's DB | Customer | Antigravity (hosted) / Customer (VPC) | Until revoked |
| Tool call arguments | Audit log + DLP scan cache | Customer | Antigravity | Per retention policy |
| Dashboard user sessions | Redis (ephemeral) | Customer | Antigravity (hosted) | Session duration |
| Stripe billing data | Stripe (PCI-DSS Level 1) | Antigravity | Stripe | Per Stripe policy |
| Support communications | Antigravity systems | Antigravity | — | 3 years |

---

## Penetration Testing

Antigravity conducts an annual third-party penetration test of the shared cloud platform. The most recent report executive summary is available to Enterprise customers under NDA.

Customers on the VPC tier may conduct their own penetration tests against their deployment without prior approval, provided they:
- Do not test shared infrastructure (only their own VPC resources)
- Do not attempt to access other tenants' data
- Notify `security@mcpsecurity.dev` before testing begins

---

## Vulnerability Disclosure

To report a security vulnerability: `security@mcpsecurity.dev`  
PGP key available at: `https://mcpsecurity.dev/.well-known/security.txt`  
Response SLA: 48 hours for critical, 7 days for others  
Bug bounty: Paid for critical and high severity findings

---

## HIPAA Business Associate Agreement

Customers processing PHI (Protected Health Information) through the gateway must execute a BAA with Antigravity before going live. Contact `enterprise@mcpsecurity.dev` to request the standard BAA template. The BAA is included in all Enterprise plan contracts at no additional cost.

---

## GDPR Data Processing Agreement

A DPA (Data Processing Agreement) compliant with GDPR Article 28 is automatically incorporated into all contracts for customers in the European Economic Area. The DPA specifies:
- Sub-processors used (AWS, Stripe, Resend)
- Data residency options (EU-West region available on Growth+ plans)
- Data subject rights handling procedures
- Cross-border transfer mechanisms (SCCs)

---

*Last updated: April 2026 · Questions: legal@mcpsecurity.dev*
