<div align="center">
  <h1>🛡️ Hypher AI v2</h1>
  <h3>The Enterprise Firewall for Autonomous AI & Secure Multi-Agent Runtime</h3>
  <p>Zero-trust security proxy, stateful LangGraph orchestrator, and real-time observability console for AI agents. Every tool call authenticated, inspected, policy-checked, and logged.</p>

  <p>
    <a href="https://github.com/Ajimsha1080/Hypher-AI--Agentic-Security-v2"><img src="https://img.shields.io/badge/GitHub-Repository-blue?logo=github" alt="GitHub Repo"></a>
    <img src="https://img.shields.io/badge/License-Apache%202.0-green.svg" alt="License">
    <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue?logo=python" alt="Python">
    <img src="https://img.shields.io/badge/TypeScript-5.0+-blue?logo=typescript" alt="TypeScript">
    <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker" alt="Docker">
    <img src="https://img.shields.io/badge/Tests-195%20Passed-brightgreen" alt="Tests">
  </p>
</div>

---

## 📖 Overview

As enterprises adopt autonomous AI agents (such as Claude, Cursor, LangChain, AutoGen, and custom LLM workflows) via the **Model Context Protocol (MCP)**, a critical security blindspot emerges: AI agents are frequently granted unrestricted access to databases, cloud infrastructure, and private file systems.

**Hypher AI** operates as a zero-latency enterprise security proxy and multi-agent orchestrator. It intercepts, sanitizes, and evaluates all agent tool requests through a strict **10-layer zero-trust security pipeline** before anything reaches your backend infrastructure.

---

## 🏗️ Architecture & 10-Layer Security Pipeline

```text
  [ User Request / Client App / AI Agent ]
                     │
                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   HYPHER SECURE MULTI-AGENT RUNTIME                    │
│                                                                        │
│  ┌──────────────────┐      ┌──────────────────┐                        │
│  │ Supervisor Agent │ ───► │ Research/RAG     │ (Vector RAG Pipeline)  │
│  └────────┬─────────┘      └──────────────────┘                        │
│           │                                                            │
│           ▼                                                            │
│  ┌──────────────────┐      ┌──────────────────┐                        │
│  │ Tool Exec Agent  │ ───► │ Security/Policy  │ (AI Guardrails & DLP)  │
│  └────────┬─────────┘      └──────────────────┘                        │
└───────────┼────────────────────────────────────────────────────────────┘
            │
            ▼
 10-LAYER HYPHER ZERO-TRUST SECURITY GATEWAY
 1. 🔑 Auth Token     — Bearer / OAuth 2.1 Token Validation & Scope Check
 2. 🏢 Tenant Scoping — Tenant Boundary Isolation & Rate Limit Metering
 3. 🔍 Inspector      — Real-Time Prompt Injection & Adversarial Payload Detection
 4. 🌐 Registry       — Tool & MCP Server Trust Scoring & Capability Verification
 5. 🛡️ RBAC Policy    — Granular Agent Policy Allowlists & Least-Privilege Enforcer
 6. 🧠 ML Anomaly     — Behavioral Vector Baseline & Entropy Anomaly Scorer
 7. 🔄 Anti-Replay    — Cryptographic SHA-256 Nonce Deduplication
 8. 🔒 Sandbox/Lock   — Isolated Execution Sandbox & Race Condition Guard
 9. ➡️ Upstream Exec  — Upstream Execution with Human-in-the-Loop (HITL) Clearance
10. 📝 Audit Trail    — 100% Immutable Hash-Chained Audit Log & Distributed Trace
```

---

## 🖥️ 14 Interactive Security & Observability Views

Hypher AI includes a complete dark obsidian **Security Operations Console** built with Geist typography and live backend telemetry:

| View | Module | Key Features |
| :--- | :--- | :--- |
| ⚡ **Command Center** | `Overview` | Real-time throughput graphs, 10-layer pipeline visual stepper, denial rate, and top tool metrics. |
| 🤖 **Multi-Agent Studio** | `Agent Runtime` | LangGraph workflow execution, step trace inspector, Secure RAG manager, and isolated memory explorer. |
| 🛡️ **DLP & PII Masking** | `DLP Engine` | Real-time regex & NLP redaction sandbox for emails, credit cards, AWS keys, and SSNs. |
| 📜 **Audit Logs** | `Audit Trail` | Chronological, immutable audit table with per-call latency, decision status, and tenant metadata. |
| 🚨 **Threat Center** | `Threats` | Prompt injection containment logs, adversarial payload metrics, and vector anomaly scores. |
| 🔒 **Security Policies** | `Policies` | Dynamic guardrail rule builder (Deny, Require HITL Approval, PII Scrubbing). |
| 🌐 **IP & Geo Rules** | `Firewall` | CIDR allowlist manager and network boundary control. |
| ✋ **HITL Queue** | `Approvals` | Interactive approval/rejection cards for high-risk operations (e.g. database drop / shell execution). |
| 🔎 **Shadow Discovery** | `Shadow MCP` | Network scanner for rogue, unapproved, or shadow AI agent instances. |
| 📊 **Analytics** | `Telemetry` | Tool call latency distribution and multi-agent usage breakdown charts. |
| 🔔 **Alerts & SIEM** | `SIEM` | Real-time webhook dispatch to Slack, Microsoft Teams, and PagerDuty. |
| 🛡️ **SOC2 Compliance** | `Compliance` | Automated evidence collection and one-click `hypher_soc2_compliance_report.json` export. |
| 🤖 **Agent-to-Agent** | `A2A Firewall` | Peer agent discovery, mTLS authentication, and inter-agent communication boundaries. |
| 💳 **Billing & Usage** | `Billing` | Real-time tenant quota tracking, token cost counters, and tier rate limits. |

---

## ⚡ Core API Endpoints

### 1. Agent Runtime & Multi-Agent Graph
- `POST /api/v1/agent/run` — Run stateful multi-agent security task.
- `POST /api/v1/agent/stream` — SSE streaming execution trace.
- `GET /api/v1/approvals` — List pending human-in-the-loop (HITL) requests.
- `POST /api/v1/approvals/{id}/approve` — Approve pending high-risk tool call.
- `POST /api/v1/approvals/{id}/reject` — Reject pending high-risk tool call.

### 2. Secure RAG & Context Memory
- `POST /api/v1/rag/ingest` — Ingest document with prompt injection scanner.
- `POST /api/v1/rag/query` — Vector similarity search with relevance scores.
- `POST /api/v1/memory` — Store tenant-isolated memory with auto-PII scrub.
- `POST /api/v1/memory/search` — Search long-term agent memory.

### 3. Gateway Telemetry & Health
- `GET /health` & `GET /ready` — Service health and model status.
- `GET /api/dashboard/metrics` — Live real-time dashboard telemetry stream.

---

## 🚀 Quick Start & Local Run

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/Ajimsha1080/Hypher-AI--Agentic-Security-v2.git
cd "Hypher-AI--Agentic-Security-v2"

# Install Node.js & TypeScript dependencies
npm install

# Install Python Agent Runtime dependencies
pip install -r requirements.txt
```

### 2. Start Services Locally
```bash
# Terminal 1: Start Dashboard Server & API Proxy (Port 3005)
node scripts/local-dashboard-server.js

# Terminal 2: Start FastAPI Agent Runtime (Port 8000)
python -m uvicorn agent_runtime.main:app --port 8000
```
- Open Dashboard: **`http://localhost:3005/dashboard`**
- Interactive API Docs: **`http://localhost:8000/docs`**

---

## ☁️ Deployment Guide

### Option 1: AWS EC2 (Recommended — 2-Minute 1-Click Bootstrap)

1. Launch an **Ubuntu 24.04 LTS** EC2 instance (`t3.small` or `t3.medium`).
2. Open ports `22`, `3000` (Dashboard), and `8000` (API) in Security Group.
3. In **Advanced Details** → **User Data**, paste:
   ```bash
   #!/bin/bash
   set -e
   apt-get update -y && apt-get install -y git curl
   curl -fsSL https://get.docker.com | sh
   systemctl enable --now docker
   git clone https://github.com/Ajimsha1080/Hypher-AI--Agentic-Security-v2.git /opt/hypher
   cd /opt/hypher
   docker compose up -d --build
   ```
4. Access your live deployment at `http://<EC2_PUBLIC_IP>:3000/dashboard`.

### Option 2: Docker Compose (Any Linux VPS / DigitalOcean / Hetzner)
```bash
docker compose up -d --build
```

### Option 3: AWS ECS Fargate
Task definition template is available in [`deploy/aws-task-definition.json`](deploy/aws-task-definition.json):
```bash
aws ecs register-task-definition --cli-input-json file://deploy/aws-task-definition.json
```

---

## 🧪 Automated Testing & Verification

All test suites pass 100%:

```bash
# Run Python Multi-Agent & Security Test Suite (10/10 Passed)
python -m pytest tests/python -v

# Run Jest Gateway & Enterprise Guardrail Suite (185/185 Passed)
npx jest

# Verify TypeScript Compilation (0 Errors)
npx tsc --noEmit
```

---

## 📄 License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
