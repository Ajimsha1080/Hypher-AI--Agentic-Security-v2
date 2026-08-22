<div align="center">
  <h1>🛡️ Hypher AI</h1>
  <h3>The Enterprise Firewall for Autonomous AI & Secure Multi-Agent Runtime</h3>
  <p>Zero-trust security proxy and stateful multi-agent orchestrator for AI agents. Every tool call authenticated, inspected, policy-checked, and logged.</p>
</div>

---

## 📖 Overview

As enterprises adopt autonomous AI agents (like Claude, Cursor, LangChain, and custom LLM workflows) via the **Model Context Protocol (MCP)**, a massive security blindspot emerges. Agents are frequently granted unrestricted access to databases, APIs, and file systems.

**Hypher AI** sits between your AI Agents and your enterprise backend. It acts as an intelligent firewall, proxying all tool requests through a strict **10-layer security pipeline** before they ever reach your servers.

### 🆕 Feature Release: Production-Oriented Secure Multi-Agent Runtime & RAG Studio (v3.4.0)

Hypher AI now includes an integrated **Secure Multi-Agent Runtime** powered by **LangGraph** and **LiteLLM**, accompanied by an interactive web **Multi-Agent & RAG Studio** inside the dashboard.

All agent tool executions, document retrieval calls, memory accesses, and human-in-the-loop approvals are strictly routed through Hypher's zero-trust security gateway.

---

## 🏗️ Architecture & Multi-Agent Workflow

```text
  [ User Query / Application Request ]
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
 10-LAYER HYPHER SECURITY GATEWAY (Zero-Trust)
 1. 🔑 Auth       — Bearer / OAuth 2.1 Token Validation
 2. 🏢 Tenant     — Tenant Isolation & Rate Metering
 3. 🔍 Inspect    — Real-Time Prompt Injection & DLP
 4. 🌐 Registry   — Tool & MCP Server Trust Scoring
 5. 🛡️ RBAC       — Granular Agent Policy Allowlists
 6. 🧠 Anomaly    — Behavioral ML Baseline Detection
 7. 🔄 Replay     — Cryptographic SHA-256 Deduplication
 8. 🔒 Lock       — Concurrency Control & Race Prevention
 9. ➡️ Forward    — Upstream Execution
10. 📝 Audit      — Immutable Hash-Chained Log & Tracing
```

---

## 🌟 Key Capabilities

### 1. Stateful LangGraph Multi-Agent Orchestrator
- **Supervisor Agent:** Evaluates user intent, manages workflow state transitions, and enforces recursion limits (max 10 iterations).
- **Research/RAG Agent:** Queries vector document stores, chunks text, and synthesizes secure context.
- **Tool Execution Agent:** Issues external tool calls strictly through Hypher Security Gateway.
- **Security/Policy Agent:** Enforces guardrails, HITL checks, and final output sanitization.

### 2. MCP + Secure Tool Calling
- All tool executions pass through the 10-layer security pipeline (`/mcp` & `/api/agent/tool-call`).
- High-risk operations (e.g. `run_command` or database drop queries) pause execution and trigger **Human-in-the-Loop (HITL)** pending approvals.

### 3. Secure RAG Agent & Document Playground
- Document ingestion, chunking, vector storage, and top-K semantic retrieval.
- Protection against in-document prompt injection, secret leakage, and context window overflow.
- System prompt immutability guarantees.

### 4. Isolated Agent Memory
- **Short-Term Memory:** Redis session state with TTLs.
- **Long-Term Memory:** PostgreSQL persistent memory table.
- Strict tenant and user isolation. Automatic PII redaction on write (`[REDACTED_AWS_KEY]`, `[REDACTED_SSN]`).

### 5. Multi-LLM Provider Layer (LiteLLM)
- Supports OpenAI, Anthropic Claude, Google Gemini, Ollama, and custom endpoints.
- Automatic model fallback, timeout handling, retries, and token/cost tracking.

### 6. AI Guardrails & Telemetry
- Multi-tier validation: Input → RAG Context → Tool Arguments → Tool Results → Output.
- Step-by-step request tracing (`request_id`, `tenant_id`, `user_id`, `agent`, `latency`, `tokens`).

---

## 🖥️ Interactive Web UI Dashboard

The Hypher AI Gateway Dashboard includes a dedicated **Multi-Agent & RAG Studio** tab:

- 🌐 **Dashboard URL**: `http://localhost:3005/dashboard` (or `http://localhost:3000/dashboard`)
- ⚡ **Interactive FastAPI OpenAPI Docs**: `http://localhost:8000/docs`

### Dashboard Sections
1. **🤖 Agent Task Executor**: Run stateful multi-agent workflows with live step-by-step trace visualization.
2. **📚 Secure RAG Manager**: Ingest documents, test semantic vector search, and verify prompt injection defense.
3. **🧠 Memory Explorer**: Store & retrieve isolated tenant memories with automatic PII redaction.
4. **✋ HITL Approvals Queue**: Inspect and manage high-risk tool approval requests.

---

## ⚡ API Endpoints (v1)

### Agent Runtime & RAG
| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/agent/run` | `POST` | Execute multi-agent workflow task |
| `/api/v1/agent/stream` | `POST` | SSE streaming multi-agent execution |
| `/api/v1/rag/ingest` | `POST` | Ingest document into vector store |
| `/api/v1/rag/query` | `POST` | Semantic context search |
| `/api/v1/memory` | `POST` | Store long-term memory |
| `/api/v1/memory/search` | `POST` | Search isolated tenant/user memories |
| `/api/v1/memory/{id}` | `DELETE` | Delete long-term memory |
| `/api/v1/tools` | `GET` | List registered tools and risk metadata |
| `/api/v1/tools/execute` | `POST` | Execute tool through Hypher Security Gateway |
| `/api/v1/approvals/{id}/approve` | `POST` | Approve pending high-risk HITL task |
| `/api/v1/approvals/{id}/reject` | `POST` | Reject pending high-risk HITL task |

---

## 🚀 Quick Start & Installation

### 1. Environment Setup

```bash
# 1. Install Node.js dependencies
npm install

# 2. Install Python dependencies for Agent Runtime
pip install -r requirements.txt

# 3. Setup environment variables
cp .env.example .env

# 4. Run database migrations (includes 016_secure_agent_runtime.sql)
npm run db:migrate
```

### 2. Start Services Locally

```bash
# Start Hypher Gateway Dashboard Server (Port 3005 / 3000)
node scripts/local-dashboard-server.js

# Start Secure Agent Runtime Python Service (Port 8000)
python -m uvicorn agent_runtime.main:app --port 8000
```

### 3. Start with Docker Compose

```bash
docker compose up --build -d
```

---

## 🧪 Automated Testing & Verification

```bash
# Run Node.js & Gateway Unit Test Suite (6/6 Test Suites Passed)
npm test

# Run Python Secure Multi-Agent Runtime Test Suite (10/10 Passed)
python -m pytest tests/python -v
```

---
*Hypher AI Gateway & Secure Agent Runtime v3.4.0 Enterprise Edition*
