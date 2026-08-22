-- MCP Security Gateway Migration 016: Secure Multi-Agent Runtime
-- Schema for Agent Sessions, Conversations, Memory, Executions, Approvals, RAG, and Evaluations.

BEGIN;

-- ── 1. AGENT SESSIONS & CONVERSATIONS ────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    TEXT NOT NULL UNIQUE,
    tenant_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    agent_name    TEXT NOT NULL DEFAULT 'supervisor',
    metadata      JSONB DEFAULT '{}'::jsonb,
    is_active     BOOLEAN DEFAULT TRUE,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_tenant ON agent_sessions(tenant_id, user_id);

CREATE TABLE IF NOT EXISTS agent_conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      TEXT NOT NULL REFERENCES agent_sessions(session_id) ON DELETE CASCADE,
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system', 'tool', 'agent')),
    content         TEXT NOT NULL,
    agent_id        TEXT DEFAULT 'supervisor',
    tool_calls      JSONB DEFAULT '[]'::jsonb,
    metadata        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_conversations_session ON agent_conversations(session_id, created_at ASC);

-- ── 2. AGENT MEMORIES (DUAL TIER: SHORT/LONG TERM ISOLATED) ──────────
CREATE TABLE IF NOT EXISTS agent_memories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    session_id      TEXT,
    memory_type     TEXT NOT NULL DEFAULT 'long_term' CHECK (memory_type IN ('short_term', 'long_term')),
    key             TEXT NOT NULL,
    value           TEXT NOT NULL,
    embedding       JSONB DEFAULT '[]'::jsonb,
    metadata        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_memories_lookup ON agent_memories(tenant_id, user_id, memory_type);
CREATE INDEX IF NOT EXISTS idx_agent_memories_key ON agent_memories(tenant_id, user_id, key);

-- ── 3. AGENT WORKFLOW EXECUTIONS & TRACES ─────────────────────────────
CREATE TABLE IF NOT EXISTS agent_executions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id        TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    session_id        TEXT,
    workflow_name     TEXT NOT NULL DEFAULT 'langgraph_multi_agent',
    model             TEXT NOT NULL,
    provider          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'PENDING_APPROVAL')),
    step_count        INTEGER DEFAULT 0,
    tools_used        JSONB DEFAULT '[]'::jsonb,
    security_decision TEXT DEFAULT 'ALLOW',
    error_message     TEXT,
    prompt_tokens     INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    estimated_cost    FLOAT DEFAULT 0.0,
    execution_time_ms INTEGER DEFAULT 0,
    trace_json        JSONB DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_exec_tenant ON agent_executions(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_exec_req ON agent_executions(request_id);

CREATE TABLE IF NOT EXISTS agent_tool_executions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id      UUID REFERENCES agent_executions(id) ON DELETE CASCADE,
    request_id        TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    agent_name        TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    arguments         JSONB DEFAULT '{}'::jsonb,
    gateway_decision  TEXT NOT NULL CHECK (gateway_decision IN ('ALLOW', 'DENY', 'PENDING_APPROVAL')),
    gateway_reason    TEXT,
    result            JSONB DEFAULT '{}'::jsonb,
    execution_time_ms INTEGER DEFAULT 0,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_tool_exec_tenant ON agent_tool_executions(tenant_id, tool_name);

-- ── 4. HUMAN-IN-THE-LOOP (HITL) APPROVAL REQUESTS ───────────────────
CREATE TABLE IF NOT EXISTS agent_approvals (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_id       TEXT NOT NULL UNIQUE,
    request_id        TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    session_id        TEXT,
    agent_name        TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    tool_arguments    JSONB DEFAULT '{}'::jsonb,
    risk_level        TEXT NOT NULL DEFAULT 'HIGH',
    reason            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')),
    approver_id       TEXT,
    approval_comment  TEXT,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    decided_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_agent_approvals_pending ON agent_approvals(tenant_id, status) WHERE status='PENDING';
CREATE INDEX IF NOT EXISTS idx_agent_approvals_id ON agent_approvals(approval_id);

-- ── 5. SECURE RAG DOCUMENTS & CHUNKS ──────────────────────────────────
CREATE TABLE IF NOT EXISTS rag_documents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    doc_id        TEXT NOT NULL UNIQUE,
    tenant_id     TEXT NOT NULL,
    title         TEXT NOT NULL,
    source        TEXT,
    doc_hash      TEXT NOT NULL,
    chunk_count   INTEGER DEFAULT 0,
    metadata      JSONB DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rag_docs_tenant ON rag_documents(tenant_id, doc_id);

CREATE TABLE IF NOT EXISTS rag_chunks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chunk_id      TEXT NOT NULL UNIQUE,
    doc_id        TEXT NOT NULL REFERENCES rag_documents(doc_id) ON DELETE CASCADE,
    tenant_id     TEXT NOT NULL,
    chunk_index   INTEGER NOT NULL,
    content       TEXT NOT NULL,
    embedding     JSONB DEFAULT '[]'::jsonb,
    metadata      JSONB DEFAULT '{}'::jsonb,
    token_count   INTEGER DEFAULT 0,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_tenant ON rag_chunks(tenant_id, doc_id);

-- ── 6. AGENT & RAG EVALUATION RESULTS ────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_evaluations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    eval_id               TEXT NOT NULL UNIQUE,
    tenant_id             TEXT NOT NULL,
    request_id            TEXT,
    task_name             TEXT NOT NULL,
    task_success          BOOLEAN DEFAULT TRUE,
    tool_call_success     BOOLEAN DEFAULT TRUE,
    retrieval_relevance   FLOAT DEFAULT 1.0,
    response_quality      FLOAT DEFAULT 1.0,
    hallucination_score   FLOAT DEFAULT 0.0,
    guardrail_violations  INTEGER DEFAULT 0,
    latency_ms            INTEGER DEFAULT 0,
    token_usage           INTEGER DEFAULT 0,
    details               JSONB DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_evals_tenant ON agent_evaluations(tenant_id, created_at DESC);

COMMIT;
