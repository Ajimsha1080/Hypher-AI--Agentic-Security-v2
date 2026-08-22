"""
FastAPI REST API Service for Secure Multi-Agent Runtime
Endpoints:
- POST /api/v1/agent/run          — Execute stateful multi-agent task
- POST /api/v1/agent/stream       — SSE streaming execution updates
- POST /api/v1/rag/ingest         — Ingest document into vector RAG store
- POST /api/v1/rag/query          — Semantic RAG retrieval
- POST /api/v1/memory             — Save long-term memory
- POST /api/v1/memory/search      — Search isolated agent memory
- DELETE /api/v1/memory/{id}      — Delete memory entry
- GET  /api/v1/tools              — List registered tools & trust metadata
- POST /api/v1/tools/execute      — Execute tool through Hypher gateway
- POST /api/v1/approvals/{id}/approve — Approve pending HITL high-risk operation
- POST /api/v1/approvals/{id}/reject  — Reject pending HITL high-risk operation
- GET  /health                    — Health check endpoint
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Header, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agent_runtime.config import settings
from agent_runtime.orchestrator.graph import AgentWorkflowOutput, SecureMultiAgentOrchestrator
from agent_runtime.rag.pipeline import DocumentIngestRequest, RAGChunkResult, SecureRAGPipeline
from agent_runtime.memory.manager import AgentMemoryManager, MemoryEntry
from agent_runtime.hitl.approval_manager import ApprovalRecord, HITLApprovalManager
from agent_runtime.security.gateway_client import HypherSecurityGatewayClient
from agent_runtime.eval.evaluator import AgentSystemEvaluator

logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger("hypher.api")

app = FastAPI(
    title="Hypher AI — Secure Multi-Agent Runtime API",
    description="Production-oriented Zero-Trust Multi-Agent Orchestrator powered by LangGraph & LiteLLM",
    version="3.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SecureMultiAgentOrchestrator()
rag_pipeline = SecureRAGPipeline()
memory_manager = AgentMemoryManager()
hitl_manager = HITLApprovalManager()
gateway_client = HypherSecurityGatewayClient()
evaluator = AgentSystemEvaluator()


# ── Request / Response Schemas ────────────────────────────────────────

class AgentRunRequest(BaseModel):
    task: str = Field(..., description="User prompt or task for multi-agent system")
    session_id: Optional[str] = Field(None, description="Optional conversation session ID")


class MemorySaveRequest(BaseModel):
    key: str
    value: str
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = {}


class MemorySearchRequest(BaseModel):
    query: str
    limit: int = 10


class ToolExecuteRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}


class ApprovalDecisionRequest(BaseModel):
    approver_id: str
    comment: Optional[str] = None


# ── Health Check ──────────────────────────────────────────────────────

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        "status": "healthy",
        "service": settings.SERVICE_NAME,
        "version": "3.4.0",
        "llm_provider": settings.LLM_PROVIDER,
        "primary_model": settings.MODEL,
        "fallback_model": settings.FALLBACK_MODEL,
        "hypher_gateway": settings.HYPHER_GATEWAY_URL,
    }


# ── 1. Agent Runtime API ──────────────────────────────────────────────

@app.post("/api/v1/agent/run", response_model=AgentWorkflowOutput)
async def run_agent(
    req: AgentRunRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    try:
        output = await orchestrator.run(
            task_input=req.task,
            tenant_id=x_tenant_id,
            user_id=x_user_id,
            session_id=req.session_id,
        )

        # Record Evaluation Metrics in background
        await evaluator.evaluate_execution(
            tenant_id=x_tenant_id,
            task_name="multi_agent_workflow",
            request_id=output.request_id,
            user_input=req.task,
            final_output=output.final_output,
            tool_results=output.tool_calls,
            retrieved_contexts=[],
            guardrail_violations=output.guardrail_violations,
            latency_ms=output.latency_ms,
            token_usage=output.prompt_tokens + output.completion_tokens,
        )

        return output
    except Exception as e:
        logger.error(f"Error executing agent task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/agent/stream")
async def stream_agent(
    req: AgentRunRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    async def event_generator():
        yield f"event: step\ndata: {{\"step\": \"supervisor\", \"status\": \"routing\"}}\n\n"
        output = await orchestrator.run(
            task_input=req.task,
            tenant_id=x_tenant_id,
            user_id=x_user_id,
            session_id=req.session_id,
        )
        yield f"event: complete\ndata: {output.model_dump_json()}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── 2. RAG API ────────────────────────────────────────────────────────

@app.post("/api/v1/rag/ingest")
async def ingest_document(
    doc: DocumentIngestRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
):
    try:
        res = await rag_pipeline.ingest_document(tenant_id=x_tenant_id, doc_req=doc)
        return res
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/rag/query")
async def query_rag(
    query: str = Query(...),
    top_k: int = Query(5),
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
):
    try:
        chunks, violations = await rag_pipeline.search(tenant_id=x_tenant_id, query=query, top_k=top_k)
        return {
            "query": query,
            "results_count": len(chunks),
            "guardrail_violations": violations,
            "chunks": [c.model_dump() for c in chunks],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── 3. Memory API ─────────────────────────────────────────────────────

@app.post("/api/v1/memory", response_model=MemoryEntry)
async def save_memory(
    req: MemorySaveRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    try:
        entry = await memory_manager.save_long_term_memory(
            tenant_id=x_tenant_id,
            user_id=x_user_id,
            key=req.key,
            value=req.value,
            session_id=req.session_id,
            metadata=req.metadata,
        )
        return entry
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/memory/search", response_model=List[MemoryEntry])
async def search_memory(
    req: MemorySearchRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    try:
        memories = await memory_manager.search_memories(
            tenant_id=x_tenant_id, user_id=x_user_id, query=req.query, limit=req.limit
        )
        return memories
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/memory/{memory_id}")
async def delete_memory(
    memory_id: str = Path(...),
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    deleted = await memory_manager.delete_memory(tenant_id=x_tenant_id, user_id=x_user_id, memory_id=memory_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Memory entry not found or unauthorized")
    return {"status": "deleted", "id": memory_id}


# ── 4. Tool Registry & Gateway Execution ──────────────────────────────

@app.get("/api/v1/tools")
async def list_tools():
    return {
        "tools": [
            {
                "name": "query_database",
                "description": "Executes read-only SQL queries on configured database",
                "risk_level": "MEDIUM",
                "requires_approval": False,
            },
            {
                "name": "read_file",
                "description": "Reads document from local storage",
                "risk_level": "LOW",
                "requires_approval": False,
            },
            {
                "name": "web_search",
                "description": "Searches external web sources for information",
                "risk_level": "LOW",
                "requires_approval": False,
            },
            {
                "name": "run_command",
                "description": "Executes system shell command",
                "risk_level": "CRITICAL",
                "requires_approval": True,
            },
        ]
    }


@app.post("/api/v1/tools/execute")
async def execute_tool(
    req: ToolExecuteRequest,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
    x_user_id: str = Header(default=settings.DEFAULT_USER_ID, alias="X-User-ID"),
):
    gw_resp = await gateway_client.execute_tool(
        tool_name=req.tool,
        arguments=req.arguments,
        user_id=x_user_id,
        session_id=None,
        agent_id="api_client",
    )
    return gw_resp.model_dump()


# ── 5. Human-in-the-Loop (HITL) Approvals ─────────────────────────────

@app.post("/api/v1/approvals/{id}/approve", response_model=ApprovalRecord)
async def approve_task(
    id: str = Path(...),
    req: ApprovalDecisionRequest = ...,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
):
    try:
        appr = await hitl_manager.approve_request(
            tenant_id=x_tenant_id, approval_id=id, approver_id=req.approver_id, comment=req.comment
        )
        if not appr:
            raise HTTPException(status_code=404, detail="Pending approval not found")
        return appr
    except ValueError as val_err:
        raise HTTPException(status_code=403, detail=str(val_err))


@app.post("/api/v1/approvals/{id}/reject", response_model=ApprovalRecord)
async def reject_task(
    id: str = Path(...),
    req: ApprovalDecisionRequest = ...,
    x_tenant_id: str = Header(default=settings.DEFAULT_TENANT_ID, alias="X-Tenant-ID"),
):
    appr = await hitl_manager.reject_request(
        tenant_id=x_tenant_id, approval_id=id, approver_id=req.approver_id, comment=req.comment
    )
    if not appr:
        raise HTTPException(status_code=404, detail="Pending approval not found")
    return appr


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("agent_runtime.main:app", host="0.0.0.0", port=settings.PORT, reload=False)
