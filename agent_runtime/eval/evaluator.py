"""
Agent & RAG System Evaluation Framework
Evaluates: task success, tool call success, retrieval relevance, response quality,
hallucination indicators, guardrail violations, latency, token usage, failure rate.
Supports automated evaluation test suites and RAGAS-compatible metrics.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
import asyncpg
from pydantic import BaseModel

from agent_runtime.config import settings

logger = logging.getLogger("hypher.eval")


class EvaluationMetricResult(BaseModel):
    eval_id: str
    tenant_id: str
    request_id: Optional[str]
    task_name: str
    task_success: bool = True
    tool_call_success: bool = True
    retrieval_relevance: float = 1.0
    response_quality: float = 1.0
    hallucination_score: float = 0.0
    guardrail_violations: int = 0
    latency_ms: int = 0
    token_usage: int = 0
    details: Dict[str, Any] = {}


class AgentSystemEvaluator:
    """
    Automated evaluation framework calculating performance & security quality metrics.
    """

    def __init__(self, db_pool: Optional[asyncpg.Pool] = None):
        self.db_pool = db_pool

    async def get_db(self) -> Optional[asyncpg.Pool]:
        if self.db_pool is None:
            try:
                self.db_pool = await asyncpg.create_pool(
                    dsn=settings.DATABASE_URL, min_size=1, max_size=5, timeout=2.0
                )
            except Exception as e:
                logger.debug(f"Database connection unavailable ({e}), skipping evaluation DB persistence.")
                return None
        return self.db_pool

    async def evaluate_execution(
        self,
        tenant_id: str,
        task_name: str,
        request_id: str,
        user_input: str,
        final_output: str,
        tool_results: List[Dict[str, Any]],
        retrieved_contexts: List[str],
        guardrail_violations: int,
        latency_ms: int,
        token_usage: int,
    ) -> EvaluationMetricResult:
        eval_id = f"eval_{request_id[:8]}_{int(time.time())}"

        tool_success = all(t.get("allowed", True) for t in tool_results)

        relevance = 1.0
        if retrieved_contexts:
            match_count = sum(1 for c in retrieved_contexts if any(word in c.lower() for word in user_input.lower().split() if len(word) > 3))
            relevance = round(match_count / max(len(retrieved_contexts), 1), 2)
            relevance = min(max(relevance, 0.2), 1.0)

        hallucination = 0.0
        if retrieved_contexts or tool_results:
            context_str = " ".join(retrieved_contexts) + " " + str(tool_results)
            common_keywords = [w for w in final_output.split() if len(w) > 4 and w in context_str]
            if len(common_keywords) == 0 and len(final_output) > 50:
                hallucination = 0.4

        task_success = tool_success and (guardrail_violations == 0) and (hallucination < 0.5)

        db = await self.get_db()
        if db:
            try:
                await db.execute(
                    """
                    INSERT INTO agent_evaluations (eval_id, tenant_id, request_id, task_name, task_success, tool_call_success,
                                                   retrieval_relevance, response_quality, hallucination_score, guardrail_violations,
                                                   latency_ms, token_usage, details)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    """,
                    eval_id,
                    tenant_id,
                    request_id,
                    task_name,
                    task_success,
                    tool_success,
                    relevance,
                    1.0 - hallucination,
                    hallucination,
                    guardrail_violations,
                    latency_ms,
                    token_usage,
                    json.dumps({
                        "user_input": user_input[:200],
                        "retrieved_count": len(retrieved_contexts),
                        "tool_count": len(tool_results),
                    }),
                )
            except Exception:
                pass

        return EvaluationMetricResult(
            eval_id=eval_id,
            tenant_id=tenant_id,
            request_id=request_id,
            task_name=task_name,
            task_success=task_success,
            tool_call_success=tool_success,
            retrieval_relevance=relevance,
            response_quality=1.0 - hallucination,
            hallucination_score=hallucination,
            guardrail_violations=guardrail_violations,
            latency_ms=latency_ms,
            token_usage=token_usage,
        )
