"""
Observability & Tracing Layer for Hypher Multi-Agent Runtime
Provides full request step tracing (User → Supervisor → Agent → Retrieval → Security Gateway → Tool → Result → Response)
Ensures NO secrets, passwords, or tokens are logged.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from agent_runtime.security.guardrails import SECRET_PATTERNS

logger = logging.getLogger("hypher.observability")


class TraceSpan(BaseModel):
    span_id: str
    parent_span_id: Optional[str] = None
    name: str
    agent_name: str
    status: str = "ok"
    start_time_ms: int
    end_time_ms: Optional[int] = None
    attributes: Dict[str, Any] = {}


class ExecutionTracer:
    """
    Contextual execution tracer capturing workflow step telemetry.
    """

    def __init__(
        self,
        request_id: str,
        tenant_id: str,
        user_id: str,
        session_id: Optional[str] = None,
        workflow: str = "langgraph_multi_agent",
    ):
        self.request_id = request_id
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.session_id = session_id
        self.workflow = workflow
        self.spans: List[TraceSpan] = []
        self.start_time_ms = int(time.time() * 1000)

    def start_span(self, name: str, agent_name: str, parent_span_id: Optional[str] = None) -> str:
        span_id = f"span_{len(self.spans)+1}_{int(time.time()*1000)%10000}"
        span = TraceSpan(
            span_id=span_id,
            parent_span_id=parent_span_id,
            name=name,
            agent_name=agent_name,
            start_time_ms=int(time.time() * 1000),
        )
        self.spans.append(span)
        return span_id

    def finish_span(self, span_id: str, status: str = "ok", attributes: Optional[Dict[str, Any]] = None):
        for span in self.spans:
            if span.span_id == span_id:
                span.end_time_ms = int(time.time() * 1000)
                span.status = status
                if attributes:
                    span.attributes.update(self._sanitize_attributes(attributes))
                break

    def to_dict(self) -> Dict[str, Any]:
        duration_ms = int(time.time() * 1000) - self.start_time_ms
        return {
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "workflow": self.workflow,
            "duration_ms": duration_ms,
            "total_spans": len(self.spans),
            "spans": [s.model_dump() for s in self.spans],
        }

    def _sanitize_attributes(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for k, v in attrs.items():
            if any(secret in k.lower() for secret in ["secret", "password", "key", "token", "auth"]):
                sanitized[k] = "[REDACTED]"
            elif isinstance(v, str):
                v_clean = v
                for secret_re, replacement in SECRET_PATTERNS:
                    import re

                    v_clean = re.sub(secret_re, replacement, v_clean)
                sanitized[k] = v_clean[:500]
            else:
                sanitized[k] = v
        return sanitized
