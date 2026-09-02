"""
Human-in-the-Loop (HITL) Approval Manager
Manages high-risk operations requiring explicit human approval.
The agent cannot self-approve any high-risk tool call.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional
import asyncpg
from pydantic import BaseModel

from agent_runtime.config import settings

logger = logging.getLogger("hypher.hitl")

_in_memory_approvals: Dict[str, Dict[str, Any]] = {}


class ApprovalRecord(BaseModel):
    approval_id: str
    request_id: str
    tenant_id: str
    user_id: str
    session_id: Optional[str]
    agent_name: str
    tool_name: str
    tool_arguments: Dict[str, Any]
    risk_level: str
    reason: str
    status: str  # "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED"
    approver_id: Optional[str] = None
    approval_comment: Optional[str] = None
    created_at: Optional[str] = None
    decided_at: Optional[str] = None


class HITLApprovalManager:
    """
    Manages pending human approval requests for sensitive agent tool calls.
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
                logger.debug(f"Database connection unavailable ({e}), using in-memory approval store.")
                return None
        return self.db_pool

    async def create_approval_request(
        self,
        request_id: str,
        tenant_id: str,
        user_id: str,
        agent_name: str,
        tool_name: str,
        tool_arguments: Dict[str, Any],
        reason: str,
        session_id: Optional[str] = None,
        risk_level: str = "HIGH",
    ) -> ApprovalRecord:
        approval_id = f"appr_{request_id[:8]}_{int(time.time())}"
        db = await self.get_db()

        if db:
            try:
                row = await db.fetchrow(
                    """
                    INSERT INTO agent_approvals (approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'PENDING')
                    RETURNING approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status, created_at
                    """,
                    approval_id,
                    request_id,
                    tenant_id,
                    user_id,
                    session_id,
                    agent_name,
                    tool_name,
                    json.dumps(tool_arguments),
                    risk_level,
                    reason,
                )
                return ApprovalRecord(
                    approval_id=row["approval_id"],
                    request_id=row["request_id"],
                    tenant_id=row["tenant_id"],
                    user_id=row["user_id"],
                    session_id=row["session_id"],
                    agent_name=row["agent_name"],
                    tool_name=row["tool_name"],
                    tool_arguments=json.loads(row["tool_arguments"]) if isinstance(row["tool_arguments"], str) else row["tool_arguments"],
                    risk_level=row["risk_level"],
                    reason=row["reason"],
                    status=row["status"],
                    created_at=row["created_at"].isoformat() if row["created_at"] else None,
                )
            except Exception:
                pass

        # In-memory fallback
        item = {
            "approval_id": approval_id,
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "session_id": session_id,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "tool_arguments": tool_arguments,
            "risk_level": risk_level,
            "reason": reason,
            "status": "PENDING",
            "approver_id": None,
            "approval_comment": None,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "decided_at": None,
        }
        _in_memory_approvals[approval_id] = item
        return ApprovalRecord(**item)

    async def approve_request(
        self, tenant_id: str, approval_id: str, approver_id: str, comment: Optional[str] = None
    ) -> Optional[ApprovalRecord]:
        if approver_id.startswith("agent_") or approver_id == "supervisor":
            raise ValueError("Agents are strictly forbidden from self-approving high-risk operations")

        db = await self.get_db()
        if db:
            try:
                row = await db.fetchrow(
                    """
                    UPDATE agent_approvals
                    SET status = 'APPROVED', approver_id = $1, approval_comment = $2, decided_at = NOW()
                    WHERE approval_id = $3 AND tenant_id = $4 AND status = 'PENDING'
                    RETURNING approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status, approver_id, approval_comment, created_at, decided_at
                    """,
                    approver_id,
                    comment or "Approved by security admin",
                    approval_id,
                    tenant_id,
                )
                if row:
                    return self._to_record(row)
            except Exception:
                pass

        item = _in_memory_approvals.get(approval_id)
        if item and item["tenant_id"] == tenant_id and item["status"] == "PENDING":
            item["status"] = "APPROVED"
            item["approver_id"] = approver_id
            item["approval_comment"] = comment or "Approved by security admin"
            item["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            return ApprovalRecord(**item)
        return None

    async def reject_request(
        self, tenant_id: str, approval_id: str, approver_id: str, comment: Optional[str] = None
    ) -> Optional[ApprovalRecord]:
        db = await self.get_db()
        if db:
            try:
                row = await db.fetchrow(
                    """
                    UPDATE agent_approvals
                    SET status = 'REJECTED', approver_id = $1, approval_comment = $2, decided_at = NOW()
                    WHERE approval_id = $3 AND tenant_id = $4 AND status = 'PENDING'
                    RETURNING approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status, approver_id, approval_comment, created_at, decided_at
                    """,
                    approver_id,
                    comment or "Rejected by security policy",
                    approval_id,
                    tenant_id,
                )
                if row:
                    return self._to_record(row)
            except Exception:
                pass

        item = _in_memory_approvals.get(approval_id)
        if item and item["tenant_id"] == tenant_id and item["status"] == "PENDING":
            item["status"] = "REJECTED"
            item["approver_id"] = approver_id
            item["approval_comment"] = comment or "Rejected by security policy"
            item["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            return ApprovalRecord(**item)
        return None

    async def get_approval(self, tenant_id: str, approval_id: str) -> Optional[ApprovalRecord]:
        db = await self.get_db()
        if db:
            try:
                row = await db.fetchrow(
                    """
                    SELECT approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status, approver_id, approval_comment, created_at, decided_at
                    FROM agent_approvals
                    WHERE approval_id = $1 AND tenant_id = $2
                    """,
                    approval_id,
                    tenant_id,
                )
                if row:
                    return self._to_record(row)
            except Exception:
                pass

    async def list_pending_approvals(self, tenant_id: str) -> List[ApprovalRecord]:
        db = await self.get_db()
        if db:
            try:
                rows = await db.fetch(
                    """
                    SELECT approval_id, request_id, tenant_id, user_id, session_id, agent_name, tool_name, tool_arguments, risk_level, reason, status, approver_id, approval_comment, created_at, decided_at
                    FROM agent_approvals
                    WHERE tenant_id = $1 AND status = 'PENDING'
                    ORDER BY created_at DESC
                    """,
                    tenant_id,
                )
                return [self._to_record(row) for row in rows]
            except Exception:
                pass

        results = []
        for item in _in_memory_approvals.values():
            if item["tenant_id"] == tenant_id and item["status"] == "PENDING":
                results.append(ApprovalRecord(**item))
        return results

    def _to_record(self, row: Any) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=row["approval_id"],
            request_id=row["request_id"],
            tenant_id=row["tenant_id"],
            user_id=row["user_id"],
            session_id=row["session_id"],
            agent_name=row["agent_name"],
            tool_name=row["tool_name"],
            tool_arguments=json.loads(row["tool_arguments"]) if isinstance(row["tool_arguments"], str) else row["tool_arguments"],
            risk_level=row["risk_level"],
            reason=row["reason"],
            status=row["status"],
            approver_id=row["approver_id"],
            approval_comment=row["approval_comment"],
            created_at=row["created_at"].isoformat() if row["created_at"] else None,
            decided_at=row["decided_at"].isoformat() if row["decided_at"] else None,
        )
