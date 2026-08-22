"""
Dual-Tier Isolated Agent Memory System
- Short-Term Memory: Redis session state with TTLs & in-memory fallback
- Long-Term Memory: PostgreSQL persistent memories table & in-memory fallback
Enforces strict Tenant & User isolation, memory retrieval, creation, deletion, and PII filtering.
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
import asyncpg
import redis.asyncio as aioredis
from pydantic import BaseModel

from agent_runtime.config import settings
from agent_runtime.security.guardrails import AIGuardrails

logger = logging.getLogger("hypher.memory")

_in_memory_short_store: Dict[str, List[Dict[str, Any]]] = {}
_in_memory_long_store: List[Dict[str, Any]] = []


class MemoryEntry(BaseModel):
    id: Optional[str] = None
    tenant_id: str
    user_id: str
    session_id: Optional[str] = None
    memory_type: str = "long_term"
    key: str
    value: str
    metadata: Dict[str, Any] = {}
    created_at: Optional[str] = None


class AgentMemoryManager:
    """
    Manages short-term and long-term agent memories securely.
    Ensures no tenant or user can read another tenant's or user's memory.
    """

    def __init__(self, db_pool: Optional[asyncpg.Pool] = None, redis_client: Optional[aioredis.Redis] = None):
        self.db_pool = db_pool
        self.redis_client = redis_client

    async def get_db(self) -> Optional[asyncpg.Pool]:
        if self.db_pool is None:
            try:
                self.db_pool = await asyncpg.create_pool(
                    dsn=settings.DATABASE_URL, min_size=1, max_size=5, timeout=2.0
                )
            except Exception as e:
                logger.debug(f"Database connection unavailable ({e}), using in-memory store for memory manager.")
                return None
        return self.db_pool

    async def get_redis(self) -> Optional[aioredis.Redis]:
        if self.redis_client is None:
            try:
                client = aioredis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
                await client.ping()
                self.redis_client = client
            except Exception as e:
                logger.debug(f"Redis connection unavailable ({e}), using in-memory store for short-term memory.")
                return None
        return self.redis_client

    # ── Short-Term Memory ──────────────────────────────────────────────

    async def save_short_term_context(
        self, tenant_id: str, user_id: str, session_id: str, messages: List[Dict[str, Any]], ttl_seconds: int = 86400
    ) -> None:
        key = f"memory:short:{tenant_id}:{user_id}:{session_id}"
        r = await self.get_redis()
        if r:
            try:
                await r.set(key, json.dumps(messages), ex=ttl_seconds)
                return
            except Exception:
                pass
        _in_memory_short_store[key] = messages

    async def get_short_term_context(
        self, tenant_id: str, user_id: str, session_id: str
    ) -> List[Dict[str, Any]]:
        key = f"memory:short:{tenant_id}:{user_id}:{session_id}"
        r = await self.get_redis()
        if r:
            try:
                data = await r.get(key)
                if data:
                    return json.loads(data)
            except Exception:
                pass
        return _in_memory_short_store.get(key, [])

    # ── Long-Term Memory ──────────────────────────────────────────

    async def save_long_term_memory(
        self, tenant_id: str, user_id: str, key: str, value: str, session_id: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None
    ) -> MemoryEntry:
        output_guard = AIGuardrails.validate_output(value)
        clean_value = output_guard.sanitized_content or value

        db = await self.get_db()
        if db:
            try:
                row = await db.fetchrow(
                    """
                    INSERT INTO agent_memories (tenant_id, user_id, session_id, memory_type, key, value, metadata, updated_at)
                    VALUES ($1, $2, $3, 'long_term', $4, $5, $6, NOW())
                    RETURNING id, tenant_id, user_id, session_id, memory_type, key, value, metadata, created_at
                    """,
                    tenant_id,
                    user_id,
                    session_id,
                    key,
                    clean_value,
                    json.dumps(metadata or {}),
                )
                return MemoryEntry(
                    id=str(row["id"]),
                    tenant_id=row["tenant_id"],
                    user_id=row["user_id"],
                    session_id=row["session_id"],
                    memory_type=row["memory_type"],
                    key=row["key"],
                    value=row["value"],
                    metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else (row["metadata"] or {}),
                    created_at=row["created_at"].isoformat() if row["created_at"] else None,
                )
            except Exception as e:
                logger.warning(f"PostgreSQL memory insert error ({e}), falling back to in-memory store.")

        # Fallback in-memory
        mem_id = str(uuid.uuid4())
        entry_dict = {
            "id": mem_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "session_id": session_id,
            "memory_type": "long_term",
            "key": key,
            "value": clean_value,
            "metadata": metadata or {},
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        _in_memory_long_store.append(entry_dict)
        return MemoryEntry(**entry_dict)

    async def search_memories(
        self, tenant_id: str, user_id: str, query: str, limit: int = 10
    ) -> List[MemoryEntry]:
        db = await self.get_db()
        if db:
            try:
                rows = await db.fetch(
                    """
                    SELECT id, tenant_id, user_id, session_id, memory_type, key, value, metadata, created_at
                    FROM agent_memories
                    WHERE tenant_id = $1 AND user_id = $2
                      AND (key ILIKE $3 OR value ILIKE $3)
                    ORDER BY created_at DESC
                    LIMIT $4
                    """,
                    tenant_id,
                    user_id,
                    f"%{query}%",
                    limit,
                )
                results = []
                for row in rows:
                    meta = json.loads(row["metadata"]) if isinstance(row["metadata"], str) else (row["metadata"] or {})
                    results.append(
                        MemoryEntry(
                            id=str(row["id"]),
                            tenant_id=row["tenant_id"],
                            user_id=row["user_id"],
                            session_id=row["session_id"],
                            memory_type=row["memory_type"],
                            key=row["key"],
                            value=row["value"],
                            metadata=meta,
                            created_at=row["created_at"].isoformat() if row["created_at"] else None,
                        )
                    )
                return results
            except Exception as e:
                logger.warning(f"PostgreSQL memory search error ({e}), falling back to in-memory search.")

        # Fallback search in-memory
        results = []
        q_lower = query.lower()
        for item in reversed(_in_memory_long_store):
            if item["tenant_id"] == tenant_id and item["user_id"] == user_id:
                if q_lower in item["key"].lower() or q_lower in item["value"].lower():
                    results.append(MemoryEntry(**item))
                    if len(results) >= limit:
                        break
        return results

    async def delete_memory(self, tenant_id: str, user_id: str, memory_id: str) -> bool:
        db = await self.get_db()
        if db:
            try:
                result = await db.execute(
                    """
                    DELETE FROM agent_memories
                    WHERE id = $1::uuid AND tenant_id = $2 AND user_id = $3
                    """,
                    memory_id,
                    tenant_id,
                    user_id,
                )
                if result.endswith("1"):
                    return True
            except Exception:
                pass

        global _in_memory_long_store
        initial_len = len(_in_memory_long_store)
        _in_memory_long_store = [
            item for item in _in_memory_long_store
            if not (item["id"] == memory_id and item["tenant_id"] == tenant_id and item["user_id"] == user_id)
        ]
        return len(_in_memory_long_store) < initial_len
