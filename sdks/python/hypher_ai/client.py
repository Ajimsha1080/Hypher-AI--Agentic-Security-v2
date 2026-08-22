"""
MCP Security Gateway — Python SDK
pip install hypher_ai

Usage:
    from hypher_ai import McpGatewayClient

    client = McpGatewayClient(
        gateway_url="https://your-gateway.com",
        token="your-bearer-token",
        tenant_id="your-tenant-id",
    )
    result = await client.call_tool("query_database", {"query": "SELECT * FROM users LIMIT 10"})
    print(result.content)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generic, List, Optional, TypeVar
import httpx

T = TypeVar("T")


# ── Error types ────────────────────────────────────────────────────────

class GatewayErrorCode(str, Enum):
    AUTH_FAILED        = "AUTH_FAILED"
    POLICY_DENIED      = "POLICY_DENIED"
    INSPECTION_BLOCKED = "INSPECTION_BLOCKED"
    RATE_LIMITED       = "RATE_LIMITED"
    REPLAY_DETECTED    = "REPLAY_DETECTED"
    UPSTREAM_ERROR     = "UPSTREAM_ERROR"


class McpGatewayError(Exception):
    """Raised when the MCP Security Gateway returns an error response."""

    def __init__(self, code: GatewayErrorCode, message: str,
                 http_status: int, reason: Optional[str] = None,
                 retry_after: Optional[int] = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.reason = reason
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"McpGatewayError(code={self.code}, status={self.http_status}, reason={self.reason})"


# ── Result types ───────────────────────────────────────────────────────

@dataclass
class ToolCallResult(Generic[T]):
    content: T
    is_error: bool = False
    execution_time_ms: Optional[int] = None
    request_id: Optional[str] = None


@dataclass
class AuditLogEntry:
    id: str
    agent_id: str
    tool_name: str
    decision: str  # "ALLOW" | "DENY"
    reason: Optional[str]
    execution_time_ms: Optional[int]
    created_at: str


@dataclass
class GatewayMetrics:
    total_calls: int
    allowed_calls: int
    denied_calls: int
    denial_rate: float
    avg_execution_ms: float
    active_agents: int


# ── Config ─────────────────────────────────────────────────────────────

@dataclass
class GatewayConfig:
    gateway_url: str
    token: str
    tenant_id: Optional[str] = None
    oidc_provider: Optional[str] = None   # "google" | "azure" | "okta"
    timeout_seconds: float = 30.0
    retries: int = 2
    verify_ssl: bool = True


# ── Main client ────────────────────────────────────────────────────────

class McpGatewayClient:
    """
    Async Python client for MCP Security Gateway.

    All tool calls route through the 10-layer security pipeline:
    Auth → Tenant → Inspect → Registry → RBAC → Anomaly →
    Replay → Lock → Forward → Audit

    Example:
        async with McpGatewayClient(config) as client:
            result = await client.call_tool("read_file", {"path": "report.pdf"})
    """

    def __init__(self, config: GatewayConfig | None = None, **kwargs):
        if config is None:
            config = GatewayConfig(**kwargs)
        self.config = config
        self._counter = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "McpGatewayClient":
        self._client = httpx.AsyncClient(
            base_url=self.config.gateway_url,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()

    # ── Core tool call ─────────────────────────────────────────────────

    async def call_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        server_name: Optional[str] = None,
    ) -> ToolCallResult:
        """
        Call a tool through the MCP Security Gateway.

        Args:
            tool_name:   Name of the MCP tool to call.
            args:        Arguments to pass to the tool.
            server_name: Target MCP server (optional, uses MCP_SERVER_NAME env if unset).

        Returns:
            ToolCallResult with content and metadata.

        Raises:
            McpGatewayError: If the gateway denies, blocks, or errors the request.
        """
        self._counter += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._counter,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args,
                **({"serverName": server_name} if server_name else {}),
            },
        }
        response = await self._post("/mcp", payload)
        return ToolCallResult(
            content=response.get("result", {}).get("content"),
            is_error=response.get("result", {}).get("isError", False),
            execution_time_ms=response.get("_meta", {}).get("executionTimeMs"),
            request_id=response.get("_meta", {}).get("requestId"),
        )

    # ── Convenience wrappers ───────────────────────────────────────────

    async def query_database(self, query: str, database: Optional[str] = None) -> ToolCallResult:
        return await self.call_tool("query_database", {"query": query, **({"database": database} if database else {})})

    async def read_file(self, path: str) -> ToolCallResult:
        return await self.call_tool("read_file", {"path": path})

    async def write_file(self, path: str, content: str) -> ToolCallResult:
        return await self.call_tool("write_file", {"path": path, "content": content})

    async def http_request(self, url: str, method: str = "GET", body: Any = None) -> ToolCallResult:
        return await self.call_tool("http_request", {"url": url, "method": method, **({"body": body} if body else {})})

    async def web_search(self, query: str) -> ToolCallResult:
        return await self.call_tool("web_search", {"query": query})

    # ── Policy management ──────────────────────────────────────────────

    async def get_policy(self, agent_id: str) -> Dict:
        return await self._get(f"/api/policies/{agent_id}")

    async def set_policy(self, agent_id: str, allowed_tools: List[str]) -> Dict:
        return await self._put(f"/api/policies/{agent_id}", {"allowedTools": allowed_tools})

    async def generate_policy(self, agent_id: str, description: str, dry_run: bool = False) -> Dict:
        """Use LLM policy assistant to generate policy from plain English."""
        return await self._post("/api/policy-assistant/generate", {
            "agentId": agent_id, "description": description, "dryRun": dry_run,
        })

    async def explain_policy(self, agent_id: str) -> str:
        result = await self._get(f"/api/policy-assistant/explain/{agent_id}")
        return result.get("explanation", "")

    # ── Audit & metrics ────────────────────────────────────────────────

    async def get_audit_log(
        self,
        limit: int = 100,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
    ) -> List[AuditLogEntry]:
        params: Dict[str, str] = {"limit": str(limit)}
        if agent_id:  params["agentId"] = agent_id
        if decision:  params["decision"] = decision
        query = "&".join(f"{k}={v}" for k, v in params.items())
        data = await self._get(f"/api/dashboard/audit?{query}")
        return [AuditLogEntry(**entry) for entry in data.get("logs", [])]

    async def get_metrics(self) -> GatewayMetrics:
        data = await self._get("/api/dashboard/metrics")
        return GatewayMetrics(
            total_calls=data.get("totalCalls", 0),
            allowed_calls=data.get("allowedCalls", 0),
            denied_calls=data.get("deniedCalls", 0),
            denial_rate=data.get("denialRate", 0.0),
            avg_execution_ms=data.get("avgExecutionMs", 0.0),
            active_agents=data.get("activeAgents", 0),
        )

    async def health_check(self) -> Dict:
        return await self._get("/health/ready")

    # ── Alerts ────────────────────────────────────────────────────────

    async def create_alert_rule(
        self,
        name: str,
        event_type: str,
        threshold: float,
        window_seconds: int,
        severity: str,
        channels: List[str],
        cooldown_seconds: int = 300,
    ) -> Dict:
        return await self._post("/api/alerts/rules", {
            "name": name, "eventType": event_type, "threshold": threshold,
            "windowSeconds": window_seconds, "severity": severity,
            "channels": channels, "cooldownSeconds": cooldown_seconds,
        })

    async def list_alert_rules(self) -> List[Dict]:
        data = await self._get("/api/alerts/rules")
        return data.get("rules", [])

    # ── Registry ──────────────────────────────────────────────────────

    async def check_server_trust(self, server_name: str) -> Dict:
        return await self._get(f"/api/registry/servers/{server_name}")

    async def list_trusted_servers(self) -> List[Dict]:
        data = await self._get("/api/registry/servers?trust=trusted")
        return data.get("servers", [])

    # ── Compliance ────────────────────────────────────────────────────

    async def export_soc2_report(
        self,
        date_from: str,
        date_to: str,
        format: str = "json",
    ) -> Dict:
        return await self._post("/api/compliance/export", {
            "dateFrom": date_from, "dateTo": date_to,
            "reportType": "soc2", "format": format,
        })

    # ── HTTP internals ─────────────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }
        if self.config.tenant_id:    h["X-Tenant-ID"] = self.config.tenant_id
        if self.config.oidc_provider: h["X-OIDC-Provider"] = self.config.oidc_provider
        return h

    async def _post(self, path: str, body: Any) -> Any:
        return await self._request("POST", path, body)

    async def _get(self, path: str) -> Any:
        return await self._request("GET", path)

    async def _put(self, path: str, body: Any) -> Any:
        return await self._request("PUT", path, body)

    async def _request(self, method: str, path: str, body: Any = None, attempt: int = 0) -> Any:
        client = self._client or httpx.AsyncClient(
            base_url=self.config.gateway_url,
            timeout=self.config.timeout_seconds,
            verify=self.config.verify_ssl,
        )
        try:
            resp = await client.request(
                method, path,
                headers=self._headers(),
                content=json.dumps(body).encode() if body is not None else None,
            )

            if not resp.is_success:
                error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                code = self._map_status(resp.status_code)

                if resp.status_code == 429 and attempt < self.config.retries:
                    retry_after = int(resp.headers.get("retry-after", "5"))
                    await asyncio.sleep(retry_after)
                    return await self._request(method, path, body, attempt + 1)

                raise McpGatewayError(
                    code=code,
                    message=error_body.get("error", f"Gateway returned {resp.status_code}"),
                    http_status=resp.status_code,
                    reason=error_body.get("reason"),
                    retry_after=int(resp.headers.get("retry-after", 0)) or None,
                )

            return resp.json()
        finally:
            if not self._client:
                await client.aclose()

    @staticmethod
    def _map_status(status: int) -> GatewayErrorCode:
        return {
            401: GatewayErrorCode.AUTH_FAILED,
            403: GatewayErrorCode.POLICY_DENIED,
            409: GatewayErrorCode.REPLAY_DETECTED,
            429: GatewayErrorCode.RATE_LIMITED,
        }.get(status, GatewayErrorCode.UPSTREAM_ERROR)


# ── Sync wrapper for non-async codebases ──────────────────────────────

class McpGatewayClientSync:
    """
    Synchronous wrapper around McpGatewayClient.
    Use this if you're not in an async context.

    Example:
        client = McpGatewayClientSync(gateway_url="...", token="...")
        result = client.call_tool("read_file", {"path": "report.pdf"})
    """

    def __init__(self, **kwargs):
        self._config = GatewayConfig(**kwargs)
        self._loop = asyncio.new_event_loop()

    def call_tool(self, tool_name: str, args: Dict[str, Any], **kwargs) -> ToolCallResult:
        return self._run(McpGatewayClient(self._config).call_tool(tool_name, args, **kwargs))

    def query_database(self, query: str, database: Optional[str] = None) -> ToolCallResult:
        return self._run(McpGatewayClient(self._config).query_database(query, database))

    def read_file(self, path: str) -> ToolCallResult:
        return self._run(McpGatewayClient(self._config).read_file(path))

    def get_metrics(self) -> GatewayMetrics:
        return self._run(McpGatewayClient(self._config).get_metrics())

    def health_check(self) -> Dict:
        return self._run(McpGatewayClient(self._config).health_check())

    def _run(self, coro):
        return self._loop.run_until_complete(coro)

    def __del__(self):
        self._loop.close()
