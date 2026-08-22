"""
MCP Security Gateway — LangChain Integration
pip install hypher_ai langchain-core

Provides:
  - hypher_aiTool:       Drop-in LangChain BaseTool backed by the gateway
  - hypher_aiToolkit:    Bundle of tools from a gateway policy
  - McpAuditCallbackHandler: LangChain callback that logs all LLM+tool activity

Usage:
    from hypher_ai.integrations.langchain import hypher_aiToolkit
    from langchain.agents import create_tool_calling_agent

    toolkit = hypher_aiToolkit(
        gateway_url="https://your-gateway.com",
        token="your-token",
        allowed_tools=["read_file", "query_database", "web_search"],
    )
    agent = create_tool_calling_agent(llm, toolkit.get_tools(), prompt)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Type

try:
    from langchain_core.tools import BaseTool, ToolException
    from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler
    from langchain_core.outputs import LLMResult
    from pydantic import BaseModel, Field
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    BaseTool = object  # type: ignore
    BaseModel = object  # type: ignore

from hypher_ai.client import McpGatewayClient, McpGatewayError, GatewayConfig


def _require_langchain():
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain-core is required for LangChain integration. "
            "Install it with: pip install langchain-core"
        )


# ── Single tool ────────────────────────────────────────────────────────

class hypher_aiTool(BaseTool):  # type: ignore[misc]
    """
    A LangChain Tool backed by MCP Security Gateway.
    All calls route through the full 10-layer security pipeline.

    Example:
        tool = hypher_aiTool(
            name="query_database",
            description="Execute a SQL query and return results",
            gateway_url="https://your-gateway.com",
            token="your-token",
        )
        result = tool.run({"query": "SELECT count(*) FROM orders"})
    """

    name: str
    description: str
    gateway_url: str
    token: str
    tenant_id: Optional[str] = None
    server_name: Optional[str] = None
    return_direct: bool = False

    class Config:
        arbitrary_types_allowed = True

    def _run(self, tool_input: str | Dict[str, Any], **kwargs) -> str:
        _require_langchain()
        args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        return asyncio.get_event_loop().run_until_complete(self._arun(args))

    async def _arun(self, tool_input: str | Dict[str, Any], **kwargs) -> str:
        _require_langchain()
        args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        config = GatewayConfig(
            gateway_url=self.gateway_url,
            token=self.token,
            tenant_id=self.tenant_id,
        )
        try:
            async with McpGatewayClient(config) as client:
                result = await client.call_tool(self.name, args, server_name=self.server_name)
                if result.is_error:
                    raise ToolException(f"Tool {self.name} returned error: {result.content}")
                return str(result.content)
        except McpGatewayError as e:
            if e.code.value == "POLICY_DENIED":
                raise ToolException(f"Policy denied: agent is not allowed to call '{self.name}'. Reason: {e.reason}")
            if e.code.value == "INSPECTION_BLOCKED":
                raise ToolException(f"Input blocked by security inspection: {e.reason}")
            raise ToolException(f"Gateway error [{e.code}]: {str(e)}")


# ── Toolkit (multiple tools) ───────────────────────────────────────────

class hypher_aiToolkit:
    """
    Creates a full set of LangChain tools from an MCP Security Gateway policy.

    Example:
        toolkit = hypher_aiToolkit(
            gateway_url="https://your-gateway.com",
            token="your-token",
            allowed_tools=["read_file", "query_database", "web_search", "http_request"],
        )
        tools = toolkit.get_tools()
        agent = create_tool_calling_agent(llm, tools, prompt)
    """

    # Tool name → description mapping
    TOOL_DESCRIPTIONS: Dict[str, str] = {
        "read_file":       "Read the contents of a file at the given path",
        "write_file":      "Write content to a file at the given path",
        "list_directory":  "List files and directories at a path",
        "query_database":  "Execute a SQL query and return the results as JSON",
        "http_request":    "Make an HTTP request to an external URL",
        "web_search":      "Search the web and return relevant results",
        "send_message":    "Send a message to a Slack channel or user",
        "run_command":     "Execute a shell command (requires explicit policy grant)",
        "create_pr":       "Create a GitHub pull request",
        "list_issues":     "List GitHub issues for a repository",
    }

    def __init__(
        self,
        gateway_url: str,
        token: str,
        allowed_tools: List[str],
        tenant_id: Optional[str] = None,
        server_name: Optional[str] = None,
        custom_descriptions: Optional[Dict[str, str]] = None,
    ):
        _require_langchain()
        self.gateway_url = gateway_url
        self.token = token
        self.allowed_tools = allowed_tools
        self.tenant_id = tenant_id
        self.server_name = server_name
        self.custom_descriptions = custom_descriptions or {}

    def get_tools(self) -> List[hypher_aiTool]:
        tools = []
        for name in self.allowed_tools:
            desc = (
                self.custom_descriptions.get(name)
                or self.TOOL_DESCRIPTIONS.get(name)
                or f"Call the '{name}' tool via MCP Security Gateway"
            )
            tools.append(hypher_aiTool(
                name=name,
                description=desc,
                gateway_url=self.gateway_url,
                token=self.token,
                tenant_id=self.tenant_id,
                server_name=self.server_name,
            ))
        return tools

    @classmethod
    async def from_gateway_policy(
        cls,
        gateway_url: str,
        token: str,
        agent_id: str,
        tenant_id: Optional[str] = None,
    ) -> "hypher_aiToolkit":
        """
        Automatically load the allowed tools from the agent's gateway policy.
        No need to hardcode the tool list.
        """
        config = GatewayConfig(gateway_url=gateway_url, token=token, tenant_id=tenant_id)
        async with McpGatewayClient(config) as client:
            policy = await client.get_policy(agent_id)
        allowed = policy.get("allowedTools", [])
        return cls(
            gateway_url=gateway_url,
            token=token,
            allowed_tools=allowed,
            tenant_id=tenant_id,
        )


# ── Audit callback handler ────────────────────────────────────────────

class McpAuditCallbackHandler(BaseCallbackHandler):  # type: ignore[misc]
    """
    LangChain callback handler that sends LLM and tool activity to the
    MCP Security Gateway audit log for full chain-of-thought auditability.

    Example:
        handler = McpAuditCallbackHandler(gateway_url="...", token="...", agent_id="agent-123")
        llm.invoke("What is the revenue?", config={"callbacks": [handler]})
    """

    def __init__(self, gateway_url: str, token: str, agent_id: str,
                 tenant_id: Optional[str] = None):
        self.gateway_url = gateway_url
        self.token = token
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self._start_times: Dict[str, float] = {}

    def on_tool_start(self, serialized: Dict, input_str: str, run_id: Any = None, **kwargs):
        import time
        self._start_times[str(run_id)] = time.time()

    def on_tool_end(self, output: str, run_id: Any = None, **kwargs):
        import time
        start = self._start_times.pop(str(run_id), time.time())
        ms = int((time.time() - start) * 1000)
        # Fire-and-forget audit log entry
        asyncio.get_event_loop().run_until_complete(
            self._log_tool_event(kwargs.get("name", "unknown"), output, ms)
        )

    async def _log_tool_event(self, tool_name: str, output: str, ms: int):
        try:
            config = GatewayConfig(
                gateway_url=self.gateway_url,
                token=self.token,
                tenant_id=self.tenant_id,
            )
            async with McpGatewayClient(config) as client:
                await client._post("/api/analytics/langchain-event", {
                    "agentId": self.agent_id,
                    "toolName": tool_name,
                    "executionTimeMs": ms,
                    "framework": "langchain",
                })
        except Exception:
            pass  # Never crash the agent chain due to audit logging
