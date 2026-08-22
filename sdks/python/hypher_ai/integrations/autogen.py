"""
MCP Security Gateway — AutoGen / AG2 Integration
pip install hypher_ai autogen-agentchat

Provides:
  - register_gateway_tools():  Register gateway tools on an AutoGen agent
  - hypher_aiFunctionMap:    Dict of callable functions for ConversableAgent
  - SecureConversableAgent:    AutoGen agent pre-wired to gateway
  - SecureGroupChat:           GroupChat where all tool calls go through gateway

Usage:
    from hypher_ai.integrations.autogen import register_gateway_tools
    from autogen import ConversableAgent

    agent = ConversableAgent(name="analyst", llm_config=llm_config)
    register_gateway_tools(
        agent,
        gateway_url="https://your-gateway.com",
        token="your-token",
        tools=["query_database", "read_file"],
    )
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional

try:
    from autogen import ConversableAgent, GroupChat, GroupChatManager
    _AUTOGEN_AVAILABLE = True
except ImportError:
    try:
        from autogen_agentchat.agents import ConversableAgent
        from autogen_agentchat.teams import GroupChat
        _AUTOGEN_AVAILABLE = True
    except ImportError:
        _AUTOGEN_AVAILABLE = False
        ConversableAgent = object  # type: ignore

from hypher_ai.client import McpGatewayClient, McpGatewayError, GatewayConfig


def _require_autogen():
    if not _AUTOGEN_AVAILABLE:
        raise ImportError(
            "autogen-agentchat is required. Install: pip install autogen-agentchat"
        )


# ── Tool function factory ──────────────────────────────────────────────

def _make_tool_fn(
    tool_name: str,
    gateway_url: str,
    token: str,
    tenant_id: Optional[str],
) -> Callable:
    """
    Create a callable function that AutoGen can register as a tool.
    Each call routes through the MCP Security Gateway pipeline.
    """
    async def gateway_tool(**kwargs) -> str:
        config = GatewayConfig(gateway_url=gateway_url, token=token, tenant_id=tenant_id)
        async with McpGatewayClient(config) as client:
            try:
                result = await client.call_tool(tool_name, kwargs)
                return str(result.content)
            except McpGatewayError as e:
                return f"ERROR [{e.code}]: {str(e)}. Reason: {e.reason}"

    # AutoGen needs a sync wrapper
    def sync_tool(**kwargs) -> str:
        return asyncio.get_event_loop().run_until_complete(gateway_tool(**kwargs))

    # Set proper function name and docstring for AutoGen's tool registry
    sync_tool.__name__ = tool_name
    sync_tool.__doc__ = f"Call '{tool_name}' via MCP Security Gateway (authenticated, inspected, audited)."
    return sync_tool


def build_function_map(
    gateway_url: str,
    token: str,
    tools: List[str],
    tenant_id: Optional[str] = None,
) -> Dict[str, Callable]:
    """
    Build a function_map dict for use with ConversableAgent.

    Args:
        gateway_url: Base URL of your MCP Security Gateway
        token:       Bearer token
        tools:       List of tool names to register
        tenant_id:   Optional tenant ID

    Returns:
        Dict mapping tool names to callable functions

    Example:
        fn_map = build_function_map(
            gateway_url="https://my-gateway.com",
            token="token-abc",
            tools=["query_database", "read_file", "web_search"],
        )
        agent = ConversableAgent(
            name="analyst",
            llm_config=llm_config,
            function_map=fn_map,
        )
    """
    return {
        name: _make_tool_fn(name, gateway_url, token, tenant_id)
        for name in tools
    }


def register_gateway_tools(
    agent: Any,
    gateway_url: str,
    token: str,
    tools: List[str],
    tenant_id: Optional[str] = None,
) -> None:
    """
    Register MCP Security Gateway tools directly on an existing AutoGen agent.
    Modifies the agent in-place.

    Args:
        agent:       AutoGen ConversableAgent instance
        gateway_url: Gateway base URL
        token:       Bearer token
        tools:       Tool names to register
        tenant_id:   Optional tenant ID

    Example:
        agent = ConversableAgent("analyst", llm_config=config)
        register_gateway_tools(agent, "https://my-gateway.com", "token", ["query_database"])
    """
    _require_autogen()
    fn_map = build_function_map(gateway_url, token, tools, tenant_id)

    if hasattr(agent, "function_map"):
        agent.function_map.update(fn_map)
    elif hasattr(agent, "register_function"):
        for name, fn in fn_map.items():
            agent.register_function(function_map={name: fn})
    else:
        raise ValueError(f"Cannot register tools on {type(agent).__name__} — unsupported agent type")


# ── SecureConversableAgent ─────────────────────────────────────────────

class SecureConversableAgent:
    """
    Factory that creates an AutoGen ConversableAgent with gateway tools
    loaded automatically from the agent's policy.

    Usage:
        agent = await SecureConversableAgent.from_policy(
            agent_id="code-agent-01",
            name="CodeAssistant",
            system_message="You are a helpful coding assistant.",
            llm_config={"config_list": [...]},
            gateway_url="https://your-gateway.com",
            token="your-token",
        )
    """

    @classmethod
    async def from_policy(
        cls,
        agent_id: str,
        name: str,
        system_message: str,
        llm_config: Dict,
        gateway_url: str,
        token: str,
        tenant_id: Optional[str] = None,
        **kwargs,
    ) -> Any:
        _require_autogen()

        config = GatewayConfig(gateway_url=gateway_url, token=token, tenant_id=tenant_id)
        async with McpGatewayClient(config) as client:
            try:
                policy = await client.get_policy(agent_id)
                tools = policy.get("allowedTools", [])
            except Exception:
                tools = []

        fn_map = build_function_map(gateway_url, token, tools, tenant_id)

        return ConversableAgent(
            name=name,
            system_message=system_message,
            llm_config=llm_config,
            function_map=fn_map,
            **kwargs,
        )
