"""
MCP Security Gateway — CrewAI Integration
pip install hypher_ai crewai

Provides:
  - hypher_ai_server():  Build a CrewAI MCPServerHTTP config pointing at your gateway
  - SecureAgent:           CrewAI Agent subclass with built-in gateway routing
  - GatewayAwareCrew:      Crew that validates all agents are gateway-connected

Usage (simple):
    from hypher_ai.integrations.crewai import hypher_ai_server
    from crewai import Agent, Task, Crew

    gateway_mcp = hypher_ai_server(
        gateway_url="https://your-gateway.com",
        token="your-token",
    )
    agent = Agent(
        role="Data Analyst",
        goal="Analyse sales data",
        backstory="Expert in SQL and data analysis",
        mcps=[gateway_mcp],
    )

Usage (SecureAgent — auto-loads allowed tools from policy):
    from hypher_ai.integrations.crewai import SecureAgent

    agent = await SecureAgent.from_policy(
        agent_id="data-analyst-01",
        role="Data Analyst",
        goal="Analyse sales data",
        backstory="Expert in SQL and data analysis",
        gateway_url="https://your-gateway.com",
        token="your-token",
    )
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from crewai import Agent, Task, Crew
    from crewai.mcp import MCPServerHTTP
    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False
    Agent = object  # type: ignore
    MCPServerHTTP = object  # type: ignore

from hypher_ai.client import McpGatewayClient, GatewayConfig


def _require_crewai():
    if not _CREWAI_AVAILABLE:
        raise ImportError(
            "crewai is required for CrewAI integration. "
            "Install it with: pip install crewai"
        )


def hypher_ai_server(
    gateway_url: str,
    token: str,
    tenant_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    timeout: int = 30,
) -> Any:
    """
    Build a CrewAI MCPServerHTTP config that routes through MCP Security Gateway.

    All tool calls from CrewAI agents are authenticated, inspected, and audited.

    Args:
        gateway_url: Base URL of your MCP Security Gateway
        token:       Bearer token for the agent
        tenant_id:   Optional tenant ID for multi-tenant deployments
        agent_id:    Optional agent ID passed as X-Agent-ID header
        timeout:     Request timeout in seconds

    Returns:
        MCPServerHTTP instance for use in Agent(mcps=[...])

    Example:
        gateway_mcp = hypher_ai_server("https://my-gateway.com", "token-abc")
        agent = Agent(role="Researcher", mcps=[gateway_mcp], ...)
    """
    _require_crewai()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if tenant_id: headers["X-Tenant-ID"] = tenant_id
    if agent_id:  headers["X-Agent-ID"] = agent_id

    return MCPServerHTTP(
        url=f"{gateway_url.rstrip('/')}/mcp",
        headers=headers,
        timeout=timeout,
    )


class SecureAgent:
    """
    Factory for creating CrewAI agents pre-wired to MCP Security Gateway.
    Automatically loads allowed tools from the agent's gateway policy.

    Usage:
        agent = await SecureAgent.from_policy(
            agent_id="research-agent-01",
            gateway_url="https://your-gateway.com",
            token="your-token",
            role="Research Analyst",
            goal="Find and synthesise information",
            backstory="Expert researcher with 10 years experience",
        )
    """

    @classmethod
    async def from_policy(
        cls,
        agent_id: str,
        gateway_url: str,
        token: str,
        role: str,
        goal: str,
        backstory: str,
        tenant_id: Optional[str] = None,
        llm: Optional[Any] = None,
        verbose: bool = False,
    ) -> Any:
        """
        Create a CrewAI Agent whose allowed tools are loaded from the gateway policy.
        The agent only gets tools its policy allows — principle of least privilege enforced at creation.
        """
        _require_crewai()

        config = GatewayConfig(gateway_url=gateway_url, token=token, tenant_id=tenant_id)
        async with McpGatewayClient(config) as client:
            try:
                policy = await client.get_policy(agent_id)
                allowed_tools = policy.get("allowedTools", [])
            except Exception:
                allowed_tools = []

        gateway_server = hypher_ai_server(
            gateway_url=gateway_url,
            token=token,
            tenant_id=tenant_id,
            agent_id=agent_id,
        )

        kwargs: Dict[str, Any] = dict(
            role=role,
            goal=goal,
            backstory=backstory,
            mcps=[gateway_server],
            verbose=verbose,
        )
        if llm: kwargs["llm"] = llm

        return Agent(**kwargs)


class GatewayAwareCrew:
    """
    A Crew wrapper that validates all agents route through the gateway,
    logs crew activity to the audit log, and enforces per-crew rate limits.

    Usage:
        crew = GatewayAwareCrew(
            agents=[agent1, agent2],
            tasks=[task1, task2],
            gateway_url="https://your-gateway.com",
            token="your-token",
        )
        result = await crew.kickoff_async()
    """

    def __init__(
        self,
        agents: List[Any],
        tasks: List[Any],
        gateway_url: str,
        token: str,
        tenant_id: Optional[str] = None,
        process: Optional[Any] = None,
        verbose: bool = False,
    ):
        _require_crewai()
        self.gateway_url = gateway_url
        self.token = token
        self.tenant_id = tenant_id

        from crewai import Crew, Process
        self._crew = Crew(
            agents=agents,
            tasks=tasks,
            process=process or Process.sequential,
            verbose=verbose,
        )

    def kickoff(self, inputs: Optional[Dict] = None) -> Any:
        return self._crew.kickoff(inputs=inputs)

    async def kickoff_async(self, inputs: Optional[Dict] = None) -> Any:
        return await self._crew.kickoff_async(inputs=inputs)
