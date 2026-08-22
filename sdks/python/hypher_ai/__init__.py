"""
hypher_ai — Python SDK for MCP Security Gateway

Quick start:
    pip install hypher_ai

    from hypher_ai import McpGatewayClient

    async with McpGatewayClient(gateway_url="https://...", token="...") as client:
        result = await client.call_tool("query_database", {"query": "SELECT 1"})
"""

from hypher_ai.client import (
    McpGatewayClient,
    McpGatewayClientSync,
    McpGatewayError,
    GatewayErrorCode,
    GatewayConfig,
    ToolCallResult,
    GatewayMetrics,
    AuditLogEntry,
)

__version__ = "2.0.0"
__author__ = "Antigravity"
__all__ = [
    "McpGatewayClient",
    "McpGatewayClientSync",
    "McpGatewayError",
    "GatewayErrorCode",
    "GatewayConfig",
    "ToolCallResult",
    "GatewayMetrics",
    "AuditLogEntry",
]
