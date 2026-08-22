# hypher_ai — Python SDK

Zero-trust MCP Security Gateway client for Python. All AI agent tool calls are authenticated, inspected, policy-checked, and audited through the gateway's 10-layer security pipeline.

## Install

```bash
pip install hypher_ai

# With framework integrations
pip install "hypher_ai[langchain]"   # LangChain + LangGraph
pip install "hypher_ai[crewai]"      # CrewAI
pip install "hypher_ai[autogen]"     # AutoGen / AG2
pip install "hypher_ai[all]"         # All frameworks
```

---

## Quick start

```python
import asyncio
from hypher_ai import McpGatewayClient

async def main():
    async with McpGatewayClient(
        gateway_url="https://your-gateway.com",
        token="your-bearer-token",
        tenant_id="your-tenant-id",
    ) as client:
        # All calls pass through 10 security layers
        result = await client.query_database("SELECT * FROM orders LIMIT 10")
        print(result.content)

asyncio.run(main())
```

### Synchronous (non-async) usage

```python
from hypher_ai import McpGatewayClientSync

client = McpGatewayClientSync(
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
)
result = client.read_file("reports/q4.pdf")
print(result.content)
```

---

## LangChain integration

```python
from hypher_ai.integrations.langchain import hypher_aiToolkit
from langchain_anthropic import ChatAnthropic
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate

# Build toolkit — all tools route through gateway security pipeline
toolkit = hypher_aiToolkit(
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
    allowed_tools=["read_file", "query_database", "web_search", "http_request"],
)

llm = ChatAnthropic(model="claude-sonnet-4-20250514")
tools = toolkit.get_tools()
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant with access to tools."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
result = executor.invoke({"input": "Read the Q4 report and summarise revenue"})
```

### Auto-load tools from gateway policy

```python
# Load allowed tools automatically from the agent's policy — no hardcoding
toolkit = await hypher_aiToolkit.from_gateway_policy(
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
    agent_id="research-agent-01",
)
tools = toolkit.get_tools()
```

---

## CrewAI integration

```python
from hypher_ai.integrations.crewai import hypher_ai_server, SecureAgent
from crewai import Task, Crew, Process
from langchain_anthropic import ChatAnthropic

# Simple: point CrewAI agent at gateway
gateway_mcp = hypher_ai_server(
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
    tenant_id="your-tenant-id",
)

agent = Agent(
    role="Data Analyst",
    goal="Analyse customer data and produce insights",
    backstory="Expert data analyst with 10 years experience in SQL and statistics.",
    mcps=[gateway_mcp],  # All tool calls go through gateway
    llm=ChatAnthropic(model="claude-sonnet-4-20250514"),
)

task = Task(
    description="Query the orders table and find the top 10 customers by revenue this quarter",
    agent=agent,
    expected_output="A ranked list of top 10 customers with revenue figures",
)

crew = Crew(agents=[agent], tasks=[task], process=Process.sequential)
result = crew.kickoff()
```

### Auto-load from policy

```python
# SecureAgent loads allowed tools from gateway policy automatically
agent = await SecureAgent.from_policy(
    agent_id="data-analyst-01",
    role="Data Analyst",
    goal="Analyse customer data",
    backstory="Expert data analyst.",
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
)
```

---

## AutoGen / AG2 integration

```python
from hypher_ai.integrations.autogen import register_gateway_tools, build_function_map
from autogen import ConversableAgent

llm_config = {"config_list": [{"model": "claude-sonnet-4-20250514", "api_key": "..."}]}

analyst = ConversableAgent(name="DataAnalyst", llm_config=llm_config)

# Register gateway tools on the agent
register_gateway_tools(
    analyst,
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
    tools=["query_database", "read_file", "web_search"],
)

# Or build function_map directly
fn_map = build_function_map(
    gateway_url="https://your-gateway.com",
    token="your-bearer-token",
    tools=["query_database", "read_file"],
)
agent = ConversableAgent(name="Analyst", llm_config=llm_config, function_map=fn_map)
```

---

## Error handling

```python
from hypher_ai import McpGatewayClient, McpGatewayError, GatewayErrorCode

async with McpGatewayClient(gateway_url="...", token="...") as client:
    try:
        result = await client.call_tool("run_command", {"cmd": "ls"})
    except McpGatewayError as e:
        match e.code:
            case GatewayErrorCode.POLICY_DENIED:
                print(f"Agent not allowed to call this tool: {e.reason}")
            case GatewayErrorCode.INSPECTION_BLOCKED:
                print(f"Input failed security inspection: {e.reason}")
            case GatewayErrorCode.RATE_LIMITED:
                print(f"Rate limited, retry after {e.retry_after}s")
            case GatewayErrorCode.AUTH_FAILED:
                print("Invalid or expired token")
            case _:
                print(f"Gateway error: {e}")
```

---

## Policy management

```python
async with McpGatewayClient(...) as client:
    # Set allowed tools for an agent
    await client.set_policy("agent-123", ["read_file", "query_database"])

    # Use LLM assistant to generate policy from plain English
    result = await client.generate_policy(
        agent_id="agent-123",
        description="Allow this agent to read files and run SELECT queries, but not write or delete anything",
        dry_run=True,  # Preview without applying
    )
    print(result["policy"]["explanation"])
```

---

## Audit & compliance

```python
async with McpGatewayClient(...) as client:
    # Get recent audit log
    logs = await client.get_audit_log(limit=50, decision="DENY")
    for entry in logs:
        print(f"{entry.agent_id} — {entry.tool_name} — {entry.decision} — {entry.reason}")

    # Export SOC 2 compliance report
    report = await client.export_soc2_report(
        date_from="2026-01-01",
        date_to="2026-03-31",
        format="json",
    )
    print(f"Total requests: {report['summary']['totalRequests']}")
    print(f"Security events: {report['securityEvents']}")
```

---

## Running tests

```bash
pip install "hypher_ai[dev]"
pytest sdks/python/hypher_ai/tests/ -v
```
