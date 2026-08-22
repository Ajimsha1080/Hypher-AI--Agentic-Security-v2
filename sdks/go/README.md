# hypher_ai-go — Go SDK

Zero-trust MCP Security Gateway client for Go. Designed for infrastructure, platform, and DevOps teams.

## Install

```bash
go get github.com/antigravity/hypher_ai-go
```

---

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    hypher_ai "github.com/antigravity/hypher_ai-go"
)

func main() {
    client := hypher_ai.New(hypher_ai.Config{
        GatewayURL: "https://your-gateway.com",
        Token:      "your-bearer-token",
        TenantID:   "your-tenant-id",
    })

    result, err := client.CallTool(context.Background(), "query_database", map[string]any{
        "query": "SELECT count(*) FROM orders WHERE status = 'pending'",
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(result.Content)
}
```

---

## Error handling

```go
result, err := client.CallTool(ctx, "run_command", map[string]any{"cmd": "ls"})
if err != nil {
    if gwErr, ok := err.(*hypher_ai.GatewayError); ok {
        switch gwErr.Code {
        case hypher_ai.ErrPolicyDenied:
            fmt.Printf("Policy denied: %s\n", gwErr.Reason)
        case hypher_ai.ErrRateLimited:
            fmt.Printf("Rate limited, retry after %ds\n", gwErr.RetryAfter)
        case hypher_ai.ErrReplayDetected:
            fmt.Println("Duplicate request blocked")
        default:
            fmt.Printf("Gateway error: %v\n", gwErr)
        }
    }
}
```

---

## All methods

```go
// Tool calls
client.CallTool(ctx, toolName, args)
client.QueryDatabase(ctx, query, database?)
client.ReadFile(ctx, path)
client.WriteFile(ctx, path, content)
client.HTTPRequest(ctx, url, method, body?)

// Policy management
client.GetPolicy(ctx, agentID)
client.SetPolicy(ctx, agentID, allowedTools)
client.GeneratePolicy(ctx, agentID, description, dryRun)

// Observability
client.GetMetrics(ctx)
client.HealthCheck(ctx)
```

---

## Running tests

```bash
go test ./... -v
```
