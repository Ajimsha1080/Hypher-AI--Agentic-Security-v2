// Package hypher_ai provides a Go client for MCP Security Gateway.
//
// Installation:
//
//	go get github.com/antigravity/hypher_ai-go
//
// Usage:
//
//	client := hypher_ai.New(hypher_ai.Config{
//	    GatewayURL: "https://your-gateway.com",
//	    Token:      "your-bearer-token",
//	    TenantID:   "your-tenant-id",
//	})
//
//	result, err := client.CallTool(ctx, "query_database", map[string]any{
//	    "query": "SELECT * FROM orders LIMIT 10",
//	})
package hypher_ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

// ── Error types ────────────────────────────────────────────────────────

// ErrorCode represents the category of gateway error.
type ErrorCode string

const (
	ErrAuthFailed        ErrorCode = "AUTH_FAILED"
	ErrPolicyDenied      ErrorCode = "POLICY_DENIED"
	ErrInspectionBlocked ErrorCode = "INSPECTION_BLOCKED"
	ErrRateLimited       ErrorCode = "RATE_LIMITED"
	ErrReplayDetected    ErrorCode = "REPLAY_DETECTED"
	ErrUpstreamError     ErrorCode = "UPSTREAM_ERROR"
)

// GatewayError is returned when the MCP Security Gateway rejects a request.
type GatewayError struct {
	Code       ErrorCode
	Message    string
	Reason     string
	HTTPStatus int
	RetryAfter int // seconds; non-zero when rate limited
}

func (e *GatewayError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("hypher_ai [%s]: %s (reason: %s)", e.Code, e.Message, e.Reason)
	}
	return fmt.Sprintf("hypher_ai [%s]: %s", e.Code, e.Message)
}

// ── Result types ───────────────────────────────────────────────────────

// ToolCallResult holds the response from a tool call.
type ToolCallResult struct {
	Content        any
	IsError        bool
	ExecutionTimeMs int
	RequestID      string
}

// GatewayMetrics holds aggregated metrics from the gateway.
type GatewayMetrics struct {
	TotalCalls    int64
	AllowedCalls  int64
	DeniedCalls   int64
	DenialRate    float64
	AvgExecMs     float64
	ActiveAgents  int
}

// HealthStatus holds the gateway health check response.
type HealthStatus struct {
	Status string
	DB     string
	Redis  string
}

// ── Config ─────────────────────────────────────────────────────────────

// Config holds the client configuration.
type Config struct {
	GatewayURL     string
	Token          string
	TenantID       string
	OIDCProvider   string        // "google" | "azure" | "okta"
	Timeout        time.Duration // default 30s
	Retries        int           // default 2
	HTTPClient     *http.Client
}

func (c *Config) setDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Retries == 0 {
		c.Retries = 2
	}
}

// ── Client ─────────────────────────────────────────────────────────────

// Client is the MCP Security Gateway client.
// It is safe for concurrent use.
type Client struct {
	config  Config
	http    *http.Client
	counter atomic.Int64
}

// New creates a new MCP Security Gateway client.
func New(cfg Config) *Client {
	cfg.setDefaults()
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{config: cfg, http: httpClient}
}

// ── Core tool call ─────────────────────────────────────────────────────

// CallTool calls a tool through the MCP Security Gateway.
// All calls pass through the full 10-layer security pipeline:
// Auth → Tenant → Inspect → Registry → RBAC → Anomaly →
// Replay → Lock → Forward → Audit
func (c *Client) CallTool(ctx context.Context, toolName string, args map[string]any) (*ToolCallResult, error) {
	id := c.counter.Add(1)
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": args,
		},
	}

	resp, err := c.post(ctx, "/mcp", body)
	if err != nil {
		return nil, err
	}

	result := resp["result"].(map[string]any)
	meta, _ := resp["_meta"].(map[string]any)

	out := &ToolCallResult{
		Content: result["content"],
		IsError: result["isError"] == true,
	}
	if meta != nil {
		if ms, ok := meta["executionTimeMs"].(float64); ok {
			out.ExecutionTimeMs = int(ms)
		}
		if id, ok := meta["requestId"].(string); ok {
			out.RequestID = id
		}
	}
	return out, nil
}

// ── Convenience wrappers ───────────────────────────────────────────────

// QueryDatabase executes a SQL query through the gateway.
func (c *Client) QueryDatabase(ctx context.Context, query string, database ...string) (*ToolCallResult, error) {
	args := map[string]any{"query": query}
	if len(database) > 0 && database[0] != "" {
		args["database"] = database[0]
	}
	return c.CallTool(ctx, "query_database", args)
}

// ReadFile reads a file through the gateway.
func (c *Client) ReadFile(ctx context.Context, path string) (*ToolCallResult, error) {
	return c.CallTool(ctx, "read_file", map[string]any{"path": path})
}

// WriteFile writes a file through the gateway.
func (c *Client) WriteFile(ctx context.Context, path, content string) (*ToolCallResult, error) {
	return c.CallTool(ctx, "write_file", map[string]any{"path": path, "content": content})
}

// HTTPRequest makes an HTTP request through the gateway.
func (c *Client) HTTPRequest(ctx context.Context, reqURL, method string, body ...any) (*ToolCallResult, error) {
	args := map[string]any{"url": reqURL, "method": method}
	if len(body) > 0 {
		args["body"] = body[0]
	}
	return c.CallTool(ctx, "http_request", args)
}

// ── Policy management ──────────────────────────────────────────────────

// GetPolicy returns the policy for an agent.
func (c *Client) GetPolicy(ctx context.Context, agentID string) (map[string]any, error) {
	return c.get(ctx, "/api/policies/"+url.PathEscape(agentID))
}

// SetPolicy sets the allowed tools for an agent.
func (c *Client) SetPolicy(ctx context.Context, agentID string, allowedTools []string) (map[string]any, error) {
	return c.put(ctx, "/api/policies/"+url.PathEscape(agentID), map[string]any{
		"allowedTools": allowedTools,
	})
}

// GeneratePolicy uses the LLM policy assistant to generate a policy from plain English.
func (c *Client) GeneratePolicy(ctx context.Context, agentID, description string, dryRun bool) (map[string]any, error) {
	return c.post(ctx, "/api/policy-assistant/generate", map[string]any{
		"agentId": agentID, "description": description, "dryRun": dryRun,
	})
}

// ── Audit & metrics ────────────────────────────────────────────────────

// GetMetrics returns aggregated gateway metrics.
func (c *Client) GetMetrics(ctx context.Context) (*GatewayMetrics, error) {
	data, err := c.get(ctx, "/api/dashboard/metrics")
	if err != nil {
		return nil, err
	}
	return &GatewayMetrics{
		TotalCalls:   int64(data["totalCalls"].(float64)),
		AllowedCalls: int64(data["allowedCalls"].(float64)),
		DeniedCalls:  int64(data["deniedCalls"].(float64)),
		DenialRate:   data["denialRate"].(float64),
		AvgExecMs:    data["avgExecutionMs"].(float64),
	}, nil
}

// HealthCheck returns the gateway health status.
func (c *Client) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	data, err := c.get(ctx, "/health/ready")
	if err != nil {
		return nil, err
	}
	h := &HealthStatus{}
	if s, ok := data["status"].(string); ok { h.Status = s }
	if s, ok := data["db"].(string); ok { h.DB = s }
	if s, ok := data["redis"].(string); ok { h.Redis = s }
	return h, nil
}

// ── HTTP internals ─────────────────────────────────────────────────────

func (c *Client) post(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.request(ctx, http.MethodPost, path, body, 0)
}

func (c *Client) get(ctx context.Context, path string) (map[string]any, error) {
	return c.request(ctx, http.MethodGet, path, nil, 0)
}

func (c *Client) put(ctx context.Context, path string, body any) (map[string]any, error) {
	return c.request(ctx, http.MethodPut, path, body, 0)
}

func (c *Client) request(ctx context.Context, method, path string, body any, attempt int) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	fullURL := c.config.GatewayURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.Token)
	if c.config.TenantID != "" {
		req.Header.Set("X-Tenant-ID", c.config.TenantID)
	}
	if c.config.OIDCProvider != "" {
		req.Header.Set("X-OIDC-Provider", c.config.OIDCProvider)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests && attempt < c.config.Retries {
		retryAfter := 5
		if s := resp.Header.Get("Retry-After"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				retryAfter = n
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(retryAfter) * time.Second):
		}
		return c.request(ctx, method, path, body, attempt+1)
	}

	if resp.StatusCode >= 400 {
		var errBody map[string]any
		_ = json.Unmarshal(respBody, &errBody)
		code := mapStatusToCode(resp.StatusCode)
		gwErr := &GatewayError{
			Code:       code,
			HTTPStatus: resp.StatusCode,
			Message:    "Gateway error",
		}
		if msg, ok := errBody["error"].(string); ok { gwErr.Message = msg }
		if reason, ok := errBody["reason"].(string); ok { gwErr.Reason = reason }
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			gwErr.RetryAfter, _ = strconv.Atoi(ra)
		}
		return nil, gwErr
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

func mapStatusToCode(status int) ErrorCode {
	switch status {
	case 401: return ErrAuthFailed
	case 403: return ErrPolicyDenied
	case 409: return ErrReplayDetected
	case 429: return ErrRateLimited
	default:  return ErrUpstreamError
	}
}
