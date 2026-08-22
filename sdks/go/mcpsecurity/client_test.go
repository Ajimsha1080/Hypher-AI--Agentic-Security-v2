package hypher_ai_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	hypher_ai "github.com/antigravity/hypher_ai-go"
)

func mockServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *hypher_ai.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := hypher_ai.New(hypher_ai.Config{
		GatewayURL: srv.URL,
		Token:      "test-token",
		TenantID:   "tenant-123",
		Timeout:    5 * time.Second,
		Retries:    1,
	})
	return srv, client
}

func TestCallToolSuccess(t *testing.T) {
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing auth header")
		}
		if r.Header.Get("X-Tenant-ID") != "tenant-123" {
			t.Error("missing tenant header")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{
				"content": "42 rows returned", "isError": false,
			},
			"_meta": map[string]any{"executionTimeMs": float64(38)},
		})
	})

	result, err := client.CallTool(context.Background(), "query_database", map[string]any{
		"query": "SELECT * FROM orders",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Content != "42 rows returned" {
		t.Errorf("got content=%v, want '42 rows returned'", result.Content)
	}
	if result.ExecutionTimeMs != 38 {
		t.Errorf("got execMs=%d, want 38", result.ExecutionTimeMs)
	}
}

func TestCallToolPolicyDenied(t *testing.T) {
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{
			"error": "Policy denied", "reason": "no_matching_policy",
		})
	})

	_, err := client.CallTool(context.Background(), "run_command", map[string]any{"cmd": "ls"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	gwErr, ok := err.(*hypher_ai.GatewayError)
	if !ok {
		t.Fatalf("expected *GatewayError, got %T", err)
	}
	if gwErr.Code != hypher_ai.ErrPolicyDenied {
		t.Errorf("got code=%s, want POLICY_DENIED", gwErr.Code)
	}
	if gwErr.HTTPStatus != 403 {
		t.Errorf("got status=%d, want 403", gwErr.HTTPStatus)
	}
	if gwErr.Reason != "no_matching_policy" {
		t.Errorf("got reason=%s, want no_matching_policy", gwErr.Reason)
	}
}

func TestCallToolReplayDetected(t *testing.T) {
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "Duplicate request"})
	})

	_, err := client.CallTool(context.Background(), "read_file", map[string]any{"path": "x"})
	gwErr, ok := err.(*hypher_ai.GatewayError)
	if !ok || gwErr.Code != hypher_ai.ErrReplayDetected {
		t.Errorf("expected REPLAY_DETECTED, got %v", err)
	}
}

func TestRetryOn429(t *testing.T) {
	callCount := 0
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{"error": "Rate limited"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"content": "ok", "isError": false},
		})
	})

	result, err := client.CallTool(context.Background(), "read_file", map[string]any{"path": "x"})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if result.Content != "ok" {
		t.Errorf("got %v, want 'ok'", result.Content)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestHealthCheck(t *testing.T) {
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok", "db": "connected", "redis": "connected",
		})
	})

	health, err := client.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("got status=%s, want ok", health.Status)
	}
}

func TestContextCancellation(t *testing.T) {
	_, client := mockServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"content": "ok", "isError": false}})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.CallTool(ctx, "read_file", map[string]any{"path": "x"})
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}
