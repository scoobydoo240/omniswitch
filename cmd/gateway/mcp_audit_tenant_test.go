package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/omniswitch-dev/omniswitch/internal/admin"
	"github.com/omniswitch-dev/omniswitch/internal/audit"
	"github.com/omniswitch-dev/omniswitch/internal/dashboard"
	"github.com/omniswitch-dev/omniswitch/internal/feedback"
	"github.com/omniswitch-dev/omniswitch/internal/gateway"
	"github.com/omniswitch-dev/omniswitch/internal/guardrail"
	"github.com/omniswitch-dev/omniswitch/internal/org"
	"github.com/omniswitch-dev/omniswitch/internal/policy"
	"github.com/omniswitch-dev/omniswitch/internal/prompt"
	"github.com/omniswitch-dev/omniswitch/internal/provider"
	mcpproxy "github.com/omniswitch-dev/omniswitch/internal/proxy"
	"github.com/omniswitch-dev/omniswitch/internal/router"
)

// TestMCPAuditRowsCarryCallerTenant covers T2 end to end: an MCP call made
// with a workspace-scoped key is written with the caller's workspace and
// organization, so the same key finds it in /api/logs and can attach
// feedback to it, while a key of another workspace cannot.
func TestMCPAuditRowsCarryCallerTenant(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`)
	}))
	t.Cleanup(upstream.Close)

	st := newTestStore(t)
	settings := runtimeSettings{
		authEnabled:       true,
		bootstrapAPIKey:   routeTestKey,
		rateLimitRequests: 1000,
		rateLimitWindow:   time.Minute,
	}
	if err := ensureBootstrapKey(context.Background(), st, settings); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	mcpHandler, err := mcpproxy.NewHandler(engine, audit.NewStoreLogger(st), upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mcpHandler.Close)
	registry := provider.NewRegistry()
	gw := gateway.New(registry, router.New(registry), st, guardrail.NewEngine())
	mux := newGatewayMux(routeHandlers{
		settings: settings, registry: registry, gateway: gw, admin: admin.New(st),
		feedback: feedback.New(st), prompt: prompt.New(st), org: org.New(st), dash: dashboard.New(st),
		mcp: mcpHandler,
	})
	h, closeRateLimiter, err := wrapGatewayMiddleware(settings, st, mux)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeRateLimiter)

	global := routeTestKey
	createID := func(path, body string) string {
		t.Helper()
		rec := doRequest(h, http.MethodPost, path, global, body, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST %s = %d, body = %s", path, rec.Code, rec.Body.String())
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.ID
	}
	orgA := createID("/api/orgs", `{"name":"A"}`)
	wsA := createID("/api/workspaces", `{"organization_id":"`+orgA+`","name":"a"}`)
	wsB := createID("/api/workspaces", `{"organization_id":"`+orgA+`","name":"b"}`)
	keyA := createTestKey(t, h, global, `{"name":"a","workspace_id":"`+wsA+`","role":"admin"}`)
	keyB := createTestKey(t, h, global, `{"name":"b","workspace_id":"`+wsB+`","role":"admin"}`)

	// A client cannot choose the tenant written with its MCP row.
	rec := doRequest(h, http.MethodPost, "/mcp", keyA,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
		map[string]string{"x-omniswitch-workspace-id": wsB, "x-omniswitch-organization-id": "org_forged"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /mcp = %d, body = %s", rec.Code, rec.Body.String())
	}

	mcpLogs := func(key string) []map[string]any {
		t.Helper()
		rec := doRequest(h, http.MethodGet, "/api/logs?provider=mcp", key, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/logs = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Logs []map[string]any `json:"logs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Logs
	}
	logs := mcpLogs(keyA)
	if len(logs) != 1 || logs[0]["workspace_id"] != wsA || logs[0]["organization_id"] != orgA {
		t.Fatalf("workspace A MCP logs = %v, want one row in %s/%s", logs, wsA, orgA)
	}
	requestID, _ := logs[0]["id"].(string)
	if got := mcpLogs(keyB); len(got) != 0 {
		t.Fatalf("workspace B sees A's MCP logs: %v", got)
	}

	feedbackBody := `{"request_id":"` + requestID + `","score":1}`
	if rec := doRequest(h, http.MethodPost, "/api/feedback", keyA, feedbackBody, nil); rec.Code != http.StatusCreated {
		t.Fatalf("workspace A feedback on its MCP call = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := doRequest(h, http.MethodPost, "/api/feedback", keyB, feedbackBody, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("workspace B feedback on A's MCP call = %d, want 404", rec.Code)
	}
	if strings.TrimSpace(requestID) == "" {
		t.Fatal("MCP log has no id")
	}
}
