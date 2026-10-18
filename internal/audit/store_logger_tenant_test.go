package audit

import (
	"strings"
	"testing"

	"github.com/omniswitch-dev/omniswitch/internal/model"
)

// TestStoreRequestLogCarriesTenant covers T2: the MCP audit row carries the
// caller's workspace and organization in the tenant columns that scoped
// dashboard reads filter on, and keeps the workspace in the metadata.
func TestStoreRequestLogCarriesTenant(t *testing.T) {
	event := NewEvent(model.ToolRequest{
		Agent: model.Agent{ID: "key_1"},
		Tool:  model.Tool{Name: "echo"},
	}, model.Decision{ID: "dec_1", Allowed: true})
	event.Workspace = "ws_1"
	event.Organization = "org_1"
	log := storeRequestLog(event)
	if log.WorkspaceID != "ws_1" || log.OrganizationID != "org_1" {
		t.Fatalf("log tenant = %q/%q, want ws_1/org_1", log.WorkspaceID, log.OrganizationID)
	}
	if !strings.Contains(log.Metadata, `"workspace_id":"ws_1"`) {
		t.Fatalf("metadata = %s, want the workspace kept", log.Metadata)
	}

	global := storeRequestLog(NewEvent(model.ToolRequest{Tool: model.Tool{Name: "echo"}}, model.Decision{ID: "dec_2"}))
	if global.WorkspaceID != "" || global.OrganizationID != "" {
		t.Fatalf("global caller log tenant = %q/%q, want none", global.WorkspaceID, global.OrganizationID)
	}
}
