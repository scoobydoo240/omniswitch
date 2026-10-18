package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestScopedAdminCannotTakeInOtherTenantsUser covers T1 end to end through
// the real authentication middleware: a workspace admin of B that posts the
// email of a user who belongs only to workspace A gets a 409 without the
// user's data, is not given a membership and does not list the user.
func TestScopedAdminCannotTakeInOtherTenantsUser(t *testing.T) {
	h := newSecurityTestServer(t, nil)
	global := routeTestKey

	decodeID := func(t *testing.T, path, key, body string) string {
		t.Helper()
		rec := doRequest(h, http.MethodPost, path, key, body, nil)
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
	orgA := decodeID(t, "/api/orgs", global, `{"name":"A"}`)
	orgB := decodeID(t, "/api/orgs", global, `{"name":"B"}`)
	wsA := decodeID(t, "/api/workspaces", global, `{"organization_id":"`+orgA+`","name":"a"}`)
	wsB := decodeID(t, "/api/workspaces", global, `{"organization_id":"`+orgB+`","name":"b"}`)
	keyA := createTestKey(t, h, global, `{"name":"a","workspace_id":"`+wsA+`","role":"admin"}`)
	keyB := createTestKey(t, h, global, `{"name":"b","workspace_id":"`+wsB+`","role":"admin"}`)

	victim := decodeID(t, "/api/users", keyA, `{"email":"victim@corp-a.example","name":"Victim Name","metadata":{"dept":"secret-dept"}}`)

	rec := doRequest(h, http.MethodPost, "/api/users", keyB, `{"email":"victim@corp-a.example"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("workspace B takes in A's user = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leak := range []string{victim, "Victim Name", "secret-dept", "created_at"} {
		if strings.Contains(body, leak) {
			t.Fatalf("409 body leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "ask a global administrator") {
		t.Fatalf("409 body = %s, want the explanation", body)
	}

	// The membership API refuses the user as if it did not exist.
	rec = doRequest(h, http.MethodPost, "/api/workspace-members", keyB, `{"workspace_id":"`+wsB+`","user_id":"`+victim+`","role":"viewer"}`, nil)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "user not found") {
		t.Fatalf("workspace B adds A's user by id = %d, body = %s; want 404 user not found", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/api/users", "/api/workspace-members"} {
		rec := doRequest(h, http.MethodGet, path, keyB, "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), victim) || strings.Contains(rec.Body.String(), "victim@corp-a.example") {
			t.Fatalf("workspace B lists A's user in %s: %s", path, rec.Body.String())
		}
	}
	// A still has its user; the global key can add it to B.
	if rec := doRequest(h, http.MethodGet, "/api/users", keyA, "", nil); !strings.Contains(rec.Body.String(), victim) {
		t.Fatalf("workspace A lost its user: %s", rec.Body.String())
	}
	rec = doRequest(h, http.MethodPost, "/api/users", global, `{"email":"victim@corp-a.example","workspace_id":"`+wsB+`"}`, nil)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), victim) {
		t.Fatalf("global adds the user to B = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := doRequest(h, http.MethodGet, "/api/users", keyB, "", nil); !strings.Contains(rec.Body.String(), victim) {
		t.Fatalf("workspace B does not see the user a global admin added: %s", rec.Body.String())
	}
}
