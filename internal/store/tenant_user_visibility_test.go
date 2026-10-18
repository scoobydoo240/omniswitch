package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestUserVisibleToTenant checks the visibility rule shared by the user
// list, user creation and membership changes (T1): a scoped filter sees a
// user only when the user is a member of a workspace the filter sees.
func TestUserVisibleToTenant(t *testing.T) {
	forEachBackend(t, func(t *testing.T, st *Store) {
		seedTenants(t, st)
		ctx := context.Background()
		for _, tc := range []struct {
			filter TenantFilter
			user   string
			want   bool
		}{
			{TenantFilter{}, "ub", true},
			{TenantFilter{}, "loose", true},
			{TenantFilter{}, "missing", false},
			{TenantFilter{WorkspaceID: "ws_a1"}, "ua", true},
			{TenantFilter{WorkspaceID: "ws_a1"}, "shared", true},
			{TenantFilter{WorkspaceID: "ws_a1"}, "ua2", false},
			{TenantFilter{WorkspaceID: "ws_a1"}, "ub", false},
			{TenantFilter{WorkspaceID: "ws_a1"}, "loose", false},
			{TenantFilter{OrganizationID: "org_a"}, "ua2", true},
			{TenantFilter{OrganizationID: "org_a"}, "ub", false},
			{TenantFilter{OrganizationID: "org_b"}, "shared", true},
			{TenantFilter{OrganizationID: "org_b"}, "missing", false},
		} {
			got, err := st.UserVisibleToTenant(ctx, tc.filter, tc.user)
			if err != nil || got != tc.want {
				t.Errorf("UserVisibleToTenant(%+v, %s) = %v, %v; want %v", tc.filter, tc.user, got, err, tc.want)
			}
		}
	})
}

// TestAddUserToWorkspaceRejectsInvisibleUser covers T1: a scoped filter
// that names the email of a user it cannot see writes nothing and learns
// nothing about the user.
func TestAddUserToWorkspaceRejectsInvisibleUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, st *Store) {
		seedTenants(t, st)
		ctx := context.Background()
		for _, tc := range []struct {
			filter    TenantFilter
			email     string
			workspace string
		}{
			// ua is only in ws_a1 (org_a); ws_b belongs to org_b.
			{TenantFilter{WorkspaceID: "ws_b"}, "ua@example.com", "ws_b"},
			{TenantFilter{OrganizationID: "org_b"}, "ua@example.com", "ws_b"},
			// loose has no membership at all.
			{TenantFilter{WorkspaceID: "ws_b"}, "loose@example.com", "ws_b"},
			// A sibling workspace is not visible to a workspace filter.
			{TenantFilter{WorkspaceID: "ws_a1"}, "ua2@example.com", "ws_a1"},
		} {
			user, _, err := st.AddUserToWorkspace(ctx, tc.filter,
				User{ID: "fresh", Email: tc.email, Name: "renamed", Metadata: map[string]string{"x": "y"}},
				WorkspaceMember{WorkspaceID: tc.workspace, Role: "viewer"})
			if !errors.Is(err, ErrUserNotVisible) {
				t.Fatalf("AddUserToWorkspace(%+v, %s) error = %v, want ErrUserNotVisible", tc.filter, tc.email, err)
			}
			if user.ID != "" || user.Name != "" || user.Metadata != nil || !user.CreatedAt.IsZero() {
				t.Fatalf("AddUserToWorkspace(%+v, %s) returned user data %+v", tc.filter, tc.email, user)
			}
			stored, err := st.GetUserByEmail(ctx, tc.email)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetWorkspaceMember(ctx, tc.workspace, stored.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("membership of %s in %s was written: %v", stored.ID, tc.workspace, err)
			}
			if _, err := st.GetUserByID(ctx, "fresh"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a user row was written for %s: %v", tc.email, err)
			}
		}
		users, err := st.ListUsersForTenant(ctx, TenantFilter{WorkspaceID: "ws_b"})
		if err != nil {
			t.Fatal(err)
		}
		if got := sortedIDs(users, func(u User) string { return u.ID }); !equalStrings(got, []string{"shared", "ub"}) {
			t.Fatalf("ws_b users = %v, want shared and ub only", got)
		}

		// An organization filter may add a user who is already a member of
		// another workspace of the organization.
		user, member, err := st.AddUserToWorkspace(ctx, TenantFilter{OrganizationID: "org_a"},
			User{ID: "fresh", Email: "ua2@example.com"}, WorkspaceMember{WorkspaceID: "ws_a1", Role: "viewer"})
		if err != nil || user.ID != "ua2" || user.Name != "ua2" || member.UserID != "ua2" {
			t.Fatalf("org_a adds ua2 = %+v, %+v, %v", user, member, err)
		}
		// A global filter adds anyone.
		if user, _, err := st.AddUserToWorkspace(ctx, TenantFilter{}, User{ID: "fresh", Email: "loose@example.com"},
			WorkspaceMember{WorkspaceID: "ws_b", Role: "viewer"}); err != nil || user.ID != "loose" {
			t.Fatalf("global adds loose = %+v, %v", user, err)
		}
	})
}

// TestAddUserToWorkspaceConcurrentSameEmail races two tenants that create
// the same new email: one creates the user, the other gets
// ErrUserNotVisible and no user data, whatever the order.
func TestAddUserToWorkspaceConcurrentSameEmail(t *testing.T) {
	forEachBackend(t, func(t *testing.T, st *Store) {
		seedTenants(t, st)
		ctx := context.Background()
		for round := range 5 {
			email := fmt.Sprintf("race%d@example.com", round)
			filters := []TenantFilter{{WorkspaceID: "ws_a1"}, {WorkspaceID: "ws_b"}}
			type result struct {
				user User
				err  error
			}
			results := make([]result, len(filters))
			var wg sync.WaitGroup
			for i, f := range filters {
				wg.Add(1)
				go func() {
					defer wg.Done()
					user, _, err := st.AddUserToWorkspace(ctx, f,
						User{ID: fmt.Sprintf("u%d_%d", round, i), Email: email, Name: f.WorkspaceID},
						WorkspaceMember{WorkspaceID: f.WorkspaceID, Role: "viewer"})
					results[i] = result{user, err}
				}()
			}
			wg.Wait()
			var ok, rejected int
			for _, r := range results {
				switch {
				case r.err == nil:
					ok++
				case errors.Is(r.err, ErrUserNotVisible):
					rejected++
					if r.user.ID != "" || r.user.Name != "" {
						t.Fatalf("rejected caller got user data %+v", r.user)
					}
				default:
					t.Fatalf("AddUserToWorkspace(%s) error = %v", email, r.err)
				}
			}
			if ok != 1 || rejected != 1 {
				t.Fatalf("round %d: %d created, %d rejected; want 1 and 1", round, ok, rejected)
			}
		}
	})
}
