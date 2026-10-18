package org

// Tenant rules for the organization API (finding SEC-3).
//
// Global callers (authentication off, or an identity with neither a
// workspace nor an organization) see and manage everything, as before.
//
// Organization-scoped callers see their own organization, its workspaces,
// the members of those workspaces and the users who are members of them.
// They may create workspaces in their own organization only, and cannot
// create organizations.
//
// Workspace-scoped callers see their own workspace and read the
// organization that owns it. They cannot create organizations or
// workspaces, and manage only the members of their own workspace.
//
// Users are shared identities: one user may belong to workspaces of several
// tenants. A user is visible to a scoped caller when it is a member of at
// least one workspace the caller can see; a scoped caller lists only those
// users. It creates a user only together with a membership in a workspace
// it can see, and it never changes an existing user. When the email
// already exists and the user is visible, the stored user is added to the
// workspace with its name and metadata unchanged. When the user is not
// visible (a member only of other tenants' workspaces, or of none), nothing
// is written and the caller gets a 409 without any user data: only a
// global administrator can bring that user into the tenant. Likewise a
// membership change that names a user who is not visible gets the same 404
// as a missing user. Only global callers can rename users.
//
// A scoped caller cannot grant a membership role above its own role, and
// cannot change a membership that already holds a role above its own, in
// line with the API key rules in internal/admin.
//
// A workspace, user or organization outside the caller's tenant gets the
// same 404 as a missing one, so its existence is not confirmed.

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/omniswitch-dev/omniswitch/internal/gateway"
	"github.com/omniswitch-dev/omniswitch/internal/store"
)

// errUserOutsideTenant is the 409 message for a scoped caller that names
// the email of a user it cannot see. It carries no user data.
const errUserOutsideTenant = "a user with this email already exists; ask a global administrator to add the user to your workspace"

// tenantFilter returns the store filter for the caller of r.
func tenantFilter(r *http.Request) store.TenantFilter {
	scope := gateway.ScopeFromContext(r.Context())
	return store.TenantFilter{WorkspaceID: scope.WorkspaceID, OrganizationID: scope.OrganizationID}
}

// memberRole returns the stored role for a requested membership role.
func memberRole(role string) string {
	role = strings.TrimSpace(role)
	if role == "" {
		return "viewer"
	}
	return role
}

// callerRole returns the role of the authenticated caller of r.
func callerRole(r *http.Request) string {
	identity, _ := gateway.IdentityFromContext(r.Context())
	return identity.Role
}

// authorizeMembership checks that a scoped caller may create or change
// member: the workspace must be visible to the caller, the role may not
// exceed the caller's, and an existing membership with a higher role may
// not be changed. It writes the error response and returns false when the
// change is not allowed.
func (h *Handler) authorizeMembership(w http.ResponseWriter, r *http.Request, scope gateway.TenantScope, member store.WorkspaceMember) bool {
	workspace, err := h.store.GetWorkspaceByID(r.Context(), member.WorkspaceID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if err != nil || !scope.Allows(workspace.ID, workspace.OrganizationID) {
		// Same answer as a missing workspace, so workspaces of other
		// tenants are not confirmed.
		writeError(w, http.StatusNotFound, "workspace not found")
		return false
	}
	own := gateway.RoleRank(callerRole(r))
	if gateway.RoleRank(member.Role) > own {
		writeError(w, http.StatusForbidden, "cannot grant a role above your own")
		return false
	}
	if member.UserID == "" {
		return true
	}
	existing, err := h.store.GetWorkspaceMember(r.Context(), member.WorkspaceID, member.UserID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return true
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	case gateway.RoleRank(existing.Role) > own:
		writeError(w, http.StatusForbidden, "cannot change a member with a role above your own")
		return false
	}
	return true
}

// createScopedUser creates a user for a scoped caller, always together with
// a membership in a workspace that the caller can see.
func (h *Handler) createScopedUser(w http.ResponseWriter, r *http.Request, scope gateway.TenantScope, user store.User, workspaceID, role string) {
	if workspaceID == "" {
		workspaceID = scope.WorkspaceID
	}
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required: a user is created together with a membership in one of your workspaces")
		return
	}
	member := store.WorkspaceMember{WorkspaceID: workspaceID, Role: memberRole(role), CreatedAt: user.CreatedAt}
	// For an existing email, authorizeMembership also checks the user's
	// current membership in the workspace, so a lower-ranked caller cannot
	// demote a higher-ranked member through this endpoint.
	filter := tenantFilter(r)
	existing, err := h.store.GetUserByEmail(r.Context(), user.Email)
	switch {
	case err == nil:
		member.UserID = existing.ID
	case !errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !h.authorizeMembership(w, r, scope, member) {
		return
	}
	if member.UserID != "" {
		// Only a user the caller can already see may be added; the
		// check runs before any write and answers without user data.
		visible, err := h.store.UserVisibleToTenant(r.Context(), filter, member.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !visible {
			writeError(w, http.StatusConflict, errUserOutsideTenant)
			return
		}
	}
	// AddUserToWorkspace repeats the visibility check in its transaction,
	// for an email created concurrently by another tenant.
	stored, _, err := h.store.AddUserToWorkspace(r.Context(), filter, user, member)
	if errors.Is(err, store.ErrUserNotVisible) {
		writeError(w, http.StatusConflict, errUserOutsideTenant)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, stored)
}
