// Package authz decides whether a principal may perform an action
// (docs/RBAC.md section 1, ADR-0007, ADR-0013). It is pure: callers load
// memberships and resources and pass them in. Tables are generated from the
// reviewed permission catalog; everything not explicitly allowed is denied.
package authz

import (
	"slices"

	"github.com/google/uuid"
)

//go:generate go run ../../tools/permgen ../../docs/rbac/permission-catalog.json catalog_gen.go

// Permission is a catalog permission ID such as "repository.update".
type Permission string

// Role is a fixed MVP workspace role.
type Role string

const (
	RoleOwner          Role = "owner"
	RoleWorkspaceAdmin Role = "workspace_admin"
	RoleQALead         Role = "qa_lead"
	RoleTester         Role = "tester"
	RoleViewer         Role = "viewer"
)

// Kind separates reading from changing.
type Kind int

const (
	Read Kind = iota + 1
	Write
)

// Scope tells whether a permission needs a project.
type Scope int

const (
	WorkspaceScope Scope = iota + 1
	ProjectScope
)

// Condition narrows a grant to some resources.
type Condition int

const (
	All Condition = iota + 1
	Own
	Assigned
)

// PermissionInfo is the catalog metadata of a permission.
type PermissionInfo struct {
	Kind           Kind
	Scope          Scope
	Administrative bool
	Sensitive      bool
	OwnerOnly      bool
}

// AccessLevel is a direct project membership level.
type AccessLevel string

const (
	Contributor AccessLevel = "contributor"
	Viewer      AccessLevel = "viewer"
)

// Visibility of a project to workspace members.
type Visibility string

const (
	Public     Visibility = "public"
	Restricted Visibility = "restricted"
)

// Principal is an authenticated actor within one workspace.
type Principal struct {
	UserID uuid.UUID
	Role   Role
	// Active is false for deactivated or missing memberships.
	Active bool
	// RecentMFA reports strong authentication within the last 10 minutes.
	RecentMFA bool
	// Limit is the credential scope; nil means an unscoped human session.
	Limit map[Permission]bool
}

// ProjectAccess describes a project relative to the principal.
type ProjectAccess struct {
	Visibility Visibility
	// MemberLevel is the principal's direct membership level, or "".
	MemberLevel AccessLevel
}

// Resource is the target of a decision.
type Resource struct {
	// Project is required for project-scoped permissions.
	Project *ProjectAccess
	// CreatedBy is the creator, for the "own" condition.
	CreatedBy uuid.UUID
	// Assignee is the assigned user, or nil when unassigned ("assigned").
	Assignee *uuid.UUID
}

// Decision is the result of Decide.
type Decision int

const (
	// Allow permits the action.
	Allow Decision = iota + 1
	// NotFound means the principal may not know the target exists (404).
	NotFound
	// Forbidden means the target is visible but the action is denied (403).
	Forbidden
	// RecentMFARequired asks for step-up authentication first.
	RecentMFARequired
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NotFound:
		return "not_found"
	case Forbidden:
		return "forbidden"
	case RecentMFARequired:
		return "recent_mfa_required"
	default:
		return "invalid"
	}
}

// Permissions lists every catalog permission in catalog order.
func Permissions() []Permission { return slices.Clone(permissionOrder) }

// Info returns a permission's metadata; unknown permissions return the zero
// value.
func Info(p Permission) PermissionInfo { return permissionTable[p] }

// projectLevel returns the effective level on a project, or false if the
// project is invisible to the principal (ADR-0007: Owners see every
// project at full level; restricted projects need direct membership;
// public projects imply contributor).
func projectLevel(p Principal, pa ProjectAccess) (AccessLevel, bool) {
	if !p.Active {
		return "", false
	}
	if p.Role == RoleOwner {
		// Owners are never narrowed by a membership level (ADR-0013).
		return Contributor, true
	}
	if pa.MemberLevel != "" {
		return pa.MemberLevel, true
	}
	if pa.Visibility == Public {
		return Contributor, true
	}
	return "", false
}

// CanSeeProject reports whether the project exists for the principal.
func CanSeeProject(p Principal, pa ProjectAccess) bool {
	_, ok := projectLevel(p, pa)
	return ok
}

// Decide intersects membership, project visibility and level, role grant,
// condition, credential scope, and recent MFA. The first failing factor
// decides; invisibility always wins so existence is not revealed.
func Decide(p Principal, perm Permission, r Resource) Decision {
	if !p.Active {
		return NotFound
	}
	info, known := permissionTable[perm]
	if !known {
		return Forbidden
	}
	if info.Scope == ProjectScope {
		if r.Project == nil {
			return Forbidden
		}
		level, visible := projectLevel(p, *r.Project)
		if !visible {
			return NotFound
		}
		if maxKind, ok := accessLevelTable[level]; !ok || info.Kind > maxKind {
			return Forbidden
		}
	}
	condition, granted := grantTable[p.Role][perm]
	if !granted {
		return Forbidden
	}
	switch condition {
	case Own:
		if r.CreatedBy != p.UserID {
			return Forbidden
		}
	case Assigned:
		if r.Assignee != nil && *r.Assignee != p.UserID {
			return Forbidden
		}
	}
	if p.Limit != nil && !p.Limit[perm] {
		return Forbidden
	}
	if info.Sensitive && !p.RecentMFA {
		return RecentMFARequired
	}
	return Allow
}
