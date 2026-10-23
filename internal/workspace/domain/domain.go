// Package domain holds the workspace rules of ADR-0013: ownership
// protection, invitation validity, and project attributes.
package domain

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
)

// Domain errors.
var (
	ErrInvalidInput = errors.New("workspace: invalid input")
	// ErrLastOwner protects the last active Owner from demotion and
	// deactivation.
	ErrLastOwner = errors.New("workspace: the last active owner cannot be demoted or deactivated")
	// ErrOwnerOnly means only an Owner may change an Owner or grant ownership.
	ErrOwnerOnly = errors.New("workspace: only an owner may change owners or grant ownership")
)

var roles = []authz.Role{authz.RoleOwner, authz.RoleWorkspaceAdmin, authz.RoleQALead, authz.RoleTester, authz.RoleViewer}

// ValidRole reports whether r is a fixed MVP role.
func ValidRole(r authz.Role) bool { return slices.Contains(roles, r) }

// Member is a workspace membership.
type Member struct {
	UserID    uuid.UUID
	Role      authz.Role
	Active    bool
	Version   int32
	CreatedAt time.Time
}

// MemberChange is a requested role and/or status change.
type MemberChange struct {
	Role   *authz.Role
	Active *bool
}

// Apply returns the member after the change.
func (m Member) Apply(c MemberChange) Member {
	if c.Role != nil {
		m.Role = *c.Role
	}
	if c.Active != nil {
		m.Active = *c.Active
	}
	return m
}

// CheckMemberChange applies the ownership rules. activeOwners is the number
// of active Owners in the workspace, read under lock by the caller.
// Permission checks (members.update_role, members.deactivate) happen before.
func CheckMemberChange(actor authz.Role, target Member, c MemberChange, activeOwners int) error {
	if c.Role == nil && c.Active == nil {
		return ErrInvalidInput
	}
	if c.Role != nil && !ValidRole(*c.Role) {
		return ErrInvalidInput
	}
	after := target.Apply(c)
	if (target.Role == authz.RoleOwner || after.Role == authz.RoleOwner) && after != target && actor != authz.RoleOwner {
		return ErrOwnerOnly
	}
	losesOwner := target.Role == authz.RoleOwner && target.Active && (after.Role != authz.RoleOwner || !after.Active)
	if losesOwner && activeOwners <= 1 {
		return ErrLastOwner
	}
	return nil
}

// InvitationLifetime is the validity of an invitation link (ADR-0006).
const InvitationLifetime = 7 * 24 * time.Hour

// InvitationWindow is the lifecycle state of an invitation.
type InvitationWindow struct {
	CreatedAt  time.Time
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
}

// NewInvitationWindow starts an invitation at now.
func NewInvitationWindow(now time.Time) InvitationWindow {
	return InvitationWindow{CreatedAt: now, ExpiresAt: now.Add(InvitationLifetime)}
}

// Pending reports whether the invitation can still be accepted at now.
func (w InvitationWindow) Pending(now time.Time) bool {
	return w.AcceptedAt == nil && w.RevokedAt == nil && now.Before(w.ExpiresAt)
}

// Invitable reports whether an invitation may grant r (never ownership).
func Invitable(r authz.Role) bool { return r != authz.RoleOwner && ValidRole(r) }

var projectCode = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)

// ValidProjectCode checks the ADR-0009 project code format.
func ValidProjectCode(code string) bool { return projectCode.MatchString(code) }

// CleanProjectName trims a project name and checks its length.
func CleanProjectName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 120 {
		return "", ErrInvalidInput
	}
	return name, nil
}

// ValidVisibility reports whether v is a project visibility.
func ValidVisibility(v authz.Visibility) bool { return v == authz.Public || v == authz.Restricted }

// ValidLevel reports whether l is a project access level.
func ValidLevel(l authz.AccessLevel) bool { return l == authz.Contributor || l == authz.Viewer }
