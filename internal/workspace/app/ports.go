// Package app holds the workspace use cases of ADR-0013: workspaces,
// members, invitations, and projects as access objects. Every use case
// resolves the caller's membership from the database and asks authz.Decide;
// nothing is cached between requests.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	identity "github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/internal/workspace/domain"
)

// WorkspaceRow is a workspace with the caller's role.
type WorkspaceRow struct {
	ID   uuid.UUID
	Name string
	Role authz.Role
}

// Invitation is a stored invitation; the raw token is never stored.
type Invitation struct {
	ID         uuid.UUID
	Email      string
	Role       authz.Role
	LookupID   string
	Verifier   []byte
	KeyVersion uint32
	InvitedBy  uuid.UUID
	Window     domain.InvitationWindow
}

// Project is a project with the caller's direct membership level ("" if
// none).
type Project struct {
	ID          uuid.UUID
	Code        string
	Name        string
	Visibility  authz.Visibility
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
	Version     int32
	MemberLevel authz.AccessLevel
}

// ProjectMember is a direct project membership.
type ProjectMember struct {
	UserID  uuid.UUID
	Level   authz.AccessLevel
	Version int32
}

// Repository persists workspace data inside the caller's scoped
// transaction; row-level security confines it to the scope's workspace.
// Missing rows return db.ErrNotFound; unique violations db.ErrConflict.
type Repository interface {
	UserWorkspaces(ctx context.Context, q db.Querier, user, after uuid.UUID, limit int) ([]WorkspaceRow, error)
	Workspace(ctx context.Context, q db.Querier) (WorkspaceRow, error)
	Membership(ctx context.Context, q db.Querier, user uuid.UUID) (domain.Member, error)
	MembershipForUpdate(ctx context.Context, q db.Querier, user uuid.UUID) (domain.Member, error)
	Members(ctx context.Context, q db.Querier, after uuid.UUID, limit int) ([]domain.Member, error)
	// LockActiveOwners locks and counts active Owners.
	LockActiveOwners(ctx context.Context, q db.Querier) (int, error)
	// UpdateMembership applies m if its stored version is m.Version and
	// returns the new row; a version mismatch is db.ErrNotFound.
	UpdateMembership(ctx context.Context, q db.Querier, m domain.Member, at time.Time) (domain.Member, error)
	InsertMembership(ctx context.Context, q db.Querier, user uuid.UUID, role authz.Role, at time.Time) error

	InvitationWorkspace(ctx context.Context, q db.Querier, lookupID string) (uuid.UUID, error)
	InsertInvitation(ctx context.Context, q db.Querier, inv Invitation) error
	RevokePendingInvitations(ctx context.Context, q db.Querier, email string, at time.Time) error
	PendingInvitations(ctx context.Context, q db.Querier, now time.Time, after uuid.UUID, limit int) ([]Invitation, error)
	RevokeInvitation(ctx context.Context, q db.Querier, id uuid.UUID, at time.Time) (bool, error)
	// InvitationByLookup locks the row; PeekInvitation reads without a lock.
	InvitationByLookup(ctx context.Context, q db.Querier, lookupID string) (Invitation, error)
	PeekInvitation(ctx context.Context, q db.Querier, lookupID string) (Invitation, error)
	AcceptInvitation(ctx context.Context, q db.Querier, id, user uuid.UUID, at time.Time) (bool, error)

	InsertProject(ctx context.Context, q db.Querier, p Project) error
	Project(ctx context.Context, q db.Querier, id, user uuid.UUID) (Project, error)
	VisibleProjects(ctx context.Context, q db.Querier, user uuid.UUID, all bool, after uuid.UUID, limit int) ([]Project, error)
	ProjectMembers(ctx context.Context, q db.Querier, project, after uuid.UUID, limit int) ([]ProjectMember, error)
	ProjectMemberForUpdate(ctx context.Context, q db.Querier, project, user uuid.UUID) (ProjectMember, error)
	InsertProjectMember(ctx context.Context, q db.Querier, project uuid.UUID, m ProjectMember, at time.Time) error
	// UpdateProjectMember and DeleteProjectMember check m.Version; a
	// mismatch is db.ErrNotFound.
	UpdateProjectMember(ctx context.Context, q db.Querier, project uuid.UUID, m ProjectMember, at time.Time) (ProjectMember, error)
	DeleteProjectMember(ctx context.Context, q db.Querier, project uuid.UUID, m ProjectMember) error
}

// Accounts is the identity module's interface for invitation acceptance
// and display profiles (implemented by identity/app.Service).
type Accounts interface {
	PrepareAccount(email, displayName string, password secret.Value) (identity.NewAccount, error)
	CreateAccount(ctx context.Context, tx *db.WriteTx, a identity.NewAccount, requiresMFA bool, m identity.RequestMeta) (identity.Grant, error)
	Profiles(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]identity.Profile, error)
}

// Errors returned to adapters.
var (
	ErrNotFound          = errors.New("workspace: not found")
	ErrForbidden         = errors.New("workspace: forbidden")
	ErrRecentMFARequired = errors.New("workspace: recent MFA required")
	ErrInvitationInvalid = errors.New("workspace: invitation is invalid")
	ErrAlreadyMember     = errors.New("workspace: already a member")
	ErrProjectCodeTaken  = errors.New("workspace: project code already used")
	ErrIfMatchRequired   = errors.New("workspace: If-Match required")
	ErrVersionMismatch   = errors.New("workspace: version mismatch")
)
