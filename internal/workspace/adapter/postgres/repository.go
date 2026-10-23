// Package postgres implements the workspace repository with sqlc queries.
// Every method runs inside the caller's scoped transaction.
package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/workspace/adapter/postgres/wsdb"
	"github.com/qali-project/qali/internal/workspace/app"
	"github.com/qali-project/qali/internal/workspace/domain"
)

// Repository implements app.Repository.
type Repository struct{}

var _ app.Repository = Repository{}

func q(tx db.Querier) *wsdb.Queries { return wsdb.New(tx) }

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	return db.MapError(err)
}

func member(userID uuid.UUID, role, status string, version int32, created time.Time) domain.Member {
	return domain.Member{UserID: userID, Role: authz.Role(role), Active: status == "active", Version: version, CreatedAt: created}
}

func status(active bool) string {
	if active {
		return "active"
	}
	return "deactivated"
}

func (Repository) UserWorkspaces(ctx context.Context, tx db.Querier, user, after uuid.UUID, limit int) ([]app.WorkspaceRow, error) {
	rows, err := q(tx).UserWorkspaces(ctx, wsdb.UserWorkspacesParams{UserID: user, After: after, RowLimit: int32(limit)}) //nolint:gosec // G115: limit is at most 201
	out := make([]app.WorkspaceRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, app.WorkspaceRow{ID: r.ID, Name: r.Name, Role: authz.Role(r.Role)})
	}
	return out, mapErr(err)
}

func (Repository) Workspace(ctx context.Context, tx db.Querier) (app.WorkspaceRow, error) {
	r, err := q(tx).Workspace(ctx)
	return app.WorkspaceRow{ID: r.ID, Name: r.Name}, mapErr(err)
}

func (Repository) Membership(ctx context.Context, tx db.Querier, user uuid.UUID) (domain.Member, error) {
	r, err := q(tx).Membership(ctx, user)
	if err != nil {
		return domain.Member{}, mapErr(err)
	}
	return member(r.UserID, r.Role, r.Status, r.Version, r.CreatedAt), nil
}

func (Repository) MembershipForUpdate(ctx context.Context, tx db.Querier, user uuid.UUID) (domain.Member, error) {
	r, err := q(tx).MembershipForUpdate(ctx, user)
	if err != nil {
		return domain.Member{}, mapErr(err)
	}
	return member(r.UserID, r.Role, r.Status, r.Version, r.CreatedAt), nil
}

func (Repository) Members(ctx context.Context, tx db.Querier, after uuid.UUID, limit int) ([]domain.Member, error) {
	rows, err := q(tx).Members(ctx, wsdb.MembersParams{After: after, RowLimit: int32(limit)}) //nolint:gosec // G115: limit is at most 201
	out := make([]domain.Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, member(r.UserID, r.Role, r.Status, r.Version, r.CreatedAt))
	}
	return out, mapErr(err)
}

func (Repository) LockActiveOwners(ctx context.Context, tx db.Querier) (int, error) {
	ids, err := q(tx).LockActiveOwners(ctx)
	return len(ids), mapErr(err)
}

func (Repository) UpdateMembership(ctx context.Context, tx db.Querier, m domain.Member, at time.Time) (domain.Member, error) {
	r, err := q(tx).UpdateMembership(ctx, wsdb.UpdateMembershipParams{
		Role: string(m.Role), Status: status(m.Active), At: at, UserID: m.UserID, Version: m.Version,
	})
	if err != nil {
		return domain.Member{}, mapErr(err)
	}
	return member(r.UserID, r.Role, r.Status, r.Version, r.CreatedAt), nil
}

func (Repository) InsertMembership(ctx context.Context, tx db.Querier, user uuid.UUID, role authz.Role, at time.Time) error {
	return mapErr(q(tx).InsertMembership(ctx, wsdb.InsertMembershipParams{UserID: user, Role: string(role), At: at}))
}

func (Repository) InvitationWorkspace(ctx context.Context, tx db.Querier, lookupID string) (uuid.UUID, error) {
	ws, err := q(tx).InvitationWorkspace(ctx, lookupID)
	return ws, mapErr(err)
}

func (Repository) InsertInvitation(ctx context.Context, tx db.Querier, inv app.Invitation) error {
	if err := q(tx).InsertInvitationLookup(ctx, inv.LookupID); err != nil {
		return mapErr(err)
	}
	return mapErr(q(tx).InsertInvitation(ctx, wsdb.InsertInvitationParams{
		ID: inv.ID, Email: inv.Email, Role: string(inv.Role), LookupID: inv.LookupID, Verifier: inv.Verifier,
		KeyVersion: int32(inv.KeyVersion), InvitedBy: inv.InvitedBy, //nolint:gosec // G115: key versions are small positive integers
		CreatedAt: inv.Window.CreatedAt, ExpiresAt: inv.Window.ExpiresAt,
	}))
}

func (Repository) RevokePendingInvitations(ctx context.Context, tx db.Querier, email string, at time.Time) error {
	return mapErr(q(tx).RevokePendingInvitations(ctx, wsdb.RevokePendingInvitationsParams{At: &at, Email: email}))
}

type invitationRow struct {
	ID         uuid.UUID
	Email      string
	Role       string
	LookupID   string
	Verifier   []byte
	KeyVersion int32
	InvitedBy  uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	RevokedAt  *time.Time
}

func invitation(r invitationRow) app.Invitation {
	return app.Invitation{
		ID: r.ID, Email: r.Email, Role: authz.Role(r.Role), LookupID: r.LookupID, Verifier: r.Verifier,
		KeyVersion: uint32(r.KeyVersion), InvitedBy: r.InvitedBy, //nolint:gosec // G115: CHECK (key_version > 0)
		Window: domain.InvitationWindow{CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, AcceptedAt: r.AcceptedAt, RevokedAt: r.RevokedAt},
	}
}

func (Repository) PendingInvitations(ctx context.Context, tx db.Querier, now time.Time, after uuid.UUID, limit int) ([]app.Invitation, error) {
	rows, err := q(tx).PendingInvitations(ctx, wsdb.PendingInvitationsParams{Now: now, After: after, RowLimit: int32(limit)}) //nolint:gosec // G115: limit is at most 201
	out := make([]app.Invitation, 0, len(rows))
	for _, r := range rows {
		out = append(out, invitation(invitationRow(r)))
	}
	return out, mapErr(err)
}

func (Repository) RevokeInvitation(ctx context.Context, tx db.Querier, id uuid.UUID, at time.Time) (bool, error) {
	n, err := q(tx).RevokeInvitation(ctx, wsdb.RevokeInvitationParams{At: &at, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) InvitationByLookup(ctx context.Context, tx db.Querier, lookupID string) (app.Invitation, error) {
	r, err := q(tx).InvitationByLookup(ctx, lookupID)
	if err != nil {
		return app.Invitation{}, mapErr(err)
	}
	return invitation(invitationRow(r)), nil
}

func (Repository) PeekInvitation(ctx context.Context, tx db.Querier, lookupID string) (app.Invitation, error) {
	r, err := q(tx).PeekInvitation(ctx, lookupID)
	if err != nil {
		return app.Invitation{}, mapErr(err)
	}
	return invitation(invitationRow(r)), nil
}

func (Repository) AcceptInvitation(ctx context.Context, tx db.Querier, id, user uuid.UUID, at time.Time) (bool, error) {
	n, err := q(tx).AcceptInvitation(ctx, wsdb.AcceptInvitationParams{At: &at, UserID: &user, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) InsertProject(ctx context.Context, tx db.Querier, p app.Project) error {
	return mapErr(q(tx).InsertProject(ctx, wsdb.InsertProjectParams{
		ID: p.ID, Code: p.Code, Name: p.Name, Visibility: string(p.Visibility), CreatedBy: p.CreatedBy, At: p.CreatedAt,
	}))
}

type projectRow struct {
	ID         uuid.UUID
	Code       string
	Name       string
	Visibility string
	CreatedBy  uuid.UUID
	CreatedAt  time.Time
	Version    int32
	Level      string
}

func project(r projectRow) app.Project {
	return app.Project{
		ID: r.ID, Code: r.Code, Name: r.Name, Visibility: authz.Visibility(r.Visibility), CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, Version: r.Version, MemberLevel: authz.AccessLevel(r.Level),
	}
}

func (Repository) Project(ctx context.Context, tx db.Querier, id, user uuid.UUID) (app.Project, error) {
	r, err := q(tx).Project(ctx, wsdb.ProjectParams{UserID: user, ID: id})
	if err != nil {
		return app.Project{}, mapErr(err)
	}
	return project(projectRow(r)), nil
}

func (Repository) VisibleProjects(ctx context.Context, tx db.Querier, user uuid.UUID, all bool, after uuid.UUID, limit int) ([]app.Project, error) {
	rows, err := q(tx).VisibleProjects(ctx, wsdb.VisibleProjectsParams{UserID: user, After: after, SeeAll: all, RowLimit: int32(limit)}) //nolint:gosec // G115: limit is at most 201
	out := make([]app.Project, 0, len(rows))
	for _, r := range rows {
		out = append(out, project(projectRow(r)))
	}
	return out, mapErr(err)
}

func (Repository) ProjectMembers(ctx context.Context, tx db.Querier, projectID, after uuid.UUID, limit int) ([]app.ProjectMember, error) {
	rows, err := q(tx).ProjectMembers(ctx, wsdb.ProjectMembersParams{ProjectID: projectID, After: after, RowLimit: int32(limit)}) //nolint:gosec // G115: limit is at most 201
	out := make([]app.ProjectMember, 0, len(rows))
	for _, r := range rows {
		out = append(out, app.ProjectMember{UserID: r.UserID, Level: authz.AccessLevel(r.Level), Version: r.Version})
	}
	return out, mapErr(err)
}

func (Repository) ProjectMemberForUpdate(ctx context.Context, tx db.Querier, projectID, user uuid.UUID) (app.ProjectMember, error) {
	r, err := q(tx).ProjectMemberForUpdate(ctx, wsdb.ProjectMemberForUpdateParams{ProjectID: projectID, UserID: user})
	if err != nil {
		return app.ProjectMember{}, mapErr(err)
	}
	return app.ProjectMember{UserID: r.UserID, Level: authz.AccessLevel(r.Level), Version: r.Version}, nil
}

func (Repository) InsertProjectMember(ctx context.Context, tx db.Querier, projectID uuid.UUID, m app.ProjectMember, at time.Time) error {
	return mapErr(q(tx).InsertProjectMember(ctx, wsdb.InsertProjectMemberParams{ProjectID: projectID, UserID: m.UserID, Level: string(m.Level), At: at}))
}

func (Repository) UpdateProjectMember(ctx context.Context, tx db.Querier, projectID uuid.UUID, m app.ProjectMember, at time.Time) (app.ProjectMember, error) {
	r, err := q(tx).UpdateProjectMember(ctx, wsdb.UpdateProjectMemberParams{
		Level: string(m.Level), At: at, ProjectID: projectID, UserID: m.UserID, Version: m.Version,
	})
	if err != nil {
		return app.ProjectMember{}, mapErr(err)
	}
	return app.ProjectMember{UserID: r.UserID, Level: authz.AccessLevel(r.Level), Version: r.Version}, nil
}

func (Repository) DeleteProjectMember(ctx context.Context, tx db.Querier, projectID uuid.UUID, m app.ProjectMember) error {
	n, err := q(tx).DeleteProjectMember(ctx, wsdb.DeleteProjectMemberParams{ProjectID: projectID, UserID: m.UserID, Version: m.Version})
	if err != nil {
		return mapErr(err)
	}
	if n != 1 {
		return db.ErrNotFound
	}
	return nil
}
