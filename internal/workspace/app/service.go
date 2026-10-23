package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	identity "github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/pagination"
	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/internal/workspace/domain"
)

// Config wires the service.
type Config struct {
	Store    *db.Store
	Repo     Repository
	Accounts Accounts
	Tokens   *crypto.Tokens
	Clock    clock.Clock
	NewID    func() (uuid.UUID, error)
}

// Service implements the workspace use cases.
type Service struct {
	cfg     Config
	cursors pagination.Codec
}

// New returns a service.
func New(cfg Config) *Service {
	return &Service{cfg: cfg, cursors: pagination.NewCodec(cfg.Tokens.Digest)}
}

// Caller is the authenticated human behind a request.
type Caller struct {
	UserID    uuid.UUID
	Email     string
	RecentMFA bool
}

// CallerFrom builds a caller from an identity session.
func CallerFrom(c identity.Current) Caller {
	return Caller{UserID: c.View.UserID, Email: c.View.Email, RecentMFA: c.RecentMFA}
}

// PageRequest is a validated page request.
type PageRequest struct {
	Limit  *int
	Cursor string
}

// Page is one page of results.
type Page[T any] struct {
	Items      []T
	NextCursor *string
}

func (s *Service) now() time.Time { return s.cfg.Clock.Now() }

func actor(id uuid.UUID) audit.Actor { return audit.Actor{Type: audit.ActorUser, ID: id.String()} }

func info(m identity.RequestMeta) db.RequestInfo {
	return db.RequestInfo{RequestID: m.RequestID, SourceIP: m.IP}
}

func (s *Service) scope(ws uuid.UUID, user uuid.UUID, m identity.RequestMeta) (db.Scope, error) {
	if ws == uuid.Nil {
		return db.Scope{}, ErrNotFound
	}
	return db.WorkspaceScope(ws, actor(user), info(m))
}

// page decodes a page request bound to the listing and the caller.
func (s *Service) page(binding string, p PageRequest) (uuid.UUID, int, error) {
	limit, err := pagination.Limit(p.Limit)
	if err != nil {
		return uuid.Nil, 0, err
	}
	after, err := s.cursors.Decode(binding, p.Cursor)
	return after, limit, err
}

// principal resolves the caller's membership in the scope's workspace.
// A missing membership is an inactive principal, which authz treats as
// "not found".
func (s *Service) principal(ctx context.Context, q db.Querier, c Caller) (authz.Principal, error) {
	m, err := s.cfg.Repo.Membership(ctx, q, c.UserID)
	if errors.Is(err, db.ErrNotFound) {
		return authz.Principal{UserID: c.UserID}, nil
	}
	if err != nil {
		return authz.Principal{}, err
	}
	return authz.Principal{UserID: c.UserID, Role: m.Role, Active: m.Active, RecentMFA: c.RecentMFA}, nil
}

func decision(d authz.Decision) error {
	switch d {
	case authz.Allow:
		return nil
	case authz.NotFound:
		return ErrNotFound
	case authz.RecentMFARequired:
		return ErrRecentMFARequired
	default:
		return ErrForbidden
	}
}

// require resolves the caller and checks a workspace-scoped permission.
func (s *Service) require(ctx context.Context, q db.Querier, c Caller, perm authz.Permission) (authz.Principal, error) {
	p, err := s.principal(ctx, q, c)
	if err != nil {
		return p, err
	}
	return p, decision(authz.Decide(p, perm, authz.Resource{}))
}

// held lists the permissions of the given scope the principal holds,
// ignoring the recent-MFA factor and grant conditions, for hiding controls.
func held(p authz.Principal, scope authz.Scope, project *authz.ProjectAccess) []string {
	p.RecentMFA = true
	out := []string{}
	for _, perm := range authz.Permissions() {
		if authz.Info(perm).Scope != scope {
			continue
		}
		if authz.Decide(p, perm, authz.Resource{Project: project, CreatedBy: p.UserID}) == authz.Allow {
			out = append(out, string(perm))
		}
	}
	return out
}

// Workspace is a workspace as the caller sees it.
type Workspace struct {
	ID          uuid.UUID
	Name        string
	Role        authz.Role
	Permissions []string
}

func workspaceView(w WorkspaceRow, userID uuid.UUID) Workspace {
	p := authz.Principal{UserID: userID, Role: w.Role, Active: true}
	return Workspace{ID: w.ID, Name: w.Name, Role: w.Role, Permissions: held(p, authz.WorkspaceScope, nil)}
}

// ListWorkspaces lists workspaces where the caller is an active member.
func (s *Service) ListWorkspaces(ctx context.Context, c Caller, pr PageRequest, m identity.RequestMeta) (Page[Workspace], error) {
	binding := "workspaces|" + c.UserID.String()
	after, limit, err := s.page(binding, pr)
	if err != nil {
		return Page[Workspace]{}, err
	}
	sc, err := db.SystemScope(actor(c.UserID), info(m))
	if err != nil {
		return Page[Workspace]{}, err
	}
	var rows []WorkspaceRow
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		rows, err = s.cfg.Repo.UserWorkspaces(ctx, q, c.UserID, after, limit+1)
		return err
	})
	if err != nil {
		return Page[Workspace]{}, err
	}
	rows, next := pagination.Page(s.cursors, binding, rows, limit, func(w WorkspaceRow) uuid.UUID { return w.ID })
	out := make([]Workspace, 0, len(rows))
	for _, w := range rows {
		out = append(out, workspaceView(w, c.UserID))
	}
	return Page[Workspace]{Items: out, NextCursor: next}, nil
}

// GetWorkspace returns one workspace with the caller's role.
func (s *Service) GetWorkspace(ctx context.Context, c Caller, ws uuid.UUID, m identity.RequestMeta) (Workspace, error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Workspace{}, err
	}
	var out Workspace
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		p, err := s.require(ctx, q, c, "workspace.read")
		if err != nil {
			return err
		}
		w, err := s.cfg.Repo.Workspace(ctx, q)
		if err != nil {
			return err
		}
		w.Role = p.Role
		out = workspaceView(w, c.UserID)
		return nil
	})
	return out, notFound(err)
}

// notFound maps a missing row to ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Member is a member with display data.
type Member struct {
	domain.Member
	Email       string
	DisplayName string
}

func (s *Service) withProfiles(ctx context.Context, ms []domain.Member) ([]Member, error) {
	ids := make([]uuid.UUID, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.UserID)
	}
	profiles, err := s.cfg.Accounts.Profiles(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		p := profiles[m.UserID]
		out = append(out, Member{Member: m, Email: p.Email, DisplayName: p.DisplayName})
	}
	return out, nil
}

// ListMembers lists workspace members (members.read).
func (s *Service) ListMembers(ctx context.Context, c Caller, ws uuid.UUID, pr PageRequest, m identity.RequestMeta) (Page[Member], error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Page[Member]{}, err
	}
	binding := "members|" + ws.String() + "|" + c.UserID.String()
	var rows []domain.Member
	var limit int
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		if _, err := s.require(ctx, q, c, "members.read"); err != nil {
			return err
		}
		after, l, err := s.page(binding, pr)
		if err != nil {
			return err
		}
		limit = l
		rows, err = s.cfg.Repo.Members(ctx, q, after, limit+1)
		return err
	})
	if err != nil {
		return Page[Member]{}, err
	}
	rows, next := pagination.Page(s.cursors, binding, rows, limit, func(m domain.Member) uuid.UUID { return m.UserID })
	items, err := s.withProfiles(ctx, rows)
	return Page[Member]{Items: items, NextCursor: next}, err
}

// UpdateMember changes a member's role and/or status. ifMatch is the
// version from If-Match (nil when missing).
func (s *Service) UpdateMember(ctx context.Context, c Caller, ws, target uuid.UUID, ch domain.MemberChange, ifMatch *int32, m identity.RequestMeta) (Member, error) {
	if ch.Role == nil && ch.Active == nil {
		return Member{}, domain.ErrInvalidInput
	}
	if ch.Role != nil && !domain.ValidRole(*ch.Role) {
		return Member{}, domain.ErrInvalidInput
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Member{}, err
	}
	var updated domain.Member
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		p, err := s.principal(ctx, tx, c)
		if err != nil {
			return err
		}
		// Every requested change needs its own permission.
		if ch.Role != nil {
			if err := decision(authz.Decide(p, "members.update_role", authz.Resource{})); err != nil {
				return err
			}
		}
		if ch.Active != nil {
			if err := decision(authz.Decide(p, "members.deactivate", authz.Resource{})); err != nil {
				return err
			}
		}
		owners, err := s.cfg.Repo.LockActiveOwners(ctx, tx)
		if err != nil {
			return err
		}
		current, err := s.cfg.Repo.MembershipForUpdate(ctx, tx, target)
		if err != nil {
			return notFound(err)
		}
		if ifMatch == nil {
			return ErrIfMatchRequired
		}
		if *ifMatch != current.Version {
			return ErrVersionMismatch
		}
		if err := domain.CheckMemberChange(p.Role, current, ch, owners); err != nil {
			if errors.Is(err, domain.ErrOwnerOnly) {
				return ErrForbidden
			}
			return err
		}
		next := current.Apply(ch)
		if updated, err = s.cfg.Repo.UpdateMembership(ctx, tx, next, s.now()); err != nil {
			return err
		}
		meta := map[string]any{}
		if current.Role != next.Role {
			meta["from_role"], meta["to_role"] = string(current.Role), string(next.Role)
		}
		if current.Active != next.Active {
			meta["active"] = next.Active
		}
		return tx.Audit(ctx, audit.Entry{Action: "member.update", TargetType: "user", TargetID: target.String(), Outcome: audit.Success, Metadata: meta})
	})
	if err != nil {
		return Member{}, err
	}
	items, err := s.withProfiles(ctx, []domain.Member{updated})
	if err != nil {
		return Member{}, err
	}
	return items[0], nil
}

// CreatedInvitation carries the one-time token.
type CreatedInvitation struct {
	Invitation Invitation
	Token      secret.Value
}

// CreateInvitation invites an email with a role (default tester). Inviting
// an administrative role also needs members.update_role and so recent MFA.
// Earlier pending invitations for the same email are revoked.
func (s *Service) CreateInvitation(ctx context.Context, c Caller, ws uuid.UUID, rawEmail string, role authz.Role, m identity.RequestMeta) (CreatedInvitation, error) {
	if role == "" {
		role = authz.RoleTester
	}
	if !domain.Invitable(role) {
		return CreatedInvitation{}, domain.ErrInvalidInput
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return CreatedInvitation{}, err
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return CreatedInvitation{}, err
	}
	raw, rec, err := s.cfg.Tokens.Issue(crypto.TokenInvitation)
	if err != nil {
		return CreatedInvitation{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return CreatedInvitation{}, err
	}
	now := s.now()
	inv := Invitation{
		ID: id, Email: email, Role: role, LookupID: rec.LookupID, Verifier: rec.Verifier, KeyVersion: rec.KeyVersion,
		InvitedBy: c.UserID, Window: domain.NewInvitationWindow(now),
	}
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		p, err := s.require(ctx, tx, c, "members.invite")
		if err != nil {
			return err
		}
		if role == authz.RoleWorkspaceAdmin {
			if err := decision(authz.Decide(p, "members.update_role", authz.Resource{})); err != nil {
				return err
			}
		}
		if err := s.cfg.Repo.RevokePendingInvitations(ctx, tx, email, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.InsertInvitation(ctx, tx, inv); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "invitation.create", TargetType: "invitation", TargetID: id.String(), Outcome: audit.Success,
			Metadata: map[string]any{"role": string(role)}})
	})
	if err != nil {
		return CreatedInvitation{}, err
	}
	return CreatedInvitation{Invitation: inv, Token: raw}, nil
}

// ListInvitations lists pending, unexpired invitations (members.invite).
func (s *Service) ListInvitations(ctx context.Context, c Caller, ws uuid.UUID, pr PageRequest, m identity.RequestMeta) (Page[Invitation], error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Page[Invitation]{}, err
	}
	binding := "invitations|" + ws.String() + "|" + c.UserID.String()
	var rows []Invitation
	var limit int
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		if _, err := s.require(ctx, q, c, "members.invite"); err != nil {
			return err
		}
		after, l, err := s.page(binding, pr)
		if err != nil {
			return err
		}
		limit = l
		rows, err = s.cfg.Repo.PendingInvitations(ctx, q, s.now(), after, limit+1)
		return err
	})
	if err != nil {
		return Page[Invitation]{}, err
	}
	rows, next := pagination.Page(s.cursors, binding, rows, limit, func(i Invitation) uuid.UUID { return i.ID })
	return Page[Invitation]{Items: rows, NextCursor: next}, nil
}

// RevokeInvitation revokes a pending invitation (members.invite).
func (s *Service) RevokeInvitation(ctx context.Context, c Caller, ws, id uuid.UUID, m identity.RequestMeta) error {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return err
	}
	return s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		if _, err := s.require(ctx, tx, c, "members.invite"); err != nil {
			return err
		}
		ok, err := s.cfg.Repo.RevokeInvitation(ctx, tx, id, s.now())
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		return tx.Audit(ctx, audit.Entry{Action: "invitation.revoke", TargetType: "invitation", TargetID: id.String(), Outcome: audit.Success})
	})
}

// InvitationPreview describes a valid invitation to its holder.
type InvitationPreview struct {
	WorkspaceName string
	Email         string
	Role          authz.Role
	ExpiresAt     time.Time
}

// invitationWorkspace finds the workspace of a token without revealing
// anything else. Every failure is ErrInvitationInvalid.
func (s *Service) invitationWorkspace(ctx context.Context, token secret.Value, m identity.RequestMeta) (uuid.UUID, string, error) {
	lookup, err := crypto.LookupID(crypto.TokenInvitation, token)
	if err != nil {
		return uuid.Nil, "", ErrInvitationInvalid
	}
	sc, err := db.SystemScope(audit.Actor{Type: audit.ActorSystem, ID: "invitation"}, info(m))
	if err != nil {
		return uuid.Nil, "", err
	}
	var ws uuid.UUID
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		ws, err = s.cfg.Repo.InvitationWorkspace(ctx, q, lookup)
		return err
	})
	if errors.Is(err, db.ErrNotFound) {
		return uuid.Nil, "", ErrInvitationInvalid
	}
	return ws, lookup, err
}

// pendingInvitation loads and verifies the invitation for token at now,
// locking it when the caller will consume it.
func (s *Service) pendingInvitation(ctx context.Context, q db.Querier, lookup string, token secret.Value, lock bool) (Invitation, error) {
	load := s.cfg.Repo.PeekInvitation
	if lock {
		load = s.cfg.Repo.InvitationByLookup
	}
	inv, err := load(ctx, q, lookup)
	if errors.Is(err, db.ErrNotFound) {
		return Invitation{}, ErrInvitationInvalid
	}
	if err != nil {
		return Invitation{}, err
	}
	if s.cfg.Tokens.Verify(crypto.TokenInvitation, token, crypto.TokenRecord{
		Type: crypto.TokenInvitation.Name, LookupID: inv.LookupID, Verifier: inv.Verifier, KeyVersion: inv.KeyVersion,
	}) != nil || !inv.Window.Pending(s.now()) {
		return Invitation{}, ErrInvitationInvalid
	}
	return inv, nil
}

// PreviewInvitation describes a pending invitation from its token.
func (s *Service) PreviewInvitation(ctx context.Context, token secret.Value, m identity.RequestMeta) (InvitationPreview, error) {
	ws, lookup, err := s.invitationWorkspace(ctx, token, m)
	if err != nil {
		return InvitationPreview{}, err
	}
	sc, err := db.WorkspaceScope(ws, audit.Actor{Type: audit.ActorSystem, ID: "invitation"}, info(m))
	if err != nil {
		return InvitationPreview{}, err
	}
	var out InvitationPreview
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		inv, err := s.pendingInvitation(ctx, q, lookup, token, false)
		if err != nil {
			return err
		}
		w, err := s.cfg.Repo.Workspace(ctx, q)
		if err != nil {
			return err
		}
		out = InvitationPreview{WorkspaceName: w.Name, Email: inv.Email, Role: inv.Role, ExpiresAt: inv.Window.ExpiresAt}
		return nil
	})
	return out, err
}

// accept consumes the invitation and creates the membership in tx.
func (s *Service) accept(ctx context.Context, tx *db.WriteTx, inv Invitation, user uuid.UUID) error {
	now := s.now()
	if ok, err := s.cfg.Repo.AcceptInvitation(ctx, tx, inv.ID, user, now); err != nil {
		return err
	} else if !ok {
		return ErrInvitationInvalid
	}
	if err := s.cfg.Repo.InsertMembership(ctx, tx, user, inv.Role, now); err != nil {
		if errors.Is(db.MapError(err), db.ErrConflict) {
			return ErrAlreadyMember
		}
		return err
	}
	return tx.Audit(ctx, audit.Entry{Action: "invitation.accept", TargetType: "invitation", TargetID: inv.ID.String(), Outcome: audit.Success,
		Metadata: map[string]any{"role": string(inv.Role)}})
}

// AcceptNewAccount creates an account for the invitation's email, adds the
// membership, and signs the new user in.
func (s *Service) AcceptNewAccount(ctx context.Context, token secret.Value, displayName string, password secret.Value, m identity.RequestMeta) (identity.Grant, error) {
	preview, err := s.PreviewInvitation(ctx, token, m)
	if err != nil {
		return identity.Grant{}, err
	}
	account, err := s.cfg.Accounts.PrepareAccount(preview.Email, displayName, password)
	if err != nil {
		return identity.Grant{}, err
	}
	ws, lookup, err := s.invitationWorkspace(ctx, token, m)
	if err != nil {
		return identity.Grant{}, err
	}
	sc, err := s.scope(ws, account.UserID(), m)
	if err != nil {
		return identity.Grant{}, err
	}
	var grant identity.Grant
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		inv, err := s.pendingInvitation(ctx, tx, lookup, token, true)
		if err != nil {
			return err
		}
		if grant, err = s.cfg.Accounts.CreateAccount(ctx, tx, account, identity.RoleRequiresMFA(string(inv.Role)), m); err != nil {
			return err
		}
		return s.accept(ctx, tx, inv, account.UserID())
	})
	return grant, err
}

// AcceptWithAccount adds the signed-in caller to the invitation's
// workspace. The session's email must match the invitation.
func (s *Service) AcceptWithAccount(ctx context.Context, c Caller, token secret.Value, m identity.RequestMeta) (Workspace, error) {
	ws, lookup, err := s.invitationWorkspace(ctx, token, m)
	if err != nil {
		return Workspace{}, err
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Workspace{}, err
	}
	var out Workspace
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		inv, err := s.pendingInvitation(ctx, tx, lookup, token, true)
		if err != nil {
			return err
		}
		if inv.Email != c.Email {
			return ErrInvitationInvalid
		}
		if err := s.accept(ctx, tx, inv, c.UserID); err != nil {
			return err
		}
		w, err := s.cfg.Repo.Workspace(ctx, tx)
		if err != nil {
			return err
		}
		w.Role = inv.Role
		out = workspaceView(w, c.UserID)
		return nil
	})
	return out, err
}

// ProjectView is a project with the caller's permissions on it.
type ProjectView struct {
	Project
	Permissions []string
}

func access(p Project) *authz.ProjectAccess {
	return &authz.ProjectAccess{Visibility: p.Visibility, MemberLevel: p.MemberLevel}
}

// NewProject is the input of CreateProject.
type NewProject struct {
	Code       string
	Name       string
	Visibility authz.Visibility
}

// CreateProject creates a project (projects.create). A non-Owner who
// creates a restricted project becomes its contributor, so the project does
// not vanish from their view.
func (s *Service) CreateProject(ctx context.Context, c Caller, ws uuid.UUID, in NewProject, m identity.RequestMeta) (ProjectView, error) {
	name, err := domain.CleanProjectName(in.Name)
	if err != nil {
		return ProjectView{}, err
	}
	if !domain.ValidProjectCode(in.Code) || !domain.ValidVisibility(in.Visibility) {
		return ProjectView{}, domain.ErrInvalidInput
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return ProjectView{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return ProjectView{}, err
	}
	now := s.now()
	proj := Project{ID: id, Code: in.Code, Name: name, Visibility: in.Visibility, CreatedBy: c.UserID, CreatedAt: now, Version: 1}
	var out ProjectView
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		p, err := s.require(ctx, tx, c, "projects.create")
		if err != nil {
			return err
		}
		if err := s.cfg.Repo.InsertProject(ctx, tx, proj); err != nil {
			if errors.Is(db.MapError(err), db.ErrConflict) {
				return ErrProjectCodeTaken
			}
			return err
		}
		if proj.Visibility == authz.Restricted && p.Role != authz.RoleOwner {
			if err := s.cfg.Repo.InsertProjectMember(ctx, tx, id, ProjectMember{UserID: c.UserID, Level: authz.Contributor}, now); err != nil {
				return err
			}
			proj.MemberLevel = authz.Contributor
		}
		out = ProjectView{Project: proj, Permissions: held(p, authz.ProjectScope, access(proj))}
		return tx.Audit(ctx, audit.Entry{Action: "project.create", TargetType: "project", TargetID: id.String(), Outcome: audit.Success,
			Metadata: map[string]any{"code": proj.Code, "visibility": string(proj.Visibility)}})
	})
	return out, err
}

// ListProjects lists projects visible to the caller.
func (s *Service) ListProjects(ctx context.Context, c Caller, ws uuid.UUID, pr PageRequest, m identity.RequestMeta) (Page[ProjectView], error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Page[ProjectView]{}, err
	}
	binding := "projects|" + ws.String() + "|" + c.UserID.String()
	var rows []Project
	var limit int
	var p authz.Principal
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		var err error
		if p, err = s.require(ctx, q, c, "workspace.read"); err != nil {
			return err
		}
		after, l, err := s.page(binding, pr)
		if err != nil {
			return err
		}
		limit = l
		rows, err = s.cfg.Repo.VisibleProjects(ctx, q, c.UserID, p.Role == authz.RoleOwner, after, limit+1)
		return err
	})
	if err != nil {
		return Page[ProjectView]{}, err
	}
	rows, next := pagination.Page(s.cursors, binding, rows, limit, func(p Project) uuid.UUID { return p.ID })
	out := make([]ProjectView, 0, len(rows))
	for _, proj := range rows {
		if authz.Decide(p, "projects.read", authz.Resource{Project: access(proj)}) != authz.Allow {
			continue
		}
		out = append(out, ProjectView{Project: proj, Permissions: held(p, authz.ProjectScope, access(proj))})
	}
	return Page[ProjectView]{Items: out, NextCursor: next}, nil
}

// project loads a project and checks perm on it.
func (s *Service) project(ctx context.Context, q db.Querier, c Caller, id uuid.UUID, perm authz.Permission) (authz.Principal, Project, error) {
	p, err := s.principal(ctx, q, c)
	if err != nil {
		return p, Project{}, err
	}
	if !p.Active {
		return p, Project{}, ErrNotFound
	}
	proj, err := s.cfg.Repo.Project(ctx, q, id, c.UserID)
	if err != nil {
		return p, Project{}, notFound(err)
	}
	return p, proj, decision(authz.Decide(p, perm, authz.Resource{Project: access(proj)}))
}

// GetProject returns a visible project (projects.read).
func (s *Service) GetProject(ctx context.Context, c Caller, ws, id uuid.UUID, m identity.RequestMeta) (ProjectView, error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return ProjectView{}, err
	}
	var out ProjectView
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		p, proj, err := s.project(ctx, q, c, id, "projects.read")
		if err != nil {
			return err
		}
		out = ProjectView{Project: proj, Permissions: held(p, authz.ProjectScope, access(proj))}
		return nil
	})
	return out, err
}

// ProjectMemberView is a direct member with display data.
type ProjectMemberView struct {
	ProjectMember
	Email       string
	DisplayName string
}

func (s *Service) projectMemberViews(ctx context.Context, ms []ProjectMember) ([]ProjectMemberView, error) {
	ids := make([]uuid.UUID, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.UserID)
	}
	profiles, err := s.cfg.Accounts.Profiles(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]ProjectMemberView, 0, len(ms))
	for _, m := range ms {
		p := profiles[m.UserID]
		out = append(out, ProjectMemberView{ProjectMember: m, Email: p.Email, DisplayName: p.DisplayName})
	}
	return out, nil
}

// ListProjectMembers lists direct members (projects.manage_access).
func (s *Service) ListProjectMembers(ctx context.Context, c Caller, ws, project uuid.UUID, pr PageRequest, m identity.RequestMeta) (Page[ProjectMemberView], error) {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return Page[ProjectMemberView]{}, err
	}
	binding := "project-members|" + project.String() + "|" + c.UserID.String()
	var rows []ProjectMember
	var limit int
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		if _, _, err := s.project(ctx, q, c, project, "projects.manage_access"); err != nil {
			return err
		}
		after, l, err := s.page(binding, pr)
		if err != nil {
			return err
		}
		limit = l
		rows, err = s.cfg.Repo.ProjectMembers(ctx, q, project, after, limit+1)
		return err
	})
	if err != nil {
		return Page[ProjectMemberView]{}, err
	}
	rows, next := pagination.Page(s.cursors, binding, rows, limit, func(m ProjectMember) uuid.UUID { return m.UserID })
	items, err := s.projectMemberViews(ctx, rows)
	return Page[ProjectMemberView]{Items: items, NextCursor: next}, err
}

// AddProjectMember adds an active workspace member to a project.
func (s *Service) AddProjectMember(ctx context.Context, c Caller, ws, project, user uuid.UUID, level authz.AccessLevel, m identity.RequestMeta) (ProjectMemberView, error) {
	if !domain.ValidLevel(level) {
		return ProjectMemberView{}, domain.ErrInvalidInput
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return ProjectMemberView{}, err
	}
	pm := ProjectMember{UserID: user, Level: level, Version: 1}
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		if _, _, err := s.project(ctx, tx, c, project, "projects.manage_access"); err != nil {
			return err
		}
		target, err := s.cfg.Repo.Membership(ctx, tx, user)
		if err != nil || !target.Active {
			return ErrNotFound
		}
		if err := s.cfg.Repo.InsertProjectMember(ctx, tx, project, pm, s.now()); err != nil {
			if errors.Is(db.MapError(err), db.ErrConflict) {
				return ErrAlreadyMember
			}
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "project.member_add", TargetType: "project", TargetID: project.String(), Outcome: audit.Success,
			Metadata: map[string]any{"user_id": user.String(), "level": string(level)}})
	})
	if err != nil {
		return ProjectMemberView{}, err
	}
	views, err := s.projectMemberViews(ctx, []ProjectMember{pm})
	if err != nil {
		return ProjectMemberView{}, err
	}
	return views[0], nil
}

// changeProjectMember loads a direct membership under lock and checks
// If-Match.
func (s *Service) changeProjectMember(ctx context.Context, tx *db.WriteTx, c Caller, project, user uuid.UUID, ifMatch *int32) (ProjectMember, error) {
	if _, _, err := s.project(ctx, tx, c, project, "projects.manage_access"); err != nil {
		return ProjectMember{}, err
	}
	current, err := s.cfg.Repo.ProjectMemberForUpdate(ctx, tx, project, user)
	if err != nil {
		return ProjectMember{}, notFound(err)
	}
	if ifMatch == nil {
		return ProjectMember{}, ErrIfMatchRequired
	}
	if *ifMatch != current.Version {
		return ProjectMember{}, ErrVersionMismatch
	}
	return current, nil
}

// UpdateProjectMember changes a direct member's level.
func (s *Service) UpdateProjectMember(ctx context.Context, c Caller, ws, project, user uuid.UUID, level authz.AccessLevel, ifMatch *int32, m identity.RequestMeta) (ProjectMemberView, error) {
	if !domain.ValidLevel(level) {
		return ProjectMemberView{}, domain.ErrInvalidInput
	}
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return ProjectMemberView{}, err
	}
	var updated ProjectMember
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		current, err := s.changeProjectMember(ctx, tx, c, project, user, ifMatch)
		if err != nil {
			return err
		}
		current.Level = level
		if updated, err = s.cfg.Repo.UpdateProjectMember(ctx, tx, project, current, s.now()); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "project.member_update", TargetType: "project", TargetID: project.String(), Outcome: audit.Success,
			Metadata: map[string]any{"user_id": user.String(), "level": string(level)}})
	})
	if err != nil {
		return ProjectMemberView{}, err
	}
	views, err := s.projectMemberViews(ctx, []ProjectMember{updated})
	if err != nil {
		return ProjectMemberView{}, err
	}
	return views[0], nil
}

// RemoveProjectMember removes a direct member.
func (s *Service) RemoveProjectMember(ctx context.Context, c Caller, ws, project, user uuid.UUID, ifMatch *int32, m identity.RequestMeta) error {
	sc, err := s.scope(ws, c.UserID, m)
	if err != nil {
		return err
	}
	return s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		current, err := s.changeProjectMember(ctx, tx, c, project, user, ifMatch)
		if err != nil {
			return err
		}
		if err := s.cfg.Repo.DeleteProjectMember(ctx, tx, project, current); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "project.member_remove", TargetType: "project", TargetID: project.String(), Outcome: audit.Success,
			Metadata: map[string]any{"user_id": user.String()}})
	})
}
