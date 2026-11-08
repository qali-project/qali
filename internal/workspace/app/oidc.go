package app

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	identity "github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
)

// RequireOIDCMember prevents a member operation from targeting another workspace.
func (s *Service) RequireOIDCMember(ctx context.Context, q db.Querier, user uuid.UUID) error {
	_, err := s.cfg.Repo.Membership(ctx, q, user)
	if errors.Is(err, db.ErrNotFound) {
		return identity.ErrNotFound
	}
	return err
}

// AuthorizeSecurity checks a security permission in the caller's scoped transaction.
func (s *Service) AuthorizeSecurity(ctx context.Context, q db.Querier, c identity.Current, permission authz.Permission) (bool, error) {
	p, err := s.require(ctx, q, CallerFrom(c), permission)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, identity.ErrNotFound
	case errors.Is(err, ErrForbidden):
		return false, identity.ErrForbidden
	case errors.Is(err, ErrRecentMFARequired):
		return false, identity.ErrRecentMFARequired
	default:
		return p.Role == authz.RoleOwner && p.Active, err
	}
}

// AcceptOIDCInvitation validates and locks the invitation before asking identity
// to create or resolve an account. The callback and membership commit atomically.
func (s *Service) AcceptOIDCInvitation(ctx context.Context, token secret.Value, email string, m identity.RequestMeta,
	finish func(context.Context, *db.WriteTx, bool) (uuid.UUID, identity.Grant, error)) (identity.Grant, error) {
	ws, lookup, err := s.invitationWorkspace(ctx, token, m)
	if err != nil {
		return identity.Grant{}, err
	}
	sc, err := db.WorkspaceScope(ws, audit.Actor{Type: audit.ActorSystem, ID: "invitation"}, info(m))
	if err != nil {
		return identity.Grant{}, err
	}
	var grant identity.Grant
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		inv, err := s.pendingInvitation(ctx, tx, lookup, token, true)
		if err != nil {
			return err
		}
		if inv.Email != email {
			return ErrInvitationInvalid
		}
		user, g, err := finish(ctx, tx, identity.RoleRequiresMFA(string(inv.Role)))
		if err != nil {
			return err
		}
		if err := s.accept(ctx, tx, inv, user); err != nil {
			return err
		}
		grant = g
		return nil
	})
	return grant, err
}
