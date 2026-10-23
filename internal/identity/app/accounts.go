package app

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
)

// This file is the identity interface used by other modules (ADR-0013):
// accounts created by invitation acceptance, and display profiles.

// Input errors from the identity domain, for adapters of other modules.
var (
	ErrWeakPassword = domain.ErrWeakPassword
	ErrInvalidEmail = domain.ErrInvalidEmail
)

// ErrAccountExists means an account already uses the email.
var ErrAccountExists = errors.New("identity: an account with this email already exists")

// NormalizeEmail returns the canonical form of an email address.
func NormalizeEmail(raw string) (string, error) { return domain.NormalizeEmail(raw) }

// NewAccount is a validated, hashed account ready to insert.
type NewAccount struct {
	user User
}

// UserID is the ID the account will have.
func (a NewAccount) UserID() uuid.UUID { return a.user.ID }

// PrepareAccount validates and hashes outside any transaction, because
// password hashing is deliberately slow.
func (s *Service) PrepareAccount(rawEmail, displayName string, password secret.Value) (NewAccount, error) {
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		return NewAccount{}, err
	}
	pw := password.Expose()
	defer clear(pw)
	if err := domain.ValidatePassword(string(pw), email); err != nil {
		return NewAccount{}, err
	}
	name, err := cleanName(displayName, 200)
	if err != nil {
		return NewAccount{}, err
	}
	hash, err := s.cfg.Passwords.Hash(password)
	if err != nil {
		return NewAccount{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return NewAccount{}, err
	}
	return NewAccount{user: User{ID: id, Email: email, DisplayName: name, PasswordHash: hash, Active: true}}, nil
}

// CreateAccount inserts a prepared account inside the caller's audited
// transaction and signs it in. Accounts that must use MFA start in
// mfa_enrollment. The caller records the audit event of its use case.
func (s *Service) CreateAccount(ctx context.Context, tx *db.WriteTx, a NewAccount, requiresMFA bool, m RequestMeta) (Grant, error) {
	if a.user.ID == uuid.Nil {
		return Grant{}, ErrInvalidInput
	}
	if err := s.cfg.Repo.InsertUser(ctx, tx, a.user, s.now()); err != nil {
		if errors.Is(db.MapError(err), db.ErrConflict) {
			return Grant{}, ErrAccountExists
		}
		return Grant{}, err
	}
	return s.issueSession(ctx, tx, a.user, domain.StateAfterPassword(requiresMFA, false), "password", nil, m)
}

// Profile is what other modules may show about a user.
type Profile struct {
	Email       string
	DisplayName string
}

// Profiles returns display profiles for the given users; unknown IDs are
// omitted.
func (s *Service) Profiles(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]Profile, error) {
	out := make(map[uuid.UUID]Profile, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		users, err := s.cfg.Repo.UsersByIDs(ctx, q, ids)
		for _, u := range users {
			out[u.ID] = Profile{Email: u.Email, DisplayName: u.DisplayName}
		}
		return err
	})
	return out, err
}

// RoleRequiresMFA reports whether a workspace role must use MFA.
func RoleRequiresMFA(role string) bool { return domain.RoleRequiresMFA(role) }
