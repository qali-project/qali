package app

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
)

type LoginPolicy struct {
	WorkspaceID uuid.UUID
	LocalLogin  bool
	Version     int32
}

type OIDCProvider struct {
	ID                              uuid.UUID
	Issuer, ClientID, Label, Status string
	Secret                          crypto.Sealed
	VerifiedAt                      *time.Time
	VerifiedBy                      *uuid.UUID
	CreatedAt, UpdatedAt            time.Time
	Version                         int32
}

type OIDCFlow struct {
	ID                                            uuid.UUID
	LookupID                                      string
	StateVerifier, NonceVerifier, BindingVerifier []byte
	KeyVersion                                    int32
	ProviderID                                    uuid.UUID
	Purpose                                       string
	UserID                                        *uuid.UUID
	Sealed                                        crypto.Sealed
	CreatedAt, ExpiresAt                          time.Time
}

type OIDCIdentity struct {
	ID, UserID              uuid.UUID
	Issuer, Subject, Method string
	LinkedAt                time.Time
	LastLoginAt             *time.Time
}

type OIDCRepository interface {
	LoginPolicy(context.Context, db.Querier, bool) (LoginPolicy, error)
	SaveLoginPolicy(context.Context, db.Querier, bool) error
	OIDCProvider(context.Context, db.Querier) (OIDCProvider, error)
	SaveOIDCProvider(context.Context, db.Querier, OIDCProvider) error
	RemoveOIDCProvider(context.Context, db.Querier) error
	InsertOIDCFlow(context.Context, db.Querier, OIDCFlow) error
	ConsumeOIDCFlow(context.Context, db.Querier, string, []byte, []byte, time.Time) (OIDCFlow, error)
	OIDCIdentity(context.Context, db.Querier, string, string) (OIDCIdentity, error)
	OwnOIDCIdentity(context.Context, db.Querier, uuid.UUID, string) (OIDCIdentity, error)
	InsertOIDCIdentity(context.Context, db.Querier, OIDCIdentity) error
	TouchOIDCIdentity(context.Context, db.Querier, uuid.UUID, time.Time) error
	RemoveOIDCIdentity(context.Context, db.Querier, uuid.UUID) error
	CleanupOIDCFlows(context.Context, db.Querier, time.Time) (int64, error)
	HasPasswordlessOIDCUsers(context.Context, db.Querier) (bool, error)
}

// SecurityAuthorizer resolves workspace membership in the caller's transaction.
// The boolean reports active Owner membership for the break-glass policy.
type SecurityAuthorizer func(context.Context, db.Querier, Current, authz.Permission) (bool, error)

var (
	ErrForbidden          = errors.New("identity: forbidden")
	ErrNotFound           = errors.New("identity: not found")
	ErrRecentMFARequired  = errors.New("identity: recent MFA required")
	ErrIfMatchRequired    = errors.New("identity: If-Match required")
	ErrVersionMismatch    = errors.New("identity: version mismatch")
	ErrOIDCUnavailable    = errors.New("identity: provider unavailable")
	ErrNoAlternativeLogin = errors.New("identity: no alternative sign-in method")
)
