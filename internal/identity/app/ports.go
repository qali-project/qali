// Package app holds the identity use cases: bootstrap, login, MFA, sessions,
// and recovery (ADR-0012). Transactions and audit come from
// internal/platform/db; persistence goes through the Repository port.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
)

// User is a stored identity.
type User struct {
	ID              uuid.UUID
	Email           string
	DisplayName     string
	PasswordHash    string
	Active          bool
	TOTP            *crypto.Sealed
	TOTPDEKID       string
	TOTPConfirmedAt *time.Time
	TOTPLastStep    int64
}

// SessionRecord is a stored session; the raw token and CSRF token are not.
type SessionRecord struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	LookupID      string
	Verifier      []byte
	KeyVersion    uint32
	CSRFVerifier  []byte
	AuthMethod    string
	Lifetime      domain.Session
	MFAVerifiedAt *time.Time
	SourceIP      netip.Addr
}

// RecoveryRecord is a stored recovery code.
type RecoveryRecord struct {
	ID     uuid.UUID
	Lookup string
	Hash   string
}

// PasswordReset is a stored operator-issued reset token.
type PasswordReset struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	LookupID   string
	Verifier   []byte
	KeyVersion uint32
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
}

// SetupToken is a stored operator-issued bootstrap token.
type SetupToken struct {
	ID         uuid.UUID
	LookupID   string
	Verifier   []byte
	KeyVersion uint32
	IssuedBy   string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
}

// Repository persists identity data inside the caller's scoped
// transaction. Missing rows return db.ErrNotFound.
type Repository interface {
	InstallationExists(ctx context.Context, q db.Querier) (bool, error)
	InsertInstallation(ctx context.Context, q db.Querier, owner uuid.UUID, at time.Time) error
	InsertUser(ctx context.Context, q db.Querier, u User, at time.Time) error
	UserByEmail(ctx context.Context, q db.Querier, email string) (User, error)
	UserByID(ctx context.Context, q db.Querier, id uuid.UUID) (User, error)
	UsersByIDs(ctx context.Context, q db.Querier, ids []uuid.UUID) ([]User, error)
	SetPassword(ctx context.Context, q db.Querier, id uuid.UUID, hash string, at time.Time) error
	SetTOTPSecret(ctx context.Context, q db.Querier, id uuid.UUID, dekID string, s crypto.Sealed, at time.Time) error
	ConfirmTOTP(ctx context.Context, q db.Querier, id uuid.UUID, step int64, at time.Time) (bool, error)
	AdvanceTOTPStep(ctx context.Context, q db.Querier, id uuid.UUID, step int64) (bool, error)
	InsertWorkspace(ctx context.Context, q db.Querier, id uuid.UUID, name string, at time.Time) error
	InsertMember(ctx context.Context, q db.Querier, workspace, user uuid.UUID, role string, at time.Time) error
	ActiveRoles(ctx context.Context, q db.Querier, user uuid.UUID) ([]string, error)
	InsertSession(ctx context.Context, q db.Querier, s SessionRecord) error
	SessionByLookup(ctx context.Context, q db.Querier, lookupID string) (SessionRecord, error)
	TouchSession(ctx context.Context, q db.Querier, id uuid.UUID, lastSeen, idleExpires time.Time) error
	RevokeSession(ctx context.Context, q db.Querier, id uuid.UUID, reason domain.RevokeReason, at time.Time) error
	RevokeUserSessions(ctx context.Context, q db.Querier, user uuid.UUID, reason domain.RevokeReason, at time.Time) error
	ReplaceRecoveryCodes(ctx context.Context, q db.Querier, user uuid.UUID, codes []RecoveryRecord, at time.Time) error
	LiveRecoveryCode(ctx context.Context, q db.Querier, user uuid.UUID, lookup string) (RecoveryRecord, error)
	UseRecoveryCode(ctx context.Context, q db.Querier, id uuid.UUID, at time.Time) (bool, error)
	InsertSetupToken(ctx context.Context, q db.Querier, t SetupToken) error
	SetupTokenByLookup(ctx context.Context, q db.Querier, lookupID string) (SetupToken, error)
	UseSetupToken(ctx context.Context, q db.Querier, id uuid.UUID, at time.Time) (bool, error)
	InsertPasswordReset(ctx context.Context, q db.Querier, r PasswordReset) error
	PasswordResetByLookup(ctx context.Context, q db.Querier, lookupID string) (PasswordReset, error)
	UsePasswordReset(ctx context.Context, q db.Querier, id uuid.UUID, at time.Time) (bool, error)
	// Throttle reads a throttle without locking (zero value if absent).
	Throttle(ctx context.Context, q db.Querier, key []byte) (domain.Throttle, error)
	// LockThrottle creates the row if needed and locks it for update.
	LockThrottle(ctx context.Context, q db.Querier, key []byte, kind string, at time.Time) (domain.Throttle, error)
	SaveThrottle(ctx context.Context, q db.Querier, key []byte, t domain.Throttle, at time.Time) error
	DEK(ctx context.Context, q db.Querier, scope string) (crypto.WrappedDEK, error)
	InsertDEK(ctx context.Context, q db.Querier, scope string, dek crypto.WrappedDEK, at time.Time) error
}

// Errors returned to adapters. Messages never reveal whether an account
// exists.
var (
	ErrAlreadyBootstrapped  = errors.New("identity: already bootstrapped")
	ErrInvalidCredentials   = errors.New("identity: invalid credentials")
	ErrInvalidCode          = errors.New("identity: invalid code")
	ErrInvalidToken         = errors.New("identity: invalid or expired token")
	ErrUnauthenticated      = errors.New("identity: not authenticated")
	ErrAlreadyEnrolled      = errors.New("identity: TOTP is already enabled")
	ErrEnrollmentNotStarted = errors.New("identity: TOTP enrollment was not started")
	ErrInvalidInput         = errors.New("identity: invalid input")
	ErrUnknownAccount       = errors.New("identity: unknown account")
	ErrInvalidSetupToken    = errors.New("identity: invalid or expired setup token")
)

// ThrottledError asks the client to wait before retrying.
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("identity: too many attempts; retry after %s", e.RetryAfter)
}
