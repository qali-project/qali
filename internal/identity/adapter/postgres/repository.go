// Package postgres implements the identity repository with sqlc queries.
// Every method runs inside the caller's scoped transaction.
package postgres

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qali-project/qali/internal/identity/adapter/postgres/iddb"
	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
)

// Repository implements app.Repository.
type Repository struct{}

var _ app.Repository = Repository{}

func q(tx db.Querier) *iddb.Queries { return iddb.New(tx) }

func ptr[T any](v T) *T { return &v }

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	return db.MapError(err)
}

func (Repository) InstallationExists(ctx context.Context, tx db.Querier) (bool, error) {
	ok, err := q(tx).InstallationExists(ctx)
	return ok, mapErr(err)
}

func (Repository) InsertInstallation(ctx context.Context, tx db.Querier, owner uuid.UUID, at time.Time) error {
	return mapErr(q(tx).InsertInstallation(ctx, iddb.InsertInstallationParams{OwnerUserID: owner, At: at}))
}

func (Repository) InsertUser(ctx context.Context, tx db.Querier, u app.User, at time.Time) error {
	return mapErr(q(tx).InsertUser(ctx, iddb.InsertUserParams{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, PasswordHash: ptr(u.PasswordHash), At: &at,
	}))
}

type userRow struct {
	ID              uuid.UUID
	Email           string
	DisplayName     string
	PasswordHash    *string
	Status          string
	TotpAlgorithm   *string
	TotpDekID       *string
	TotpNonce       []byte
	TotpCiphertext  []byte
	TotpConfirmedAt *time.Time
	TotpLastStep    *int64
}

func toUser(r userRow) app.User {
	u := app.User{ID: r.ID, Email: r.Email, DisplayName: r.DisplayName, Active: r.Status == "active", TOTPConfirmedAt: r.TotpConfirmedAt}
	if r.PasswordHash != nil {
		u.PasswordHash = *r.PasswordHash
	}
	if r.TotpCiphertext != nil && r.TotpAlgorithm != nil && r.TotpDekID != nil {
		u.TOTP = &crypto.Sealed{Algorithm: *r.TotpAlgorithm, DEKID: *r.TotpDekID, Nonce: r.TotpNonce, Ciphertext: r.TotpCiphertext}
		u.TOTPDEKID = *r.TotpDekID
	}
	if r.TotpLastStep != nil {
		u.TOTPLastStep = *r.TotpLastStep
	}
	return u
}

func (Repository) UserByEmail(ctx context.Context, tx db.Querier, email string) (app.User, error) {
	r, err := q(tx).UserByEmail(ctx, email)
	if err != nil {
		return app.User{}, mapErr(err)
	}
	return toUser(userRow(r)), nil
}

func (Repository) UserByID(ctx context.Context, tx db.Querier, id uuid.UUID) (app.User, error) {
	r, err := q(tx).UserByID(ctx, id)
	if err != nil {
		return app.User{}, mapErr(err)
	}
	return toUser(userRow(r)), nil
}

func (Repository) UsersByIDs(ctx context.Context, tx db.Querier, ids []uuid.UUID) ([]app.User, error) {
	rows, err := q(tx).UsersByIDs(ctx, ids)
	out := make([]app.User, 0, len(rows))
	for _, r := range rows {
		out = append(out, app.User{ID: r.ID, Email: r.Email, DisplayName: r.DisplayName})
	}
	return out, mapErr(err)
}

func (Repository) SetPassword(ctx context.Context, tx db.Querier, id uuid.UUID, hash string, at time.Time) error {
	return mapErr(q(tx).SetPassword(ctx, iddb.SetPasswordParams{PasswordHash: &hash, At: &at, ID: id}))
}

func (Repository) SetTOTPSecret(ctx context.Context, tx db.Querier, id uuid.UUID, dekID string, s crypto.Sealed, at time.Time) error {
	return mapErr(q(tx).SetTOTPSecret(ctx, iddb.SetTOTPSecretParams{
		Algorithm: &s.Algorithm, DekID: &dekID, Nonce: s.Nonce, Ciphertext: s.Ciphertext, At: at, ID: id,
	}))
}

func (Repository) ConfirmTOTP(ctx context.Context, tx db.Querier, id uuid.UUID, step int64, at time.Time) (bool, error) {
	n, err := q(tx).ConfirmTOTP(ctx, iddb.ConfirmTOTPParams{At: &at, Step: &step, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) AdvanceTOTPStep(ctx context.Context, tx db.Querier, id uuid.UUID, step int64) (bool, error) {
	n, err := q(tx).AdvanceTOTPStep(ctx, iddb.AdvanceTOTPStepParams{Step: &step, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) InsertWorkspace(ctx context.Context, tx db.Querier, id uuid.UUID, name string, at time.Time) error {
	return mapErr(q(tx).InsertWorkspace(ctx, iddb.InsertWorkspaceParams{ID: id, Name: name, At: at}))
}

func (Repository) InsertMember(ctx context.Context, tx db.Querier, workspace, user uuid.UUID, role string, at time.Time) error {
	return mapErr(q(tx).InsertMember(ctx, iddb.InsertMemberParams{WorkspaceID: workspace, UserID: user, Role: role, At: at}))
}

func (Repository) ActiveRoles(ctx context.Context, tx db.Querier, user uuid.UUID) ([]string, error) {
	roles, err := q(tx).ActiveRoles(ctx, user)
	return roles, mapErr(err)
}

func (Repository) InsertSession(ctx context.Context, tx db.Querier, s app.SessionRecord) error {
	var ip *netip.Addr
	if s.SourceIP.IsValid() {
		ip = &s.SourceIP
	}
	return mapErr(q(tx).InsertSession(ctx, iddb.InsertSessionParams{
		ID: s.ID, UserID: s.UserID, LookupID: s.LookupID, Verifier: s.Verifier, KeyVersion: int32(s.KeyVersion), //nolint:gosec // G115: key versions are small
		CsrfVerifier: s.CSRFVerifier, State: string(s.Lifetime.State), AuthMethod: s.AuthMethod,
		CreatedAt: s.Lifetime.CreatedAt, IdleExpiresAt: s.Lifetime.IdleExpiresAt, ExpiresAt: s.Lifetime.ExpiresAt,
		MfaVerifiedAt: s.MFAVerifiedAt, SourceIp: ip,
	}))
}

func (Repository) SessionByLookup(ctx context.Context, tx db.Querier, lookupID string) (app.SessionRecord, error) {
	r, err := q(tx).SessionByLookup(ctx, lookupID)
	if err != nil {
		return app.SessionRecord{}, mapErr(err)
	}
	rec := app.SessionRecord{
		ID: r.ID, UserID: r.UserID, LookupID: r.LookupID, Verifier: r.Verifier, KeyVersion: uint32(r.KeyVersion), //nolint:gosec // G115: checked positive by the schema
		CSRFVerifier: r.CsrfVerifier, AuthMethod: r.AuthMethod, MFAVerifiedAt: r.MfaVerifiedAt,
		Lifetime: domain.Session{
			State: domain.SessionState(r.State), CreatedAt: r.CreatedAt, LastSeenAt: r.LastSeenAt,
			IdleExpiresAt: r.IdleExpiresAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
		},
	}
	if r.RevokeReason != nil {
		rec.Lifetime.RevokeReason = domain.RevokeReason(*r.RevokeReason)
	}
	return rec, nil
}

func (Repository) TouchSession(ctx context.Context, tx db.Querier, id uuid.UUID, lastSeen, idleExpires time.Time) error {
	return mapErr(q(tx).TouchSession(ctx, iddb.TouchSessionParams{LastSeenAt: lastSeen, IdleExpiresAt: idleExpires, ID: id}))
}

func (Repository) RevokeSession(ctx context.Context, tx db.Querier, id uuid.UUID, reason domain.RevokeReason, at time.Time) error {
	return mapErr(q(tx).RevokeSession(ctx, iddb.RevokeSessionParams{At: &at, Reason: ptr(string(reason)), ID: id}))
}

func (Repository) RevokeUserSessions(ctx context.Context, tx db.Querier, user uuid.UUID, reason domain.RevokeReason, at time.Time) error {
	_, err := q(tx).RevokeUserSessions(ctx, iddb.RevokeUserSessionsParams{At: &at, Reason: ptr(string(reason)), UserID: user})
	return mapErr(err)
}

func (Repository) ReplaceRecoveryCodes(ctx context.Context, tx db.Querier, user uuid.UUID, codes []app.RecoveryRecord, at time.Time) error {
	qq := q(tx)
	if err := qq.SupersedeRecoveryCodes(ctx, iddb.SupersedeRecoveryCodesParams{At: &at, UserID: user}); err != nil {
		return mapErr(err)
	}
	for _, c := range codes {
		if err := qq.InsertRecoveryCode(ctx, iddb.InsertRecoveryCodeParams{ID: c.ID, UserID: user, Lookup: c.Lookup, CodeHash: c.Hash, At: at}); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (Repository) LiveRecoveryCode(ctx context.Context, tx db.Querier, user uuid.UUID, lookup string) (app.RecoveryRecord, error) {
	r, err := q(tx).LiveRecoveryCode(ctx, iddb.LiveRecoveryCodeParams{UserID: user, Lookup: lookup})
	if err != nil {
		return app.RecoveryRecord{}, mapErr(err)
	}
	return app.RecoveryRecord{ID: r.ID, Lookup: lookup, Hash: r.CodeHash}, nil
}

func (Repository) UseRecoveryCode(ctx context.Context, tx db.Querier, id uuid.UUID, at time.Time) (bool, error) {
	n, err := q(tx).UseRecoveryCode(ctx, iddb.UseRecoveryCodeParams{At: &at, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) InsertSetupToken(ctx context.Context, tx db.Querier, t app.SetupToken) error {
	return mapErr(q(tx).InsertSetupToken(ctx, iddb.InsertSetupTokenParams{
		ID: t.ID, LookupID: t.LookupID, Verifier: t.Verifier, KeyVersion: int32(t.KeyVersion), //nolint:gosec // G115: key versions are small positive integers
		IssuedBy: t.IssuedBy, CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
	}))
}

func (Repository) SetupTokenByLookup(ctx context.Context, tx db.Querier, lookupID string) (app.SetupToken, error) {
	r, err := q(tx).SetupTokenByLookup(ctx, lookupID)
	if err != nil {
		return app.SetupToken{}, mapErr(err)
	}
	return app.SetupToken{
		ID: r.ID, LookupID: lookupID, Verifier: r.Verifier, KeyVersion: uint32(r.KeyVersion), //nolint:gosec // G115: CHECK (key_version > 0)
		ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt,
	}, nil
}

func (Repository) UseSetupToken(ctx context.Context, tx db.Querier, id uuid.UUID, at time.Time) (bool, error) {
	n, err := q(tx).UseSetupToken(ctx, iddb.UseSetupTokenParams{At: &at, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) InsertPasswordReset(ctx context.Context, tx db.Querier, r app.PasswordReset) error {
	return mapErr(q(tx).InsertPasswordReset(ctx, iddb.InsertPasswordResetParams{
		ID: r.ID, UserID: r.UserID, LookupID: r.LookupID, Verifier: r.Verifier, KeyVersion: int32(r.KeyVersion), //nolint:gosec // G115: key versions are small
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}))
}

func (Repository) PasswordResetByLookup(ctx context.Context, tx db.Querier, lookupID string) (app.PasswordReset, error) {
	r, err := q(tx).PasswordResetByLookup(ctx, lookupID)
	if err != nil {
		return app.PasswordReset{}, mapErr(err)
	}
	return app.PasswordReset{
		ID: r.ID, UserID: r.UserID, LookupID: lookupID, Verifier: r.Verifier, KeyVersion: uint32(r.KeyVersion), //nolint:gosec // G115: checked positive by the schema
		ExpiresAt: r.ExpiresAt, UsedAt: r.UsedAt,
	}, nil
}

func (Repository) UsePasswordReset(ctx context.Context, tx db.Querier, id uuid.UUID, at time.Time) (bool, error) {
	n, err := q(tx).UsePasswordReset(ctx, iddb.UsePasswordResetParams{At: &at, ID: id})
	return n == 1, mapErr(err)
}

func (Repository) Throttle(ctx context.Context, tx db.Querier, key []byte) (domain.Throttle, error) {
	r, err := q(tx).ThrottleState(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Throttle{}, nil
	}
	if err != nil {
		return domain.Throttle{}, mapErr(err)
	}
	return domain.Throttle{Failures: int(r.Failures), NextAllowedAt: r.NextAllowedAt}, nil
}

func (Repository) LockThrottle(ctx context.Context, tx db.Querier, key []byte, kind string, at time.Time) (domain.Throttle, error) {
	qq := q(tx)
	if err := qq.EnsureThrottle(ctx, iddb.EnsureThrottleParams{Key: key, Kind: kind, At: at}); err != nil {
		return domain.Throttle{}, mapErr(err)
	}
	r, err := qq.LockThrottle(ctx, key)
	if err != nil {
		return domain.Throttle{}, mapErr(err)
	}
	return domain.Throttle{Failures: int(r.Failures), NextAllowedAt: r.NextAllowedAt}, nil
}

func (Repository) SaveThrottle(ctx context.Context, tx db.Querier, key []byte, t domain.Throttle, at time.Time) error {
	next := t.NextAllowedAt
	if next.IsZero() {
		next = at
	}
	return mapErr(q(tx).SaveThrottle(ctx, iddb.SaveThrottleParams{
		Failures: int32(min(t.Failures, 1<<30)), NextAllowedAt: next, At: at, Key: key, //nolint:gosec // G115: clamped
	}))
}

func (Repository) DEK(ctx context.Context, tx db.Querier, scope string) (crypto.WrappedDEK, error) {
	r, err := q(tx).DEKByScope(ctx, scope)
	if err != nil {
		return crypto.WrappedDEK{}, mapErr(err)
	}
	return crypto.WrappedDEK{ID: r.ID, KEKVersion: uint32(r.KekVersion), Nonce: r.Nonce, Ciphertext: r.Ciphertext}, nil //nolint:gosec // G115: checked positive by the schema
}

func (Repository) InsertDEK(ctx context.Context, tx db.Querier, scope string, dek crypto.WrappedDEK, at time.Time) error {
	return mapErr(q(tx).InsertDEK(ctx, iddb.InsertDEKParams{
		ID: dek.ID, Scope: scope, KekVersion: int32(dek.KEKVersion), Nonce: dek.Nonce, Ciphertext: dek.Ciphertext, At: at, //nolint:gosec // G115: key versions are small
	}))
}
