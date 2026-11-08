package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/adapter/postgres/iddb"
	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
)

var _ app.OIDCRepository = Repository{}

func (Repository) HasPasswordlessOIDCUsers(ctx context.Context, tx db.Querier) (bool, error) {
	v, err := q(tx).HasPasswordlessOIDCUsers(ctx)
	return v, mapErr(err)
}

func (Repository) LoginPolicy(ctx context.Context, tx db.Querier, lock bool) (app.LoginPolicy, error) {
	if lock {
		r, err := q(tx).LockLoginPolicy(ctx)
		return app.LoginPolicy{WorkspaceID: r.PrimaryWorkspaceID, LocalLogin: r.LocalLoginEnabled, Version: r.LoginPolicyVersion}, mapErr(err)
	}
	r, err := q(tx).LoginPolicy(ctx)
	return app.LoginPolicy{WorkspaceID: r.PrimaryWorkspaceID, LocalLogin: r.LocalLoginEnabled, Version: r.LoginPolicyVersion}, mapErr(err)
}

func (Repository) SaveLoginPolicy(ctx context.Context, tx db.Querier, enabled bool) error {
	return mapErr(q(tx).SaveLoginPolicy(ctx, enabled))
}

func (Repository) OIDCProvider(ctx context.Context, tx db.Querier) (app.OIDCProvider, error) {
	r, err := q(tx).OIDCProvider(ctx)
	return app.OIDCProvider{ID: r.ID, Issuer: r.Issuer, ClientID: r.ClientID, Label: r.Label, Status: r.Status,
		Secret:     crypto.Sealed{Algorithm: crypto.AlgorithmAES256GCM, DEKID: r.SecretDekID, Nonce: r.SecretNonce, Ciphertext: r.SecretCiphertext},
		VerifiedAt: r.VerifiedAt, VerifiedBy: r.VerifiedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Version: r.Version}, mapErr(err)
}

func (Repository) SaveOIDCProvider(ctx context.Context, tx db.Querier, p app.OIDCProvider) error {
	return mapErr(q(tx).SaveOIDCProvider(ctx, iddb.SaveOIDCProviderParams{ID: p.ID, Issuer: p.Issuer, ClientID: p.ClientID, Label: p.Label,
		SecretDekID: p.Secret.DEKID, SecretNonce: p.Secret.Nonce, SecretCiphertext: p.Secret.Ciphertext, Status: p.Status,
		VerifiedAt: p.VerifiedAt, VerifiedBy: p.VerifiedBy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, Version: p.Version}))
}

func (Repository) RemoveOIDCProvider(ctx context.Context, tx db.Querier) error {
	if err := q(tx).RemoveAllOIDCIdentities(ctx); err != nil {
		return mapErr(err)
	}
	return mapErr(q(tx).RemoveOIDCProvider(ctx))
}

func (Repository) InsertOIDCFlow(ctx context.Context, tx db.Querier, f app.OIDCFlow) error {
	return mapErr(q(tx).InsertOIDCFlow(ctx, iddb.InsertOIDCFlowParams{ID: f.ID, LookupID: f.LookupID,
		StateVerifier: f.StateVerifier, NonceVerifier: f.NonceVerifier, BindingVerifier: f.BindingVerifier, KeyVersion: f.KeyVersion,
		ProviderID: f.ProviderID, Purpose: f.Purpose, UserID: f.UserID, SealedDekID: f.Sealed.DEKID, SealedNonce: f.Sealed.Nonce,
		SealedPayload: f.Sealed.Ciphertext, CreatedAt: f.CreatedAt, ExpiresAt: f.ExpiresAt}))
}

func (Repository) ConsumeOIDCFlow(ctx context.Context, tx db.Querier, lookup string, state, binding []byte, at time.Time) (app.OIDCFlow, error) {
	r, err := q(tx).ConsumeOIDCFlow(ctx, iddb.ConsumeOIDCFlowParams{LookupID: lookup, StateVerifier: state, BindingVerifier: binding, At: &at})
	return app.OIDCFlow{ID: r.ID, LookupID: r.LookupID, StateVerifier: r.StateVerifier, NonceVerifier: r.NonceVerifier,
		BindingVerifier: r.BindingVerifier, KeyVersion: r.KeyVersion, ProviderID: r.ProviderID, Purpose: r.Purpose, UserID: r.UserID,
		Sealed:    crypto.Sealed{Algorithm: crypto.AlgorithmAES256GCM, DEKID: r.SealedDekID, Nonce: r.SealedNonce, Ciphertext: r.SealedPayload},
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}, mapErr(err)
}

func oidcIdentity(r iddb.QaliUserIdentity) app.OIDCIdentity {
	return app.OIDCIdentity{ID: r.ID, UserID: r.UserID, Issuer: r.Issuer, Subject: r.Subject, Method: r.LinkMethod, LinkedAt: r.LinkedAt, LastLoginAt: r.LastLoginAt}
}

func (Repository) OIDCIdentity(ctx context.Context, tx db.Querier, issuer, subject string) (app.OIDCIdentity, error) {
	r, err := q(tx).OIDCIdentity(ctx, iddb.OIDCIdentityParams{Issuer: issuer, Subject: subject})
	return oidcIdentity(r), mapErr(err)
}

func (Repository) OwnOIDCIdentity(ctx context.Context, tx db.Querier, user uuid.UUID, issuer string) (app.OIDCIdentity, error) {
	r, err := q(tx).OwnOIDCIdentity(ctx, iddb.OwnOIDCIdentityParams{UserID: user, Issuer: issuer})
	return oidcIdentity(r), mapErr(err)
}

func (Repository) InsertOIDCIdentity(ctx context.Context, tx db.Querier, i app.OIDCIdentity) error {
	return mapErr(q(tx).InsertOIDCIdentity(ctx, iddb.InsertOIDCIdentityParams{ID: i.ID, UserID: i.UserID, Issuer: i.Issuer, Subject: i.Subject, LinkMethod: i.Method, LinkedAt: i.LinkedAt, LastLoginAt: i.LastLoginAt}))
}

func (Repository) TouchOIDCIdentity(ctx context.Context, tx db.Querier, id uuid.UUID, at time.Time) error {
	return mapErr(q(tx).TouchOIDCIdentity(ctx, iddb.TouchOIDCIdentityParams{ID: id, LastLoginAt: &at}))
}

func (Repository) RemoveOIDCIdentity(ctx context.Context, tx db.Querier, user uuid.UUID) error {
	return mapErr(q(tx).RemoveOIDCIdentity(ctx, user))
}

func (Repository) CleanupOIDCFlows(ctx context.Context, tx db.Querier, at time.Time) (int64, error) {
	n, err := q(tx).CleanupOIDCFlows(ctx, at)
	return n, mapErr(err)
}
