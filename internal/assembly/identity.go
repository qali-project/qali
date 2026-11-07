package assembly

import (
	"context"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	identity "github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
	workspace "github.com/qali-project/qali/internal/workspace/app"
)

// IdentityWorkspace connects public application ports before serving requests.
// resolve breaks the construction cycle; no adapters cross module boundaries.
func IdentityWorkspace(cfg identity.Config, resolve func() *workspace.Service) identity.Config {
	cfg.SecurityMember = func(ctx context.Context, q db.Querier, user uuid.UUID) error {
		return resolve().RequireOIDCMember(ctx, q, user)
	}
	cfg.Security = func(ctx context.Context, q db.Querier, c identity.Current, p authz.Permission) (bool, error) {
		return resolve().AuthorizeSecurity(ctx, q, c, p)
	}
	cfg.AcceptOIDCInvitation = func(ctx context.Context, token secret.Value, email string, m identity.RequestMeta, finish func(context.Context, *db.WriteTx, bool) (uuid.UUID, identity.Grant, error)) (identity.Grant, error) {
		return resolve().AcceptOIDCInvitation(ctx, token, email, m, finish)
	}
	return cfg
}
