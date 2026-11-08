package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/identity/oidc"
	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/jobs"
	"github.com/qali-project/qali/internal/platform/secret"
)

const oidcLifetime = 10 * time.Minute

func (s *Service) OIDCRedirectURI() string {
	return strings.TrimRight(s.cfg.OIDC.PublicURL, "/") + "/api/v1/auth/oidc/callback"
}

// OIDCInvitationAcceptor keeps membership ownership in the workspace module.
// It calls finish inside the invitation's scoped transaction after validating
// its token and email. User creation, linking and consumption commit together.
type OIDCInvitationAcceptor func(ctx context.Context, token secret.Value, email string, m RequestMeta,
	finish func(context.Context, *db.WriteTx, bool) (uuid.UUID, Grant, error)) (Grant, error)

func (s *Service) oidcRepo() OIDCRepository { r, _ := s.cfg.Repo.(OIDCRepository); return r }

func (s *Service) protocol(p OIDCProvider) (*oidc.Client, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidcClient != nil && s.oidcProviderID == p.ID && s.oidcVersion == p.Version {
		return s.oidcClient, nil
	}
	cfg := s.cfg.OIDC
	cfg.Issuer = p.Issuer
	cfg.ClientID = p.ClientID
	cfg.Clock = s.cfg.Clock
	c, err := oidc.New(cfg)
	if err != nil {
		return nil, ErrInvalidInput
	}
	if s.oidcClient != nil {
		s.oidcClient.Close()
	}
	s.oidcClient = c
	s.oidcProviderID = p.ID
	s.oidcVersion = p.Version
	return c, nil
}

func (s *Service) oidcContext(kind string, id uuid.UUID) crypto.Context {
	secretType := "payload"
	if kind == "oidc_provider" {
		secretType = "client_secret"
	}
	return crypto.Context{WorkspaceID: installationScope, OwnerType: kind, OwnerID: id.String(), SecretType: secretType, SchemaVersion: 1}
}

func (s *Service) sealOIDC(ctx context.Context, q db.Querier, kind string, id uuid.UUID, v secret.Value) (crypto.Sealed, error) {
	dek, err := s.installationDEK(ctx, q)
	if err != nil {
		return crypto.Sealed{}, err
	}
	return s.cfg.Keyring.Seal(dek, s.oidcContext(kind, id), v)
}

func (s *Service) openOIDC(ctx context.Context, q db.Querier, kind string, id uuid.UUID, v crypto.Sealed) (secret.Value, error) {
	dek, err := s.cfg.Repo.DEK(ctx, q, installationScope)
	if err != nil {
		return secret.Value{}, err
	}
	if dek.ID != v.DEKID {
		return secret.Value{}, crypto.ErrDecrypt
	}
	return s.cfg.Keyring.Open(dek, s.oidcContext(kind, id), v)
}

func randomOIDC() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (s *Service) oidcAudit(ctx context.Context, tx *db.WriteTx, action string, id uuid.UUID) error {
	metadata := map[string]any{}
	if strings.HasPrefix(action, "security.") {
		metadata["severity"] = "high"
	}
	return tx.Audit(ctx, audit.Entry{Action: action, TargetType: "oidc", TargetID: id.String(), Outcome: audit.Success, Metadata: metadata})
}

// AuthMethods exposes only a verified provider's label and the local policy.
func (s *Service) AuthMethods(ctx context.Context) (bool, string, error) {
	local, label := true, ""
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		policy, err := s.oidcRepo().LoginPolicy(ctx, q, false)
		if errors.Is(err, db.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		local = policy.LocalLogin
		p, err := s.oidcRepo().OIDCProvider(ctx, q)
		if errors.Is(err, db.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if p.Status == "verified" {
			label = p.Label
		}
		return nil
	})
	return local, label, err
}

// securityScope and security authorize within the same tenant-scoped transaction.
func (s *Service) securityScope(c Current, ws uuid.UUID, m RequestMeta) (db.Scope, error) {
	return db.WorkspaceScope(ws, userActor(c.View.UserID), m.info())
}
func (s *Service) security(ctx context.Context, q db.Querier, c Current, ws uuid.UUID, perm authz.Permission, lock bool) (LoginPolicy, error) {
	p, err := s.oidcRepo().LoginPolicy(ctx, q, lock)
	if err != nil {
		return p, err
	}
	if p.WorkspaceID != ws {
		return p, ErrNotFound
	}
	if s.cfg.Security == nil {
		return p, ErrForbidden
	}
	_, err = s.cfg.Security(ctx, q, c, perm)
	return p, err
}

func matchOIDC(version int32, want *int32) error {
	if want == nil {
		return ErrIfMatchRequired
	}
	if *want != version {
		return ErrVersionMismatch
	}
	return nil
}

func (s *Service) GetOIDCProvider(ctx context.Context, c Current, ws uuid.UUID, m RequestMeta) (OIDCProvider, error) {
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return OIDCProvider{}, err
	}
	var out OIDCProvider
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		if _, err := s.security(ctx, q, c, ws, "security.read", false); err != nil {
			return err
		}
		var err error
		out, err = s.oidcRepo().OIDCProvider(ctx, q)
		return err
	})
	return out, err
}

type OIDCProviderInput struct {
	Issuer, ClientID, Label string
	ClientSecret            *secret.Value
}

func (s *Service) PutOIDCProvider(ctx context.Context, c Current, ws uuid.UUID, in OIDCProviderInput, version *int32, m RequestMeta) (OIDCProvider, error) {
	if strings.TrimSpace(in.Label) == "" || utf8.RuneCountInString(in.Label) > 80 || len(in.Issuer) > 2048 {
		return OIDCProvider{}, ErrInvalidInput
	}
	cfg := s.cfg.OIDC
	cfg.Issuer = in.Issuer
	cfg.ClientID = in.ClientID
	if _, err := s.GetOIDCProviderForVerification(ctx, c, ws, m); err != nil {
		return OIDCProvider{}, err
	}
	client, err := oidc.New(cfg)
	if err != nil {
		return OIDCProvider{}, ErrInvalidInput
	}
	defer client.Close()
	if err := client.Discover(ctx); err != nil {
		return OIDCProvider{}, ErrOIDCUnavailable
	}
	if in.ClientSecret != nil && (in.ClientSecret.Len() == 0 || in.ClientSecret.Len() > 8192) {
		return OIDCProvider{}, ErrInvalidInput
	}
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return OIDCProvider{}, err
	}
	var out OIDCProvider
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		policy, err := s.security(ctx, tx, c, ws, "security.manage_sso", true)
		if err != nil {
			return err
		}
		p, err := s.oidcRepo().OIDCProvider(ctx, tx)
		fresh := errors.Is(err, db.ErrNotFound)
		if err != nil && !fresh {
			return err
		}
		if fresh {
			if version != nil && *version != 0 {
				return ErrVersionMismatch
			}
			if in.ClientSecret == nil {
				return ErrInvalidInput
			}
			p.ID, err = s.cfg.NewID()
			if err != nil {
				return err
			}
			p.CreatedAt = s.now()
		}
		if !fresh {
			if err := matchOIDC(p.Version, version); err != nil {
				return err
			}
		}
		changed := fresh || p.Issuer != in.Issuer || p.ClientID != in.ClientID || in.ClientSecret != nil
		if !fresh && p.Issuer != in.Issuer {
			if err := s.canRemoveProvider(ctx, tx); err != nil {
				return err
			}
		}
		if in.ClientSecret != nil {
			p.Secret, err = s.sealOIDC(ctx, tx, "oidc_provider", p.ID, *in.ClientSecret)
			if err != nil {
				return err
			}
		}
		p.Issuer, p.ClientID, p.Label = in.Issuer, in.ClientID, in.Label
		p.Version++
		p.UpdatedAt = s.now()
		if changed {
			p.Status = "draft"
			p.VerifiedAt = nil
			p.VerifiedBy = nil
			if !policy.LocalLogin {
				if err := s.enableLocalLogin(ctx, tx); err != nil {
					return err
				}
			}
		}
		if err := s.oidcRepo().SaveOIDCProvider(ctx, tx, p); err != nil {
			return err
		}
		out = p
		return s.oidcAudit(ctx, tx, "security.oidc_configured", p.ID)
	})
	return out, err
}

func (s *Service) enableLocalLogin(ctx context.Context, tx *db.WriteTx) error {
	if err := s.oidcRepo().SaveLoginPolicy(ctx, tx, true); err != nil {
		return err
	}
	return tx.Audit(ctx, audit.Entry{Action: "security.login_policy_changed", TargetType: "installation", Outcome: audit.Success, Metadata: map[string]any{"local_login": true, "severity": "high"}})
}

func (s *Service) DeleteOIDCProvider(ctx context.Context, c Current, ws uuid.UUID, version *int32, m RequestMeta) error {
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return err
	}
	return s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		policy, err := s.security(ctx, tx, c, ws, "security.manage_sso", true)
		if err != nil {
			return err
		}
		p, err := s.oidcRepo().OIDCProvider(ctx, tx)
		if err != nil {
			return err
		}
		if err := matchOIDC(p.Version, version); err != nil {
			return err
		}
		if !policy.LocalLogin {
			if err := s.enableLocalLogin(ctx, tx); err != nil {
				return err
			}
		}
		// Passwordless accounts must retain their usable provider identity.
		if err := s.canRemoveProvider(ctx, tx); err != nil {
			return err
		}
		if err := s.oidcRepo().RemoveOIDCProvider(ctx, tx); err != nil {
			return err
		}
		return s.oidcAudit(ctx, tx, "security.oidc_removed", p.ID)
	})
}

func (s *Service) GetLoginPolicy(ctx context.Context, c Current, ws uuid.UUID, m RequestMeta) (LoginPolicy, error) {
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return LoginPolicy{}, err
	}
	var p LoginPolicy
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		var err error
		p, err = s.security(ctx, q, c, ws, "security.read", false)
		return err
	})
	return p, err
}

func (s *Service) PutLoginPolicy(ctx context.Context, c Current, ws uuid.UUID, local bool, version *int32, m RequestMeta) (LoginPolicy, error) {
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return LoginPolicy{}, err
	}
	var out LoginPolicy
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		p, err := s.security(ctx, tx, c, ws, "security.update", true)
		if err != nil {
			return err
		}
		if err := matchOIDC(p.Version, version); err != nil {
			return err
		}
		if !local {
			provider, err := s.oidcRepo().OIDCProvider(ctx, tx)
			if err != nil || provider.Status != "verified" {
				return ErrOIDCUnavailable
			}
		}
		if err := s.oidcRepo().SaveLoginPolicy(ctx, tx, local); err != nil {
			return err
		}
		p.LocalLogin = local
		p.Version++
		out = p
		return tx.Audit(ctx, audit.Entry{Action: "security.login_policy_changed", TargetType: "installation", Outcome: audit.Success, Metadata: map[string]any{"local_login": local, "severity": "high"}})
	})
	return out, err
}

func (s *Service) passwordLoginAllowed(ctx context.Context, q db.Querier, u User, m RequestMeta) (bool, error) {
	p, err := s.oidcRepo().LoginPolicy(ctx, q, true)
	if err != nil {
		return false, err
	}
	if p.LocalLogin {
		return false, nil
	}
	if u.TOTPConfirmedAt == nil || s.cfg.Security == nil {
		return false, ErrInvalidCredentials
	}
	sc, err := db.WorkspaceScope(p.WorkspaceID, userActor(u.ID), m.info())
	if err != nil {
		return false, err
	}
	owner := false
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, tx db.Querier) error {
		var err error
		owner, err = s.cfg.Security(ctx, tx, Current{View: SessionView{UserID: u.ID}, RecentMFA: true}, "security.read")
		return err
	})
	if err != nil || !owner {
		return false, ErrInvalidCredentials
	}
	return true, nil
}

type oidcPayload struct {
	Verifier    string
	Invitation  string
	SessionID   uuid.UUID
	Version     int32
	WorkspaceID uuid.UUID
}
type OIDCStartResult struct {
	URL     string
	Binding secret.Value
}

func (s *Service) StartOIDC(ctx context.Context, c Current, purpose string, invitation, password secret.Value, ws uuid.UUID, m RequestMeta) (OIDCStartResult, error) {
	if purpose != "login" && purpose != "invitation" && purpose != "link" && purpose != "verify" {
		return OIDCStartResult{}, ErrInvalidInput
	}
	if purpose == "invitation" && invitation.IsZero() {
		return OIDCStartResult{}, ErrInvalidInput
	}
	if purpose == "link" {
		u, err := s.user(ctx, c.View.UserID)
		if err != nil {
			return OIDCStartResult{}, err
		}
		if u.TOTPConfirmedAt != nil {
			if !c.RecentMFA {
				return OIDCStartResult{}, ErrRecentMFARequired
			}
		} else if ok, _ := s.verifyPassword(u, true, password); !ok {
			return OIDCStartResult{}, ErrInvalidCredentials
		}
	}
	var p OIDCProvider
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, m), func(ctx context.Context, q db.Querier) error {
		var err error
		p, err = s.oidcRepo().OIDCProvider(ctx, q)
		return err
	})
	if err != nil {
		return OIDCStartResult{}, ErrOIDCUnavailable
	}
	if purpose != "verify" && p.Status != "verified" {
		return OIDCStartResult{}, ErrOIDCUnavailable
	}
	if purpose == "verify" {
		if _, err := s.GetOIDCProviderForVerification(ctx, c, ws, m); err != nil {
			return OIDCStartResult{}, err
		}
	}
	client, err := s.protocol(p)
	if err != nil {
		return OIDCStartResult{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return OIDCStartResult{}, err
	}
	stateSecret, err := randomOIDC()
	if err != nil {
		return OIDCStartResult{}, err
	}
	state := id.String() + "." + stateSecret
	nonce, err := randomOIDC()
	if err != nil {
		return OIDCStartResult{}, err
	}
	binding, err := randomOIDC()
	if err != nil {
		return OIDCStartResult{}, err
	}
	verifier, err := randomOIDC()
	if err != nil {
		return OIDCStartResult{}, err
	}
	url, err := client.AuthorizationURL(ctx, state, nonce, verifier)
	if err != nil {
		return OIDCStartResult{}, ErrOIDCUnavailable
	}
	payload := oidcPayload{Verifier: verifier, Version: p.Version, SessionID: c.SessionID, WorkspaceID: ws}
	if purpose == "invitation" {
		payload.Invitation = string(invitation.Expose())
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return OIDCStartResult{}, err
	}
	defer clear(raw)
	f := OIDCFlow{ID: id, LookupID: id.String(), StateVerifier: s.cfg.Tokens.Digest("oidc-state", []byte(state)), NonceVerifier: s.cfg.Tokens.Digest("oidc-nonce", []byte(nonce)), BindingVerifier: s.cfg.Tokens.Digest("oidc-binding", []byte(binding)), KeyVersion: 1, ProviderID: p.ID, Purpose: purpose, CreatedAt: s.now(), ExpiresAt: s.now().Add(oidcLifetime)}
	if purpose == "link" || purpose == "verify" {
		f.UserID = &c.View.UserID
	}
	err = s.cfg.Store.Write(ctx, s.systemScope(anonymous, m), func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.checkProviderVersion(ctx, tx, p.ID, p.Version); err != nil {
			return err
		}
		var err error
		f.Sealed, err = s.sealOIDC(ctx, tx, "oidc_flow", id, secret.New(raw))
		if err != nil {
			return err
		}
		if err := s.oidcRepo().InsertOIDCFlow(ctx, tx, f); err != nil {
			return err
		}
		queue := jobs.NewQueue(s.cfg.Clock, s.cfg.NewID)
		if _, _, err := queue.Enqueue(ctx, tx, jobs.EnqueueParams{Kind: "identity.oidc_cleanup", RunAt: f.ExpiresAt, IdempotencyKey: "oidc-cleanup:" + f.ID.String()}); err != nil {
			return err
		}
		return s.oidcAudit(ctx, tx, "auth.oidc_started", id)
	})
	if err != nil {
		return OIDCStartResult{}, err
	}
	return OIDCStartResult{URL: url, Binding: secret.New([]byte(binding))}, nil
}

func (s *Service) GetOIDCProviderForVerification(ctx context.Context, c Current, ws uuid.UUID, m RequestMeta) (LoginPolicy, error) {
	sc, err := s.securityScope(c, ws, m)
	if err != nil {
		return LoginPolicy{}, err
	}
	var p LoginPolicy
	err = s.cfg.Store.Read(ctx, sc, func(ctx context.Context, q db.Querier) error {
		var err error
		p, err = s.security(ctx, q, c, ws, "security.manage_sso", false)
		return err
	})
	return p, err
}

func (s *Service) checkProviderVersion(ctx context.Context, q db.Querier, id uuid.UUID, version int32) error {
	if _, err := s.oidcRepo().LoginPolicy(ctx, q, true); err != nil {
		return err
	}
	p, err := s.oidcRepo().OIDCProvider(ctx, q)
	if err != nil || p.ID != id || p.Version != version {
		return ErrInvalidToken
	}
	return nil
}

// CompleteOIDC consumes a browser-bound flow in a committed transaction before
// exchanging any code, including cancellation and invalid issuer responses.
func (s *Service) CompleteOIDC(ctx context.Context, state, code, providerError, issuer string, binding, session secret.Value, m RequestMeta) (Grant, string, error) {
	if len(state) > 256 || len(code) > 8192 || binding.IsZero() {
		return Grant{}, "", ErrInvalidToken
	}
	lookup, _, ok := strings.Cut(state, ".")
	if !ok {
		return Grant{}, "", ErrInvalidToken
	}
	var f OIDCFlow
	var payload oidcPayload
	var p OIDCProvider
	var credential secret.Value
	err := s.cfg.Store.Write(ctx, s.systemScope(anonymous, m), func(ctx context.Context, tx *db.WriteTx) error {
		var err error
		f, err = s.oidcRepo().ConsumeOIDCFlow(ctx, tx, lookup, s.cfg.Tokens.Digest("oidc-state", []byte(state)), s.cfg.Tokens.Digest("oidc-binding", binding.Expose()), s.now())
		if err != nil {
			return ErrInvalidToken
		}
		return s.oidcAudit(ctx, tx, "auth.oidc_callback_received", f.ID)
	})
	if err != nil {
		return Grant{}, "", ErrInvalidToken
	}
	fail := func() (Grant, string, error) {
		_ = s.cfg.Store.Write(ctx, s.systemScope(anonymous, m), func(ctx context.Context, tx *db.WriteTx) error {
			return tx.Audit(ctx, audit.Entry{Action: "auth.oidc_login_failed", TargetType: "oidc", TargetID: f.ID.String(), Outcome: audit.Failure})
		})
		return Grant{}, "", ErrInvalidToken
	}
	if providerError != "" || code == "" {
		return fail()
	}
	err = s.cfg.Store.Read(ctx, s.systemScope(anonymous, m), func(ctx context.Context, q db.Querier) error {
		raw, err := s.openOIDC(ctx, q, "oidc_flow", f.ID, f.Sealed)
		if err != nil {
			return err
		}
		b := raw.Expose()
		defer clear(b)
		if err := json.Unmarshal(b, &payload); err != nil {
			return err
		}
		p, err = s.oidcRepo().OIDCProvider(ctx, q)
		if err != nil || p.ID != f.ProviderID || p.Version != payload.Version {
			return ErrInvalidToken
		}
		credential, err = s.openOIDC(ctx, q, "oidc_provider", p.ID, p.Secret)
		return err
	})
	if err != nil || issuer != "" && issuer != p.Issuer {
		return fail()
	}
	var cur Current
	if f.UserID != nil {
		cur, err = s.Authenticate(ctx, session, m)
		if err != nil || cur.SessionID != payload.SessionID || cur.View.UserID != *f.UserID || cur.View.State != domain.StateActive {
			return fail()
		}
	}
	client, err := s.protocol(p)
	if err != nil {
		return fail()
	}
	i, err := client.Exchange(ctx, code, payload.Verifier, credential, func(nonce string) bool {
		return hmac.Equal(f.NonceVerifier, s.cfg.Tokens.Digest("oidc-nonce", []byte(nonce)))
	})
	if err != nil {
		return fail()
	}
	if f.Purpose == "invitation" {
		if !i.EmailVerified || s.cfg.AcceptOIDCInvitation == nil {
			return fail()
		}
		email, err := domain.NormalizeEmail(i.Email)
		if err != nil {
			return fail()
		}
		g, err := s.cfg.AcceptOIDCInvitation(ctx, secret.New([]byte(payload.Invitation)), email, m, func(ctx context.Context, tx *db.WriteTx, requiresMFA bool) (uuid.UUID, Grant, error) {
			if err := s.checkProviderVersion(ctx, tx, p.ID, p.Version); err != nil {
				return uuid.Nil, Grant{}, err
			}
			u, err := s.cfg.Repo.UserByEmail(ctx, tx, email)
			if errors.Is(err, db.ErrNotFound) {
				id, e := s.cfg.NewID()
				if e != nil {
					return uuid.Nil, Grant{}, e
				}
				name := strings.TrimSpace(i.Name)
				if name == "" {
					name = email
				}
				if utf8.RuneCountInString(name) > 200 {
					return uuid.Nil, Grant{}, ErrInvalidInput
				}
				u = User{ID: id, Email: email, DisplayName: name, Active: true}
				err = s.cfg.Repo.InsertUser(ctx, tx, u, s.now())
			}
			if err != nil || !u.Active {
				return uuid.Nil, Grant{}, ErrInvalidToken
			}
			if err := s.linkOIDC(ctx, tx, u.ID, i, "invitation"); err != nil {
				return uuid.Nil, Grant{}, err
			}
			roles, err := s.cfg.Repo.ActiveRoles(ctx, tx, u.ID)
			if err != nil {
				return uuid.Nil, Grant{}, err
			}
			for _, r := range roles {
				requiresMFA = requiresMFA || domain.RoleRequiresMFA(r)
			}
			g, err := s.issueSession(ctx, tx, u, domain.StateAfterPassword(requiresMFA, u.TOTPConfirmedAt != nil), "oidc", nil, m)
			return u.ID, g, err
		})
		if err != nil {
			return fail()
		}
		return g, "/", nil
	}
	sc := s.systemScope(anonymous, m)
	if f.Purpose == "verify" {
		sc, err = s.securityScope(cur, payload.WorkspaceID, m)
		if err != nil {
			return fail()
		}
	}
	var grant Grant
	destination := "/"
	err = s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.checkProviderVersion(ctx, tx, p.ID, p.Version); err != nil {
			return err
		}
		if f.Purpose == "verify" {
			if _, err := s.security(ctx, tx, cur, payload.WorkspaceID, "security.manage_sso", false); err != nil {
				return err
			}
		}
		if f.UserID != nil {
			u, err := s.cfg.Repo.UserByID(ctx, tx, *f.UserID)
			if err != nil || !u.Active {
				return ErrInvalidToken
			}
			method := "explicit"
			if f.Purpose == "verify" {
				method = "verify"
			}
			if err := s.linkOIDC(ctx, tx, u.ID, i, method); err != nil {
				return err
			}
			destination = "/account"
			if f.Purpose == "verify" {
				now := s.now()
				p.Status = "verified"
				p.VerifiedAt = &now
				p.VerifiedBy = f.UserID
				p.Version++
				p.UpdatedAt = now
				if err := s.oidcRepo().SaveOIDCProvider(ctx, tx, p); err != nil {
					return err
				}
				destination = "/w/" + payload.WorkspaceID.String() + "/security"
				return s.oidcAudit(ctx, tx, "security.oidc_verified", p.ID)
			}
			return s.oidcAudit(ctx, tx, "auth.oidc_linked", u.ID)
		}
		if p.Status != "verified" {
			return ErrInvalidToken
		}
		linked, err := s.oidcRepo().OIDCIdentity(ctx, tx, i.Issuer, i.Subject)
		var u User
		if errors.Is(err, db.ErrNotFound) {
			if !i.EmailVerified {
				return ErrInvalidToken
			}
			email, err := domain.NormalizeEmail(i.Email)
			if err != nil {
				return ErrInvalidToken
			}
			u, err = s.cfg.Repo.UserByEmail(ctx, tx, email)
			if err != nil {
				return ErrInvalidToken
			}
			if err := s.linkOIDC(ctx, tx, u.ID, i, "verified_email"); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			u, err = s.cfg.Repo.UserByID(ctx, tx, linked.UserID)
			if err != nil {
				return err
			}
			if err := s.oidcRepo().TouchOIDCIdentity(ctx, tx, linked.ID, s.now()); err != nil {
				return err
			}
		}
		if !u.Active {
			return ErrInvalidToken
		}
		roles, err := s.cfg.Repo.ActiveRoles(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		privileged := false
		for _, r := range roles {
			privileged = privileged || domain.RoleRequiresMFA(r)
		}
		grant, err = s.issueSession(ctx, tx, u, domain.StateAfterPassword(privileged, u.TOTPConfirmedAt != nil), "oidc", nil, m)
		if err != nil {
			return err
		}
		return s.oidcAudit(ctx, tx, "auth.oidc_login", u.ID)
	})
	if err != nil {
		return fail()
	}
	return grant, destination, nil
}

func (s *Service) linkOIDC(ctx context.Context, tx *db.WriteTx, user uuid.UUID, i oidc.Identity, method string) error {
	if len(i.Subject) == 0 || len(i.Subject) > 255 {
		return ErrInvalidToken
	}
	existing, err := s.oidcRepo().OIDCIdentity(ctx, tx, i.Issuer, i.Subject)
	if err == nil {
		if existing.UserID != user {
			return ErrInvalidToken
		}
		return nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return err
	}
	now := s.now()
	if err := s.oidcRepo().InsertOIDCIdentity(ctx, tx, OIDCIdentity{ID: id, UserID: user, Issuer: i.Issuer, Subject: i.Subject, Method: method, LinkedAt: now, LastLoginAt: &now}); err != nil {
		return err
	}
	return tx.Audit(ctx, audit.Entry{Action: "auth.oidc_linked", TargetType: "user", TargetID: user.String(), Outcome: audit.Success, Metadata: map[string]any{"method": method}})
}

func (s *Service) OwnOIDCIdentity(ctx context.Context, c Current, m RequestMeta) (OIDCIdentity, error) {
	var out OIDCIdentity
	err := s.cfg.Store.Read(ctx, s.systemScope(userActor(c.View.UserID), m), func(ctx context.Context, q db.Querier) error {
		p, err := s.oidcRepo().OIDCProvider(ctx, q)
		if err != nil {
			return err
		}
		out, err = s.oidcRepo().OwnOIDCIdentity(ctx, q, c.View.UserID, p.Issuer)
		return err
	})
	return out, err
}

func (s *Service) UnlinkOIDC(ctx context.Context, c Current, ws, user uuid.UUID, m RequestMeta) error {
	sc := s.systemScope(userActor(c.View.UserID), m)
	if ws != uuid.Nil {
		var err error
		sc, err = s.securityScope(c, ws, m)
		if err != nil {
			return err
		}
	} else if user != c.View.UserID {
		return ErrForbidden
	}
	return s.cfg.Store.Write(ctx, sc, func(ctx context.Context, tx *db.WriteTx) error {
		p, err := s.oidcRepo().LoginPolicy(ctx, tx, true)
		if err != nil {
			return err
		}
		if ws != uuid.Nil {
			if _, err := s.security(ctx, tx, c, ws, "security.manage_sso", false); err != nil {
				return err
			}
			if s.cfg.SecurityMember == nil {
				return ErrForbidden
			}
			if err := s.cfg.SecurityMember(ctx, tx, user); err != nil {
				return err
			}
		}
		u, err := s.cfg.Repo.UserByID(ctx, tx, user)
		if err != nil {
			return err
		}
		if !u.Active || u.PasswordHash == "" {
			return ErrNoAlternativeLogin
		}
		if !p.LocalLogin {
			if _, err := s.passwordLoginAllowed(ctx, tx, u, m); err != nil {
				return ErrNoAlternativeLogin
			}
		}
		if err := s.oidcRepo().RemoveOIDCIdentity(ctx, tx, user); err != nil {
			return err
		}
		return s.oidcAudit(ctx, tx, "auth.oidc_unlinked", user)
	})
}

func (s *Service) CleanupOIDCFlows(ctx context.Context) error {
	return s.cfg.Store.Write(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, tx *db.WriteTx) error {
		n, err := s.oidcRepo().CleanupOIDCFlows(ctx, tx, s.now())
		if err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.oidc_flows_cleaned", TargetType: "oidc", Outcome: audit.Success, Metadata: map[string]any{"count": n}})
	})
}

func (s *Service) canRemoveProvider(ctx context.Context, q db.Querier) error {
	v, err := s.oidcRepo().HasPasswordlessOIDCUsers(ctx, q)
	if err != nil {
		return err
	}
	if v {
		return ErrNoAlternativeLogin
	}
	return nil
}
