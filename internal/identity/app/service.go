package app

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
)

const (
	installationScope = "installation"
	resetLifetime     = 30 * time.Minute
	setupLifetime     = time.Hour
)

// Config wires the service.
type Config struct {
	Store     *db.Store
	Repo      Repository
	Passwords *crypto.Passwords
	Tokens    *crypto.Tokens
	Keyring   *crypto.Keyring
	Clock     clock.Clock
	NewID     func() (uuid.UUID, error)
	// Issuer labels TOTP entries in authenticator apps.
	Issuer string
}

// Service implements the identity use cases.
type Service struct {
	cfg       Config
	dummyHash string
}

// New returns a service. It precomputes a dummy password hash so that
// unknown accounts cost the same verification time as known ones.
func New(cfg Config) *Service {
	dummy, err := cfg.Passwords.Hash(secret.New([]byte("dummy password for timing equalization")))
	if err != nil {
		panic(err) // crypto/rand failure
	}
	return &Service{cfg: cfg, dummyHash: dummy}
}

// RequestMeta is request attribution.
type RequestMeta struct {
	IP        netip.Addr
	RequestID string
}

func (m RequestMeta) info() db.RequestInfo {
	return db.RequestInfo{RequestID: m.RequestID, SourceIP: m.IP}
}

// SessionView is what a client may know about its session.
type SessionView struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
	MFAEnrolled bool
	State       domain.SessionState
	ExpiresAt   time.Time
}

// Grant is a newly issued session. Token and CSRF are shown once.
type Grant struct {
	Token secret.Value
	CSRF  secret.Value
	View  SessionView
}

// Current is an authenticated session for one request.
type Current struct {
	SessionID uuid.UUID
	View      SessionView
	// RecentMFA reports a TOTP verification within domain.RecentMFAWindow.
	RecentMFA     bool
	mfaVerifiedAt *time.Time
	csrf          []byte
	csrfToken     secret.Value
}

type currentKey struct{}

// WithCurrent returns ctx carrying the authenticated session. Adapters of
// other modules read it with CurrentFrom.
func WithCurrent(ctx context.Context, c Current) context.Context {
	return context.WithValue(ctx, currentKey{}, c)
}

// CurrentFrom returns the authenticated session of the request, if any.
func CurrentFrom(ctx context.Context) (Current, bool) {
	c, ok := ctx.Value(currentKey{}).(Current)
	return c, ok
}

// CSRFToken returns the session's CSRF token so a reloaded page can obtain
// it again with the cookie alone.
func (c Current) CSRFToken() secret.Value { return c.csrfToken }

// csrfFor derives the session's CSRF token from its bearer token. It is
// session-bound, rotates with the session, and is never stored in clear.
func (s *Service) csrfFor(token secret.Value) []byte {
	raw := token.Expose()
	defer clear(raw)
	return []byte(base64.RawURLEncoding.EncodeToString(s.cfg.Tokens.Digest("csrf-token", raw)))
}

// TOTPEnrollment carries a new secret for display.
type TOTPEnrollment struct {
	Secret string
	URI    string
}

// BootstrapInput is the first owner's data and the operator's setup token.
type BootstrapInput struct {
	Email         string
	DisplayName   string
	Password      secret.Value
	WorkspaceName string
	SetupToken    secret.Value
}

func userActor(id uuid.UUID) audit.Actor { return audit.Actor{Type: audit.ActorUser, ID: id.String()} }

var anonymous = audit.Actor{Type: audit.ActorSystem, ID: "auth"}

func (s *Service) systemScope(actor audit.Actor, m RequestMeta) db.Scope {
	sc, err := db.SystemScope(actor, m.info())
	if err != nil {
		panic(err) // actors are constructed in this package and always valid
	}
	return sc
}

func (s *Service) now() time.Time { return s.cfg.Clock.Now() }

// SetupRequired reports whether no owner exists yet.
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	var exists bool
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		var err error
		exists, err = s.cfg.Repo.InstallationExists(ctx, q)
		return err
	})
	return !exists, err
}

func cleanName(s string, maxLen int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > maxLen {
		return "", ErrInvalidInput
	}
	return s, nil
}

// Bootstrap creates the first owner, workspace, and membership, and returns
// a session that must enroll in TOTP. Concurrent calls create exactly one
// owner; later calls fail with ErrAlreadyBootstrapped.
func (s *Service) Bootstrap(ctx context.Context, in BootstrapInput, m RequestMeta) (Grant, error) {
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		return Grant{}, err
	}
	pw := in.Password.Expose()
	defer clear(pw)
	if err := domain.ValidatePassword(string(pw), email); err != nil {
		return Grant{}, err
	}
	name, err := cleanName(in.DisplayName, 200)
	if err != nil {
		return Grant{}, err
	}
	workspaceName, err := cleanName(in.WorkspaceName, 120)
	if err != nil {
		return Grant{}, err
	}
	if required, err := s.SetupRequired(ctx); err != nil {
		return Grant{}, err
	} else if !required {
		return Grant{}, ErrAlreadyBootstrapped
	}
	// Check the operator's token before the deliberately slow hash.
	if err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, m), func(ctx context.Context, q db.Querier) error {
		_, err := s.setupToken(ctx, q, in.SetupToken)
		return err
	}); err != nil {
		return Grant{}, err
	}
	hash, err := s.cfg.Passwords.Hash(in.Password)
	if err != nil {
		return Grant{}, err
	}
	userID, err := s.cfg.NewID()
	if err != nil {
		return Grant{}, err
	}
	workspaceID, err := s.cfg.NewID()
	if err != nil {
		return Grant{}, err
	}
	scope, err := db.WorkspaceScope(workspaceID, userActor(userID), m.info())
	if err != nil {
		return Grant{}, err
	}
	user := User{ID: userID, Email: email, DisplayName: name, PasswordHash: hash, Active: true}
	var grant Grant
	err = s.cfg.Store.Write(ctx, scope, func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		tok, err := s.setupToken(ctx, tx, in.SetupToken)
		if err != nil {
			return err
		}
		if used, err := s.cfg.Repo.UseSetupToken(ctx, tx, tok.ID, now); err != nil {
			return err
		} else if !used {
			return ErrInvalidSetupToken // a concurrent bootstrap used it
		}
		if err := s.cfg.Repo.InsertInstallation(ctx, tx, userID, now); err != nil {
			if errors.Is(db.MapError(err), db.ErrConflict) {
				return ErrAlreadyBootstrapped
			}
			return err
		}
		if err := s.cfg.Repo.InsertUser(ctx, tx, user, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.InsertWorkspace(ctx, tx, workspaceID, workspaceName, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.InsertMember(ctx, tx, workspaceID, userID, "owner", now); err != nil {
			return err
		}
		if grant, err = s.issueSession(ctx, tx, user, domain.StateMFAEnrollment, "bootstrap", nil, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.bootstrap", TargetType: "user", TargetID: userID.String(), Outcome: audit.Success,
			Metadata: map[string]any{"workspace_id": workspaceID.String()}})
	})
	return grant, err
}

// setupToken finds and verifies an unused, unexpired setup token. Every
// failure is ErrInvalidSetupToken.
func (s *Service) setupToken(ctx context.Context, q db.Querier, token secret.Value) (SetupToken, error) {
	lookup, err := crypto.LookupID(crypto.TokenSetup, token)
	if err != nil {
		return SetupToken{}, ErrInvalidSetupToken
	}
	tok, err := s.cfg.Repo.SetupTokenByLookup(ctx, q, lookup)
	if errors.Is(err, db.ErrNotFound) {
		return SetupToken{}, ErrInvalidSetupToken
	}
	if err != nil {
		return SetupToken{}, err
	}
	if s.cfg.Tokens.Verify(crypto.TokenSetup, token, crypto.TokenRecord{
		Type: crypto.TokenSetup.Name, LookupID: tok.LookupID, Verifier: tok.Verifier, KeyVersion: tok.KeyVersion,
	}) != nil || tok.UsedAt != nil || !s.now().Before(tok.ExpiresAt) {
		return SetupToken{}, ErrInvalidSetupToken
	}
	return tok, nil
}

// IssueSetupToken returns, once, a single-use token that authorizes the
// first-owner bootstrap for one hour (operator CLI, REVIEW-001). It fails
// once the installation has an owner.
func (s *Service) IssueSetupToken(ctx context.Context, operator string) (secret.Value, time.Time, error) {
	if required, err := s.SetupRequired(ctx); err != nil {
		return secret.Value{}, time.Time{}, err
	} else if !required {
		return secret.Value{}, time.Time{}, ErrAlreadyBootstrapped
	}
	raw, rec, err := s.cfg.Tokens.Issue(crypto.TokenSetup)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	now := s.now()
	expires := now.Add(setupLifetime)
	actor := audit.Actor{Type: audit.ActorOperator, ID: operator}
	err = s.cfg.Store.Write(ctx, s.systemScope(actor, RequestMeta{}), func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.cfg.Repo.InsertSetupToken(ctx, tx, SetupToken{
			ID: id, LookupID: rec.LookupID, Verifier: rec.Verifier, KeyVersion: rec.KeyVersion,
			IssuedBy: operator, CreatedAt: now, ExpiresAt: expires,
		}); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.setup_token_issued", TargetType: "installation", TargetID: id.String(), Outcome: audit.Success})
	})
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	return raw, expires, nil
}

// issueSession creates a session row and returns the raw credentials once.
func (s *Service) issueSession(ctx context.Context, q db.Querier, u User, state domain.SessionState, method string, mfaAt *time.Time, m RequestMeta) (Grant, error) {
	raw, rec, err := s.cfg.Tokens.Issue(crypto.TokenSession)
	if err != nil {
		return Grant{}, err
	}
	csrfToken := s.csrfFor(raw)
	id, err := s.cfg.NewID()
	if err != nil {
		return Grant{}, err
	}
	life := domain.NewSession(s.now(), state)
	err = s.cfg.Repo.InsertSession(ctx, q, SessionRecord{
		ID: id, UserID: u.ID, LookupID: rec.LookupID, Verifier: rec.Verifier, KeyVersion: rec.KeyVersion,
		CSRFVerifier: s.cfg.Tokens.Digest("csrf", csrfToken), AuthMethod: method, Lifetime: life,
		MFAVerifiedAt: mfaAt, SourceIP: m.IP,
	})
	if err != nil {
		return Grant{}, err
	}
	return Grant{Token: raw, CSRF: secret.New(csrfToken), View: s.view(u, life)}, nil
}

func (s *Service) view(u User, life domain.Session) SessionView {
	return SessionView{
		UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName, MFAEnrolled: u.TOTPConfirmedAt != nil,
		State: life.State, ExpiresAt: life.IdleExpiresAt,
	}
}

// throttleKeys derives keyed, non-reversible throttle keys.
func (s *Service) accountKey(purpose, account string) []byte {
	return s.cfg.Tokens.Digest("throttle-"+purpose, []byte(account))
}

func (s *Service) ipKey(ip netip.Addr) []byte {
	return s.cfg.Tokens.Digest("throttle-ip", []byte(ip.String()))
}

// checkThrottle returns a ThrottledError if any key is still delayed.
func (s *Service) checkThrottle(ctx context.Context, keys ...[]byte) error {
	var wait time.Duration
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		for _, k := range keys {
			t, err := s.cfg.Repo.Throttle(ctx, q, k)
			if err != nil {
				return err
			}
			wait = max(wait, t.Wait(s.now()))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if wait > 0 {
		return &ThrottledError{RetryAfter: wait}
	}
	return nil
}

type throttleKey struct {
	key       []byte
	kind      string
	threshold int
}

// recordFailure counts a failed attempt against every key and audits it.
func (s *Service) recordFailure(ctx context.Context, actor audit.Actor, m RequestMeta, keys []throttleKey, e audit.Entry) error {
	return s.cfg.Store.Write(ctx, s.systemScope(actor, m), func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		for _, k := range keys {
			t, err := s.cfg.Repo.LockThrottle(ctx, tx, k.key, k.kind, now)
			if err != nil {
				return err
			}
			t.Fail(now, k.threshold)
			if err := s.cfg.Repo.SaveThrottle(ctx, tx, k.key, t, now); err != nil {
				return err
			}
		}
		e.Outcome = audit.Failure
		return tx.Audit(ctx, e)
	})
}

func (s *Service) clearThrottle(ctx context.Context, q db.Querier, key []byte, kind string) error {
	now := s.now()
	t, err := s.cfg.Repo.LockThrottle(ctx, q, key, kind, now)
	if err != nil {
		return err
	}
	t.Succeed()
	return s.cfg.Repo.SaveThrottle(ctx, q, key, t, now)
}

// lookupUser returns the active user with this email, if any.
func (s *Service) lookupUser(ctx context.Context, email string) (User, bool, error) {
	var u User
	err := s.cfg.Store.Read(ctx, s.systemScope(anonymous, RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		var err error
		u, err = s.cfg.Repo.UserByEmail(ctx, q, email)
		return err
	})
	if errors.Is(err, db.ErrNotFound) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, u.Active, nil
}

// verifyPassword checks a password, spending the same work when the account
// does not exist or has no password.
func (s *Service) verifyPassword(u User, found bool, password secret.Value) (ok, rehash bool) {
	if !found || u.PasswordHash == "" {
		_, _, _ = s.cfg.Passwords.Verify(password, s.dummyHash)
		return false, false
	}
	ok, rehash, err := s.cfg.Passwords.Verify(password, u.PasswordHash)
	if err != nil {
		return false, false
	}
	return ok, rehash
}

// Login verifies email and password. Privileged users without TOTP get an
// mfa_enrollment session; enrolled users get an mfa_challenge session.
func (s *Service) Login(ctx context.Context, rawEmail string, password secret.Value, m RequestMeta) (Grant, error) {
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		email = strings.ToLower(strings.TrimSpace(rawEmail))
	}
	acct, ip := s.accountKey("login", email), s.ipKey(m.IP)
	if err := s.checkThrottle(ctx, acct, ip); err != nil {
		return Grant{}, err
	}
	u, found, err := s.lookupUser(ctx, email)
	if err != nil {
		return Grant{}, err
	}
	ok, rehash := s.verifyPassword(u, found, password)
	if !ok {
		e := audit.Entry{Action: "auth.login_failed", TargetType: "account"}
		if found {
			e.TargetType, e.TargetID = "user", u.ID.String()
		}
		if err := s.recordFailure(ctx, anonymous, m, []throttleKey{{acct, "account", domain.AccountThreshold}, {ip, "ip", domain.IPThreshold}}, e); err != nil {
			return Grant{}, err
		}
		return Grant{}, ErrInvalidCredentials
	}

	privileged, err := s.requiresMFA(ctx, u.ID, m)
	if err != nil {
		return Grant{}, err
	}
	state := domain.StateAfterPassword(privileged, u.TOTPConfirmedAt != nil)

	var newHash string
	if rehash {
		if newHash, err = s.cfg.Passwords.Hash(password); err != nil {
			return Grant{}, err
		}
	}
	var grant Grant
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if newHash != "" {
			if err := s.cfg.Repo.SetPassword(ctx, tx, u.ID, newHash, s.now()); err != nil {
				return err
			}
		}
		if err := s.clearThrottle(ctx, tx, acct, "account"); err != nil {
			return err
		}
		var err error
		if grant, err = s.issueSession(ctx, tx, u, state, "password", nil, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.login", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success,
			Metadata: map[string]any{"state": string(state), "rehashed": newHash != ""}})
	})
	return grant, err
}

// requiresMFA reports whether any active membership of the user requires
// MFA (Owner or Workspace Administrator).
func (s *Service) requiresMFA(ctx context.Context, user uuid.UUID, m RequestMeta) (bool, error) {
	var roles []string
	err := s.cfg.Store.Read(ctx, s.systemScope(userActor(user), m), func(ctx context.Context, q db.Querier) error {
		var err error
		roles, err = s.cfg.Repo.ActiveRoles(ctx, q, user)
		return err
	})
	for _, r := range roles {
		if domain.RoleRequiresMFA(r) {
			return true, err
		}
	}
	return false, err
}

// Authenticate resolves a session cookie. Every failure is
// ErrUnauthenticated.
func (s *Service) Authenticate(ctx context.Context, token secret.Value, m RequestMeta) (Current, error) {
	lookup, err := crypto.LookupID(crypto.TokenSession, token)
	if err != nil {
		return Current{}, ErrUnauthenticated
	}
	var rec SessionRecord
	var u User
	err = s.cfg.Store.Read(ctx, s.systemScope(anonymous, m), func(ctx context.Context, q db.Querier) error {
		var err error
		if rec, err = s.cfg.Repo.SessionByLookup(ctx, q, lookup); err != nil {
			return err
		}
		u, err = s.cfg.Repo.UserByID(ctx, q, rec.UserID)
		return err
	})
	if errors.Is(err, db.ErrNotFound) {
		return Current{}, ErrUnauthenticated
	}
	if err != nil {
		return Current{}, err
	}
	now := s.now()
	if s.cfg.Tokens.Verify(crypto.TokenSession, token, crypto.TokenRecord{
		Type: crypto.TokenSession.Name, LookupID: rec.LookupID, Verifier: rec.Verifier, KeyVersion: rec.KeyVersion,
	}) != nil || rec.Lifetime.Check(now) != nil || !u.Active {
		return Current{}, ErrUnauthenticated
	}
	if rec.Lifetime.Touch(now) {
		if err := s.touch(ctx, rec); err != nil {
			return Current{}, err
		}
	}
	// Roles change while sessions live: re-check the MFA requirement on
	// every request for sessions that never completed MFA.
	if rec.Lifetime.State == domain.StateActive && rec.MFAVerifiedAt == nil {
		privileged, err := s.requiresMFA(ctx, u.ID, m)
		if err != nil {
			return Current{}, err
		}
		rec.Lifetime.State = domain.EffectiveState(rec.Lifetime.State, false, privileged, u.TOTPConfirmedAt != nil)
	}
	return Current{
		SessionID: rec.ID, View: s.view(u, rec.Lifetime),
		RecentMFA: domain.RecentMFA(rec.MFAVerifiedAt, now), mfaVerifiedAt: rec.MFAVerifiedAt,
		csrf: rec.CSRFVerifier, csrfToken: secret.New(s.csrfFor(token)),
	}, nil
}

// CheckCSRF compares a request's CSRF token with the session's verifier.
func (s *Service) CheckCSRF(c Current, token string) bool {
	if token == "" || len(c.csrf) == 0 {
		return false
	}
	return hmac.Equal(s.cfg.Tokens.Digest("csrf", []byte(token)), c.csrf)
}

func totpContext(user uuid.UUID) crypto.Context {
	return crypto.Context{WorkspaceID: installationScope, OwnerType: "user", OwnerID: user.String(), SecretType: "totp_secret", SchemaVersion: 1}
}

// installationDEK returns the installation DEK, creating it on first use.
func (s *Service) installationDEK(ctx context.Context, q db.Querier) (crypto.WrappedDEK, error) {
	dek, err := s.cfg.Repo.DEK(ctx, q, installationScope)
	if err == nil {
		return dek, nil
	}
	if !errors.Is(err, db.ErrNotFound) {
		return crypto.WrappedDEK{}, err
	}
	fresh, err := s.cfg.Keyring.NewDEK(installationScope)
	if err != nil {
		return crypto.WrappedDEK{}, err
	}
	if err := s.cfg.Repo.InsertDEK(ctx, q, installationScope, fresh, s.now()); err != nil {
		return crypto.WrappedDEK{}, err
	}
	return s.cfg.Repo.DEK(ctx, q, installationScope)
}

func (s *Service) totpSecret(ctx context.Context, q db.Querier, u User) ([]byte, error) {
	if u.TOTP == nil {
		return nil, ErrEnrollmentNotStarted
	}
	dek, err := s.cfg.Repo.DEK(ctx, q, installationScope)
	if err != nil {
		return nil, err
	}
	plain, err := s.cfg.Keyring.Open(dek, totpContext(u.ID), *u.TOTP)
	if err != nil {
		return nil, err
	}
	return plain.Expose(), nil
}

// verifyTOTP checks a code against the user's secret and stored last step.
func (s *Service) verifyTOTP(ctx context.Context, u User, code string, m RequestMeta) (int64, error) {
	var secretBytes []byte
	err := s.cfg.Store.Read(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, q db.Querier) error {
		var err error
		secretBytes, err = s.totpSecret(ctx, q, u)
		return err
	})
	if err != nil {
		return 0, err
	}
	defer clear(secretBytes)
	step, ok := domain.VerifyTOTP(secretBytes, code, s.now(), u.TOTPLastStep)
	if !ok {
		return 0, ErrInvalidCode
	}
	return step, nil
}

func (s *Service) user(ctx context.Context, id uuid.UUID) (User, error) {
	var u User
	err := s.cfg.Store.Read(ctx, s.systemScope(userActor(id), RequestMeta{}), func(ctx context.Context, q db.Querier) error {
		var err error
		u, err = s.cfg.Repo.UserByID(ctx, q, id)
		return err
	})
	return u, err
}

// mfaFailure audits a wrong TOTP code; reserveMFAAttempt already counted it.
func (s *Service) mfaFailure(ctx context.Context, u User, m RequestMeta, action string) error {
	err := s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		return tx.Audit(ctx, audit.Entry{Action: action, TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Failure})
	})
	if err != nil {
		return err
	}
	return ErrInvalidCode
}

// rotate replaces the current session with a new one in the given state.
func (s *Service) rotate(ctx context.Context, tx *db.WriteTx, c Current, u User, state domain.SessionState, m RequestMeta) (Grant, error) {
	now := s.now()
	if err := s.cfg.Repo.RevokeSession(ctx, tx, c.SessionID, domain.RevokeRotated, now); err != nil {
		return Grant{}, err
	}
	var mfaAt *time.Time
	if state == domain.StateActive && u.TOTPConfirmedAt != nil {
		mfaAt = &now
	}
	return s.issueSession(ctx, tx, u, state, "password", mfaAt, m)
}

// CompleteMFAChallenge activates an mfa_challenge session with a TOTP code.
func (s *Service) CompleteMFAChallenge(ctx context.Context, c Current, code string, m RequestMeta) (Grant, error) {
	if c.View.State != domain.StateMFAChallenge {
		return Grant{}, ErrUnauthenticated
	}
	key, err := s.reserveMFAAttempt(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, err
	}
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, err
	}
	step, err := s.verifyTOTP(ctx, u, code, m)
	if errors.Is(err, ErrInvalidCode) {
		return Grant{}, s.mfaFailure(ctx, u, m, "auth.mfa_challenge_failed")
	}
	if err != nil {
		return Grant{}, err
	}
	var grant Grant
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if advanced, err := s.cfg.Repo.AdvanceTOTPStep(ctx, tx, u.ID, step); err != nil {
			return err
		} else if !advanced {
			return ErrInvalidCode // a concurrent request used this code
		}
		if err := s.clearThrottle(ctx, tx, key, "account"); err != nil {
			return err
		}
		var err error
		if grant, err = s.rotate(ctx, tx, c, u, domain.StateActive, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.mfa_challenge", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	return grant, err
}

// StepUp verifies a TOTP code for a sensitive action, records recent MFA,
// and rotates the session (RBAC.md: session IDs rotate on step-up).
func (s *Service) StepUp(ctx context.Context, c Current, code string, m RequestMeta) (Grant, error) {
	key, err := s.reserveMFAAttempt(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, err
	}
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, err
	}
	if u.TOTPConfirmedAt == nil {
		return Grant{}, ErrEnrollmentNotStarted
	}
	step, err := s.verifyTOTP(ctx, u, code, m)
	if errors.Is(err, ErrInvalidCode) {
		return Grant{}, s.mfaFailure(ctx, u, m, "auth.mfa_step_up_failed")
	}
	if err != nil {
		return Grant{}, err
	}
	var grant Grant
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if advanced, err := s.cfg.Repo.AdvanceTOTPStep(ctx, tx, u.ID, step); err != nil {
			return err
		} else if !advanced {
			return ErrInvalidCode
		}
		if err := s.clearThrottle(ctx, tx, key, "account"); err != nil {
			return err
		}
		var err error
		if grant, err = s.rotate(ctx, tx, c, u, domain.StateActive, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.mfa_step_up", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	return grant, err
}

// BeginTOTPEnrollment stores a new unconfirmed secret and returns it once.
func (s *Service) BeginTOTPEnrollment(ctx context.Context, c Current, m RequestMeta) (TOTPEnrollment, error) {
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	if u.TOTPConfirmedAt != nil {
		return TOTPEnrollment{}, ErrAlreadyEnrolled
	}
	raw := domain.NewTOTPSecret()
	defer clear(raw)
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		dek, err := s.installationDEK(ctx, tx)
		if err != nil {
			return err
		}
		sealed, err := s.cfg.Keyring.Seal(dek, totpContext(u.ID), secret.New(raw))
		if err != nil {
			return err
		}
		if err := s.cfg.Repo.SetTOTPSecret(ctx, tx, u.ID, dek.ID, sealed, s.now()); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.mfa_enroll_start", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{Secret: domain.EncodeTOTPSecret(raw), URI: domain.TOTPURI(s.cfg.Issuer, u.Email, raw)}, nil
}

// newRecoveryCodes generates a set and its hashes.
func (s *Service) newRecoveryCodes() ([]string, []RecoveryRecord, error) {
	codes := domain.NewRecoveryCodes()
	display := make([]string, 0, len(codes))
	records := make([]RecoveryRecord, 0, len(codes))
	for _, c := range codes {
		hash, err := s.cfg.Passwords.Hash(secret.New([]byte(c.Secret)))
		if err != nil {
			return nil, nil, err
		}
		id, err := s.cfg.NewID()
		if err != nil {
			return nil, nil, err
		}
		display = append(display, c.Display)
		records = append(records, RecoveryRecord{ID: id, Lookup: c.Lookup, Hash: hash})
	}
	return display, records, nil
}

// ConfirmTOTPEnrollment enables TOTP, rotates the session to active, and
// returns recovery codes once.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, c Current, code string, m RequestMeta) (Grant, []string, error) {
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, nil, err
	}
	if u.TOTPConfirmedAt != nil {
		return Grant{}, nil, ErrAlreadyEnrolled
	}
	key, err := s.reserveMFAAttempt(ctx, u.ID)
	if err != nil {
		return Grant{}, nil, err
	}
	step, err := s.verifyTOTP(ctx, u, code, m)
	if errors.Is(err, ErrInvalidCode) {
		return Grant{}, nil, s.mfaFailure(ctx, u, m, "auth.mfa_enroll_failed")
	}
	if err != nil {
		return Grant{}, nil, err
	}
	display, records, err := s.newRecoveryCodes()
	if err != nil {
		return Grant{}, nil, err
	}
	var grant Grant
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		if confirmed, err := s.cfg.Repo.ConfirmTOTP(ctx, tx, u.ID, step, now); err != nil {
			return err
		} else if !confirmed {
			return ErrAlreadyEnrolled
		}
		if err := s.cfg.Repo.ReplaceRecoveryCodes(ctx, tx, u.ID, records, now); err != nil {
			return err
		}
		if err := s.clearThrottle(ctx, tx, key, "account"); err != nil {
			return err
		}
		u.TOTPConfirmedAt = &now
		var err error
		if grant, err = s.rotate(ctx, tx, c, u, domain.StateActive, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.mfa_enroll", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	if err != nil {
		return Grant{}, nil, err
	}
	return grant, display, nil
}

// RegenerateRecoveryCodes replaces the user's codes after a TOTP check.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, c Current, code string, m RequestMeta) ([]string, error) {
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return nil, err
	}
	if u.TOTPConfirmedAt == nil {
		return nil, ErrEnrollmentNotStarted
	}
	key, err := s.reserveMFAAttempt(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	step, err := s.verifyTOTP(ctx, u, code, m)
	if errors.Is(err, ErrInvalidCode) {
		return nil, s.mfaFailure(ctx, u, m, "auth.recovery_codes_failed")
	}
	if err != nil {
		return nil, err
	}
	display, records, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if advanced, err := s.cfg.Repo.AdvanceTOTPStep(ctx, tx, u.ID, step); err != nil {
			return err
		} else if !advanced {
			return ErrInvalidCode
		}
		if err := s.cfg.Repo.ReplaceRecoveryCodes(ctx, tx, u.ID, records, s.now()); err != nil {
			return err
		}
		if err := s.clearThrottle(ctx, tx, key, "account"); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.recovery_codes_regenerated", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	if err != nil {
		return nil, err
	}
	return display, nil
}

// ChangePassword requires the current password, revokes every other
// session, and rotates the current one.
func (s *Service) ChangePassword(ctx context.Context, c Current, current, next secret.Value, m RequestMeta) (Grant, error) {
	key := s.accountKey("password-change", c.View.UserID.String())
	if err := s.checkThrottle(ctx, key); err != nil {
		return Grant{}, err
	}
	u, err := s.user(ctx, c.View.UserID)
	if err != nil {
		return Grant{}, err
	}
	if ok, _ := s.verifyPassword(u, true, current); !ok {
		if err := s.recordFailure(ctx, userActor(u.ID), m, []throttleKey{{key, "account", domain.AccountThreshold}},
			audit.Entry{Action: "auth.password_change_failed", TargetType: "user", TargetID: u.ID.String()}); err != nil {
			return Grant{}, err
		}
		return Grant{}, ErrInvalidCredentials
	}
	nextPlain := next.Expose()
	defer clear(nextPlain)
	if err := domain.ValidatePassword(string(nextPlain), u.Email); err != nil {
		return Grant{}, err
	}
	hash, err := s.cfg.Passwords.Hash(next)
	if err != nil {
		return Grant{}, err
	}
	var grant Grant
	err = s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		if err := s.cfg.Repo.SetPassword(ctx, tx, u.ID, hash, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.RevokeUserSessions(ctx, tx, u.ID, domain.RevokePasswordChanged, now); err != nil {
			return err
		}
		var err error
		// The new session keeps the old one's MFA time: a password is not
		// strong authentication and must not refresh recent MFA.
		if grant, err = s.issueSession(ctx, tx, u, domain.StateActive, "password", c.mfaVerifiedAt, m); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.password_change", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	return grant, err
}

// Logout revokes the current session.
func (s *Service) Logout(ctx context.Context, c Current, m RequestMeta) error {
	return s.cfg.Store.Write(ctx, s.systemScope(userActor(c.View.UserID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.cfg.Repo.RevokeSession(ctx, tx, c.SessionID, domain.RevokeLogout, s.now()); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.logout", TargetType: "user", TargetID: c.View.UserID.String(), Outcome: audit.Success})
	})
}

// LogoutAll revokes every session of the current user.
func (s *Service) LogoutAll(ctx context.Context, c Current, m RequestMeta) error {
	return s.cfg.Store.Write(ctx, s.systemScope(userActor(c.View.UserID), m), func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.cfg.Repo.RevokeUserSessions(ctx, tx, c.View.UserID, domain.RevokeLogoutAll, s.now()); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.logout_all", TargetType: "user", TargetID: c.View.UserID.String(), Outcome: audit.Success})
	})
}

// Recover sets a new password with a single-use recovery code and revokes
// every session.
func (s *Service) Recover(ctx context.Context, rawEmail, code string, newPassword secret.Value, m RequestMeta) error {
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		email = strings.ToLower(strings.TrimSpace(rawEmail))
	}
	plain := newPassword.Expose()
	defer clear(plain)
	if err := domain.ValidatePassword(string(plain), email); err != nil {
		return err
	}
	acct, ip := s.accountKey("recovery", email), s.ipKey(m.IP)
	if err := s.checkThrottle(ctx, acct, ip); err != nil {
		return err
	}
	u, found, err := s.lookupUser(ctx, email)
	if err != nil {
		return err
	}
	lookup, codeSecret, parseErr := domain.ParseRecoveryCode(code)
	var rec RecoveryRecord
	if found && parseErr == nil {
		err = s.cfg.Store.Read(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, q db.Querier) error {
			var err error
			rec, err = s.cfg.Repo.LiveRecoveryCode(ctx, q, u.ID, lookup)
			return err
		})
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return err
		}
	}
	ok := false
	if rec.Hash != "" {
		ok, _, _ = s.cfg.Passwords.Verify(secret.New([]byte(codeSecret)), rec.Hash)
	} else {
		_, _, _ = s.cfg.Passwords.Verify(secret.New([]byte(codeSecret)), s.dummyHash)
	}
	if !ok {
		e := audit.Entry{Action: "auth.recovery_failed", TargetType: "account"}
		if found {
			e.TargetType, e.TargetID = "user", u.ID.String()
		}
		if err := s.recordFailure(ctx, anonymous, m, []throttleKey{{acct, "account", domain.AccountThreshold}, {ip, "ip", domain.IPThreshold}}, e); err != nil {
			return err
		}
		return ErrInvalidCredentials
	}
	hash, err := s.cfg.Passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	return s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		if used, err := s.cfg.Repo.UseRecoveryCode(ctx, tx, rec.ID, now); err != nil {
			return err
		} else if !used {
			return ErrInvalidCredentials // a concurrent request used it
		}
		if err := s.cfg.Repo.SetPassword(ctx, tx, u.ID, hash, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.RevokeUserSessions(ctx, tx, u.ID, domain.RevokeRecovered, now); err != nil {
			return err
		}
		if err := s.clearThrottle(ctx, tx, acct, "account"); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.recovery_used", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
}

// IssuePasswordReset creates a single-use reset token for an operator to
// hand over out of band. The token is returned once.
func (s *Service) IssuePasswordReset(ctx context.Context, rawEmail, operator string) (secret.Value, time.Time, error) {
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	u, found, err := s.lookupUser(ctx, email)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	if !found {
		return secret.Value{}, time.Time{}, ErrUnknownAccount
	}
	raw, rec, err := s.cfg.Tokens.Issue(crypto.TokenPasswordReset)
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	id, err := s.cfg.NewID()
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	now := s.now()
	expires := now.Add(resetLifetime)
	actor := audit.Actor{Type: audit.ActorOperator, ID: operator}
	err = s.cfg.Store.Write(ctx, s.systemScope(actor, RequestMeta{}), func(ctx context.Context, tx *db.WriteTx) error {
		if err := s.cfg.Repo.InsertPasswordReset(ctx, tx, PasswordReset{
			ID: id, UserID: u.ID, LookupID: rec.LookupID, Verifier: rec.Verifier, KeyVersion: rec.KeyVersion,
			CreatedAt: now, ExpiresAt: expires,
		}); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.password_reset_issued", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
	if err != nil {
		return secret.Value{}, time.Time{}, err
	}
	return raw, expires, nil
}

// RedeemPasswordReset sets a new password with an operator-issued token and
// revokes every session.
func (s *Service) RedeemPasswordReset(ctx context.Context, token, newPassword secret.Value, m RequestMeta) error {
	ip := s.ipKey(m.IP)
	if err := s.checkThrottle(ctx, ip); err != nil {
		return err
	}
	fail := func(target string) error {
		if err := s.recordFailure(ctx, anonymous, m, []throttleKey{{ip, "ip", domain.IPThreshold}},
			audit.Entry{Action: "auth.password_reset_failed", TargetType: "user", TargetID: target}); err != nil {
			return err
		}
		return ErrInvalidToken
	}
	lookup, err := crypto.LookupID(crypto.TokenPasswordReset, token)
	if err != nil {
		return fail("")
	}
	var reset PasswordReset
	var u User
	err = s.cfg.Store.Read(ctx, s.systemScope(anonymous, m), func(ctx context.Context, q db.Querier) error {
		var err error
		if reset, err = s.cfg.Repo.PasswordResetByLookup(ctx, q, lookup); err != nil {
			return err
		}
		u, err = s.cfg.Repo.UserByID(ctx, q, reset.UserID)
		return err
	})
	if errors.Is(err, db.ErrNotFound) {
		return fail("")
	}
	if err != nil {
		return err
	}
	valid := s.cfg.Tokens.Verify(crypto.TokenPasswordReset, token, crypto.TokenRecord{
		Type: crypto.TokenPasswordReset.Name, LookupID: lookup, Verifier: reset.Verifier, KeyVersion: reset.KeyVersion,
	}) == nil
	if !valid || reset.UsedAt != nil || !s.now().Before(reset.ExpiresAt) || !u.Active {
		return fail(u.ID.String())
	}
	plain := newPassword.Expose()
	defer clear(plain)
	if err := domain.ValidatePassword(string(plain), u.Email); err != nil {
		return err
	}
	hash, err := s.cfg.Passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	return s.cfg.Store.Write(ctx, s.systemScope(userActor(u.ID), m), func(ctx context.Context, tx *db.WriteTx) error {
		now := s.now()
		if used, err := s.cfg.Repo.UsePasswordReset(ctx, tx, reset.ID, now); err != nil {
			return err
		} else if !used {
			return ErrInvalidToken
		}
		if err := s.cfg.Repo.SetPassword(ctx, tx, u.ID, hash, now); err != nil {
			return err
		}
		if err := s.cfg.Repo.RevokeUserSessions(ctx, tx, u.ID, domain.RevokeRecovered, now); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "auth.password_reset", TargetType: "user", TargetID: u.ID.String(), Outcome: audit.Success})
	})
}
