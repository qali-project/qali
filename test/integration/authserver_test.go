//go:build integration

package integration_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/assembly"
	"github.com/qali-project/qali/internal/identity/adapter/httpapi"
	"github.com/qali-project/qali/internal/identity/adapter/postgres"
	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
	"github.com/qali-project/qali/internal/platform/secret"
	workspacehttp "github.com/qali-project/qali/internal/workspace/adapter/httpapi"
	workspacepg "github.com/qali-project/qali/internal/workspace/adapter/postgres"
	workspaceapp "github.com/qali-project/qali/internal/workspace/app"
)

const ownerPassword = "correct horse battery staple"

// authServer is the real router with the identity module over a real
// database. Clients are cookie-jar HTTP clients, as a browser would be.
type authServer struct {
	t      *testing.T
	db     testDatabase
	store  *db.Store
	svc    *app.Service
	clock  *clock.Manual
	srv    *httptest.Server
	logs   *bytes.Buffer
	logsMu *sync.Mutex
	// passwordPepper lets tests create hashes with other parameters.
	passwordPepper secret.Value
}

// serverPasswordParams are slightly above the minimum so tests can store
// weaker hashes and observe the upgrade on login.
var serverPasswordParams = crypto.PasswordParams{MemoryKiB: crypto.MinPasswordParams.MemoryKiB, Time: 3, Threads: 1}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func key32(t *testing.T) secret.Value {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return secret.New(b)
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	d := migratedDatabase(t)
	c := clock.NewManual(time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC))
	store, err := db.Open(t.Context(), d.app, db.Options{Clock: c})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	keyring, err := crypto.NewKeyring(1, map[uint32]secret.Value{1: key32(t)})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := crypto.NewTokens(1, map[uint32]secret.Value{1: key32(t)})
	if err != nil {
		t.Fatal(err)
	}
	passwordPepper := key32(t)
	passwords, err := crypto.NewPasswords(passwordPepper, serverPasswordParams)
	if err != nil {
		t.Fatal(err)
	}
	svc := app.New(app.Config{
		Store: store, Repo: postgres.Repository{}, Passwords: passwords, Tokens: tokens, Keyring: keyring,
		Clock: c, NewID: uuid.NewV7, Issuer: "Qali",
	})
	logs, mu := &bytes.Buffer{}, &sync.Mutex{}
	logger := slog.New(slog.NewJSONHandler(lockedWriter{mu: mu, buf: logs}, nil))
	public, _ := url.Parse("https://qali.example.org")
	handler := httpapi.New(svc, logger)
	workspaces := workspaceapp.New(workspaceapp.Config{
		Store: store, Repo: workspacepg.Repository{}, Accounts: svc, Tokens: tokens, Clock: c, NewID: uuid.NewV7,
	})
	srv := httptest.NewServer(httpserver.NewHandler(httpserver.Options{
		PublicURL:      public,
		Clock:          c,
		Logger:         logger,
		RateLimit:      httpserver.RateLimit{PerSecond: 1000, Burst: 1000},
		API:            assembly.API(handler, workspacehttp.New(workspaces, logger, httpapi.WriteSession)),
		APIMiddlewares: []openapi.MiddlewareFunc{handler.Authenticate},
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		if t.Failed() {
			mu.Lock()
			defer mu.Unlock()
			t.Logf("server logs:\n%s", logs.String())
		}
	})
	return &authServer{t: t, db: d, store: store, svc: svc, clock: c, srv: srv, logs: logs, logsMu: mu, passwordPepper: passwordPepper}
}

// client is one browser.
type client struct {
	s    *authServer
	http *http.Client
	csrf string
	// extra headers for the next request (doWith).
	extra map[string]string
}

func (s *authServer) client() *client {
	jar, _ := cookiejar.New(nil)
	// The cookie is Secure; the test server is plain HTTP, so the jar is
	// told the origin is HTTPS by rewriting cookies in do().
	return &client{s: s, http: &http.Client{Jar: jar}}
}

type response struct {
	status int
	body   map[string]any
	raw    string
	header http.Header
}

func (c *client) do(method, path string, body any) response {
	c.s.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.s.t.Fatal(err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(c.s.t.Context(), method, c.s.srv.URL+path, r)
	if err != nil {
		c.s.t.Fatal(err)
	}
	req.Header.Set("Origin", "https://qali.example.org")
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range c.extra {
		req.Header.Set(k, v)
	}
	u, _ := url.Parse(c.s.srv.URL)
	for _, ck := range c.http.Jar.Cookies(&url.URL{Scheme: "https", Host: u.Host}) {
		req.AddCookie(ck)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.s.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if cookies := res.Cookies(); len(cookies) > 0 {
		c.http.Jar.SetCookies(&url.URL{Scheme: "https", Host: u.Host}, cookies)
	}
	out := response{status: res.StatusCode, raw: string(raw), header: res.Header}
	_ = json.Unmarshal(raw, &out.body)
	if token, ok := out.body["csrfToken"].(string); ok {
		c.csrf = token
	}
	if sess, ok := out.body["session"].(map[string]any); ok {
		if token, ok := sess["csrfToken"].(string); ok {
			c.csrf = token
		}
	}
	return out
}

func (c *client) cookie() string {
	u, _ := url.Parse(c.s.srv.URL)
	for _, ck := range c.http.Jar.Cookies(&url.URL{Scheme: "https", Host: u.Host}) {
		if ck.Name == "__Host-qali_session" {
			return ck.Value
		}
	}
	return ""
}

func (r response) code() string {
	if c, ok := r.body["code"].(string); ok {
		return c
	}
	return ""
}

func (r response) state() string {
	if s, ok := r.body["state"].(string); ok {
		return s
	}
	if sess, ok := r.body["session"].(map[string]any); ok {
		s, _ := sess["state"].(string)
		return s
	}
	return ""
}

func expect(t *testing.T, r response, status int) {
	t.Helper()
	if r.status != status {
		t.Fatalf("status = %d, want %d: %s", r.status, status, r.raw)
	}
}

// setupToken issues a one-time setup token as the operator CLI would.
func (s *authServer) setupToken() string {
	s.t.Helper()
	token, _, err := s.svc.IssueSetupToken(s.t.Context(), "test")
	if err != nil {
		s.t.Fatal(err)
	}
	return string(token.Expose())
}

func (s *authServer) bootstrapBody(email string) map[string]any {
	s.t.Helper()
	return map[string]any{"email": email, "displayName": "Owner", "password": ownerPassword, "workspaceName": "Acme QA", "setupToken": s.setupToken()}
}

// totpCode computes the current code from a base32 secret with the server's
// clock.
func (s *authServer) totpCode(secretB32 string) string {
	s.t.Helper()
	raw, err := decodeBase32(secretB32)
	if err != nil {
		s.t.Fatal(err)
	}
	return domain.TOTPCode(raw, domain.TOTPStep(s.clock.Now()))
}

// enrolledOwner bootstraps, enrolls TOTP, and returns the client, the TOTP
// secret, and the recovery codes.
func (s *authServer) enrolledOwner() (*client, string, []string) {
	s.t.Helper()
	c := s.client()
	expect(s.t, c.do(http.MethodPost, "/api/v1/setup/owner", s.bootstrapBody("owner@example.org")), http.StatusCreated)
	begin := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
	expect(s.t, begin, http.StatusOK)
	secretB32 := begin.body["secret"].(string)
	confirm := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": s.totpCode(secretB32)})
	expect(s.t, confirm, http.StatusOK)
	var codes []string
	for _, v := range confirm.body["recoveryCodes"].([]any) {
		codes = append(codes, v.(string))
	}
	s.clock.Advance(31 * time.Second) // the next code uses a new step
	return c, secretB32, codes
}

// login signs in with password and, when challenged, TOTP.
func (s *authServer) login(email, password, secretB32 string) *client {
	s.t.Helper()
	c := s.client()
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": email, "password": password})
	expect(s.t, r, http.StatusOK)
	if r.state() == "mfa_challenge" {
		expect(s.t, c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": s.totpCode(secretB32)}), http.StatusOK)
		s.clock.Advance(31 * time.Second)
	}
	return c
}

func (s *authServer) logText() string {
	s.logsMu.Lock()
	defer s.logsMu.Unlock()
	return s.logs.String()
}

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func decodeBase32(s string) ([]byte, error) {
	return base32NoPad.DecodeString(strings.ToUpper(s))
}
