//go:build integration

package integration_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/secret"
)

func TestLoginRequiresTOTPForEnrolledOwner(t *testing.T) {
	s := newAuthServer(t)
	_, secretB32, _ := s.enrolledOwner()

	c := s.client()
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "OWNER@example.org", "password": ownerPassword})
	expect(t, r, http.StatusOK)
	if r.state() != "mfa_challenge" {
		t.Fatalf("state = %s, want mfa_challenge", r.state())
	}
	// A pre-MFA session cannot reach active-only operations.
	if got := c.do(http.MethodPost, "/api/v1/auth/logout-all", nil); got.status != http.StatusForbidden || got.code() != "mfa_required" {
		t.Fatalf("pre-MFA access: %d %s", got.status, got.raw)
	}
	bad := c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": "000000"})
	if bad.status != http.StatusUnauthorized || bad.code() != "invalid_code" {
		t.Fatalf("wrong code: %d %s", bad.status, bad.raw)
	}
	code := s.totpCode(secretB32)
	ok := c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": code})
	expect(t, ok, http.StatusOK)
	if ok.state() != "active" {
		t.Fatalf("state after challenge = %s", ok.state())
	}

	// The same code cannot complete another login (TOTP replay, AC-02).
	other := s.client()
	expect(t, other.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}), http.StatusOK)
	replay := other.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": code})
	if replay.status != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP code accepted: %d %s", replay.status, replay.raw)
	}
}

// TestLoginErrorsDoNotRevealAccounts proves MVP-04.AC-07.
func TestLoginErrorsDoNotRevealAccounts(t *testing.T) {
	s := newAuthServer(t)
	s.enrolledOwner()

	known := s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": "wrong password value"})
	unknown := s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "nobody@example.org", "password": "wrong password value"})
	malformed := s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "not an email", "password": "wrong password value"})
	for name, r := range map[string]response{"known": known, "unknown": unknown, "malformed": malformed} {
		if r.status != http.StatusUnauthorized || r.code() != "invalid_credentials" {
			t.Fatalf("%s account: %d %s", name, r.status, r.raw)
		}
		r.body["requestId"] = nil
		r.body["title"] = nil
	}
	if strip(known.raw) != strip(unknown.raw) {
		t.Fatalf("responses differ:\n%s\n%s", known.raw, unknown.raw)
	}
}

func strip(raw string) string {
	i := strings.Index(raw, `"requestId"`)
	if i < 0 {
		return raw
	}
	j := strings.Index(raw[i:], ",")
	if j < 0 {
		return raw[:i]
	}
	return raw[:i] + raw[i+j+1:]
}

// TestThrottlingIsIdenticalForKnownAndUnknownAccounts proves MVP-04.AC-05
// and the throttling half of AC-07.
func TestThrottlingIsIdenticalForKnownAndUnknownAccounts(t *testing.T) {
	s := newAuthServer(t)
	s.enrolledOwner()
	attempt := func(email, password string) response {
		return s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": email, "password": password})
	}
	for _, email := range []string{"owner@example.org", "ghost@example.org"} {
		for i := range 5 {
			if r := attempt(email, "wrong password value"); r.status != http.StatusUnauthorized {
				t.Fatalf("%s attempt %d: %d", email, i+1, r.status)
			}
		}
		r := attempt(email, "wrong password value")
		if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") != "1" || r.code() != "too_many_attempts" {
			t.Fatalf("%s sixth attempt: %d Retry-After %q %s", email, r.status, r.header.Get("Retry-After"), r.raw)
		}
	}
	// Even the right password waits while throttled, then works.
	if r := attempt("owner@example.org", ownerPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("correct password during throttle: %d", r.status)
	}
	s.clock.Advance(2 * time.Second)
	if r := attempt("owner@example.org", ownerPassword); r.status != http.StatusOK {
		t.Fatalf("after the delay: %d %s", r.status, r.raw)
	}
	// Success reset the account counter.
	if r := attempt("owner@example.org", "wrong password value"); r.status != http.StatusUnauthorized {
		t.Fatalf("after success the first failure must not be throttled: %d", r.status)
	}
}

// TestAuthenticationEventsAreAudited proves MVP-04.AC-13.
func TestAuthenticationEventsAreAudited(t *testing.T) {
	s := newAuthServer(t)
	c, secretB32, _ := s.enrolledOwner()
	expect(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
	s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": "wrong password value"})
	s.login("owner@example.org", ownerPassword, secretB32)

	rows, err := connect(t, s.db.admin).Query(t.Context(), "SELECT action, actor_type, coalesce(actor_id, ''), metadata::text FROM qali.audit_events ORDER BY seq")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action, actorType, actorID, md string
		if err := rows.Scan(&action, &actorType, &actorID, &md); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
		if strings.Contains(md, ownerPassword) || strings.Contains(md, secretB32) {
			t.Fatalf("audit metadata leaks a secret: %s", md)
		}
		if action == "auth.login" && (actorType != "user" || actorID == "") {
			t.Fatalf("login not attributed: %s %s", actorType, actorID)
		}
	}
	want := []string{"auth.setup_token_issued", "auth.bootstrap", "auth.mfa_enroll_start", "auth.mfa_enroll", "auth.logout", "auth.login_failed", "auth.login", "auth.mfa_challenge"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions = %v\nwant %v", actions, want)
	}
}

// TestPasswordRehashOnLogin proves the rehash part of MVP-04.AC-01.
func TestPasswordRehashOnLogin(t *testing.T) {
	s := newAuthServer(t)
	_, secretB32, _ := s.enrolledOwner()
	weak, err := crypto.NewPasswords(s.passwordPepper, crypto.MinPasswordParams)
	if err != nil {
		t.Fatal(err)
	}
	old, err := weak.Hash(secret.New([]byte(ownerPassword)))
	if err != nil {
		t.Fatal(err)
	}
	admin := connect(t, s.db.admin)
	if _, err := admin.Exec(t.Context(), "UPDATE qali.users SET password_hash = $1", old); err != nil {
		t.Fatal(err)
	}
	s.login("owner@example.org", ownerPassword, secretB32)
	var hash string
	if err := admin.QueryRow(t.Context(), "SELECT password_hash FROM qali.users").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == old || !strings.Contains(hash, "m=19456,t=3,p=1") {
		t.Fatalf("hash was not upgraded on login: %s", hash)
	}
	s.login("owner@example.org", ownerPassword, secretB32) // the upgraded hash still verifies
}
