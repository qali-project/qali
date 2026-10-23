//go:build integration

package integration_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/app"
	"github.com/qali-project/qali/internal/platform/secret"
)

func TestEnrollmentStateErrors(t *testing.T) {
	s := newAuthServer(t)
	c := s.client()
	expect(t, c.do(http.MethodPost, "/api/v1/setup/owner", s.bootstrapBody("owner@example.org")), http.StatusCreated)

	if r := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": "123456"}); r.status != http.StatusConflict || r.code() != "enrollment_not_started" {
		t.Fatalf("confirm before begin: %d %s", r.status, r.raw)
	}
	begin := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
	secretB32 := begin.body["secret"].(string)
	if r := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": "000000"}); r.status != http.StatusUnauthorized || r.code() != "invalid_code" {
		t.Fatalf("wrong enrollment code: %d %s", r.status, r.raw)
	}
	expect(t, c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": s.totpCode(secretB32)}), http.StatusOK)
	if r := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil); r.status != http.StatusConflict || r.code() != "already_enrolled" {
		t.Fatalf("re-enrollment: %d %s", r.status, r.raw)
	}
	if r := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": s.totpCode(secretB32)}); r.status != http.StatusConflict {
		t.Fatalf("second confirmation: %d %s", r.status, r.raw)
	}
}

func TestTOTPGuessingIsThrottled(t *testing.T) {
	s := newAuthServer(t)
	_, secretB32, _ := s.enrolledOwner()
	c := s.client()
	expect(t, c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}), http.StatusOK)
	for range 5 {
		if r := c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": "000000"}); r.status != http.StatusUnauthorized {
			t.Fatalf("wrong code: %d", r.status)
		}
	}
	if r := c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": s.totpCode(secretB32)}); r.status != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt, even with the right code: %d %s", r.status, r.raw)
	}
	s.clock.Advance(2 * time.Second)
	expect(t, c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": s.totpCode(secretB32)}), http.StatusOK)
}

func TestTamperedOrMalformedCookiesAreRejected(t *testing.T) {
	s := newAuthServer(t)
	owner, _, _ := s.enrolledOwner()
	good := owner.cookie()
	tampered := good[:len(good)-1] + map[bool]string{true: "A", false: "B"}[good[len(good)-1] != 'A']
	for name, value := range map[string]string{
		"tampered secret": tampered,
		"malformed":       "not-a-session",
		"other type":      strings.Replace(good, "qali_sess_", "qali_ci_", 1),
		"unknown lookup":  "qali_sess_aaaaaaaaaaaaaaaa_" + strings.Repeat("A", 43),
	} {
		if r := s.withCookie(value).do(http.MethodGet, "/api/v1/auth/session", nil); r.status != http.StatusUnauthorized {
			t.Fatalf("%s cookie: %d", name, r.status)
		}
	}
	if sessionStatus(owner) != http.StatusOK {
		t.Fatal("rejecting forged cookies must not affect the real session")
	}
}

func TestDeactivatedUsersCannotAuthenticate(t *testing.T) {
	s := newAuthServer(t)
	owner, _, codes := s.enrolledOwner()
	if _, err := connect(t, s.db.admin).Exec(t.Context(), "UPDATE qali.users SET status = 'deactivated'"); err != nil {
		t.Fatal(err)
	}
	if sessionStatus(owner) != http.StatusUnauthorized {
		t.Fatal("a deactivated user's session still works")
	}
	if r := s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}); r.status != http.StatusUnauthorized {
		t.Fatalf("deactivated login: %d", r.status)
	}
	if r := s.client().do(http.MethodPost, "/api/v1/auth/recovery", map[string]any{"email": "owner@example.org", "recoveryCode": codes[0], "newPassword": "recovery attempt passphrase"}); r.status != http.StatusUnauthorized {
		t.Fatalf("deactivated recovery: %d", r.status)
	}
}

func TestPasswordChangeRejectsWeakPasswords(t *testing.T) {
	s := newAuthServer(t)
	owner, _, _ := s.enrolledOwner()
	r := owner.do(http.MethodPost, "/api/v1/auth/password", map[string]any{"currentPassword": ownerPassword, "newPassword": "owner@example.org"})
	if r.status != http.StatusBadRequest || r.code() != "weak_password" {
		t.Fatalf("weak new password: %d %s", r.status, r.raw)
	}
	if sessionStatus(owner) != http.StatusOK {
		t.Fatal("a rejected change must not revoke the session")
	}
}

func TestRegeneratingCodesRequiresEnrollment(t *testing.T) {
	s := newAuthServer(t)
	_, _, _ = s.enrolledOwner()
	err := s.svc.LogoutAll(t.Context(), app.Current{}, app.RequestMeta{})
	if err != nil {
		t.Fatalf("logging out a zero session is a no-op: %v", err)
	}
	if _, err := s.svc.RegenerateRecoveryCodes(t.Context(), app.Current{}, "123456", app.RequestMeta{}); err == nil {
		t.Fatal("regeneration for an unknown user succeeded")
	}
}

// TestInfrastructureFailuresAreNotAuthenticationOutcomes: when the database
// is unavailable, use cases must report an internal error, never a
// credential verdict that would log users out or mislead them.
func TestInfrastructureFailuresAreNotAuthenticationOutcomes(t *testing.T) {
	s := newAuthServer(t)
	_, _, _ = s.enrolledOwner()
	s.store.Close()
	ctx := t.Context()
	pw := secret.New([]byte(ownerPassword))
	cur := app.Current{}
	verdicts := []error{app.ErrInvalidCredentials, app.ErrInvalidCode, app.ErrInvalidToken, app.ErrUnauthenticated,
		app.ErrAlreadyBootstrapped, app.ErrAlreadyEnrolled, app.ErrEnrollmentNotStarted, app.ErrUnknownAccount}
	calls := map[string]func() error{
		"setup": func() error { _, err := s.svc.SetupRequired(ctx); return err },
		"bootstrap": func() error {
			_, err := s.svc.Bootstrap(ctx, app.BootstrapInput{Email: "o@example.org", DisplayName: "O", Password: pw, WorkspaceName: "W"}, app.RequestMeta{})
			return err
		},
		"login": func() error { _, err := s.svc.Login(ctx, "owner@example.org", pw, app.RequestMeta{}); return err },
		"authenticate": func() error {
			_, err := s.svc.Authenticate(ctx, secret.New([]byte("qali_sess_aaaaaaaaaaaaaaaa_"+strings.Repeat("A", 43))), app.RequestMeta{})
			return err
		},
		"challenge": func() error {
			_, err := s.svc.CompleteMFAChallenge(ctx, app.Current{View: app.SessionView{State: "mfa_challenge"}}, "123456", app.RequestMeta{})
			return err
		},
		"begin": func() error { _, err := s.svc.BeginTOTPEnrollment(ctx, cur, app.RequestMeta{}); return err },
		"confirm": func() error {
			_, _, err := s.svc.ConfirmTOTPEnrollment(ctx, cur, "123456", app.RequestMeta{})
			return err
		},
		"regenerate": func() error {
			_, err := s.svc.RegenerateRecoveryCodes(ctx, cur, "123456", app.RequestMeta{})
			return err
		},
		"change":     func() error { _, err := s.svc.ChangePassword(ctx, cur, pw, pw, app.RequestMeta{}); return err },
		"logout":     func() error { return s.svc.Logout(ctx, cur, app.RequestMeta{}) },
		"logout all": func() error { return s.svc.LogoutAll(ctx, cur, app.RequestMeta{}) },
		"recover": func() error {
			return s.svc.Recover(ctx, "owner@example.org", "AAAA-BBBB-CCCC-DDDD", secret.New([]byte("a long new passphrase")), app.RequestMeta{})
		},
		"issue reset": func() error { _, _, err := s.svc.IssuePasswordReset(ctx, "owner@example.org", "ops"); return err },
		"redeem reset": func() error {
			return s.svc.RedeemPasswordReset(ctx, secret.New([]byte("qali_reset_aaaaaaaaaaaaaaaa_"+strings.Repeat("A", 43))), secret.New([]byte("a long new passphrase")), app.RequestMeta{})
		},
	}
	for name, call := range calls {
		err := call()
		if err == nil {
			t.Fatalf("%s succeeded with the database closed", name)
		}
		for _, v := range verdicts {
			if errors.Is(err, v) {
				t.Fatalf("%s reported %v while the database was unavailable", name, v)
			}
		}
	}
	if (&app.ThrottledError{RetryAfter: 2 * time.Second}).Error() == "" {
		t.Fatal("throttle errors need a message")
	}
}
