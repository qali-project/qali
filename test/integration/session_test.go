//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// withCookie returns a browser that presents a captured session cookie.
func (s *authServer) withCookie(value string) *client {
	c := s.client()
	u, _ := url.Parse(s.srv.URL)
	c.http.Jar.SetCookies(&url.URL{Scheme: "https", Host: u.Host}, []*http.Cookie{{Name: "__Host-qali_session", Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
	return c
}

func sessionStatus(c *client) int {
	return c.do(http.MethodGet, "/api/v1/auth/session", nil).status
}

func TestSessionCookieAttributes(t *testing.T) {
	s := newAuthServer(t)
	r := s.client().do(http.MethodPost, "/api/v1/setup/owner", s.bootstrapBody("owner@example.org"))
	expect(t, r, http.StatusCreated)
	header := r.header.Get("Set-Cookie")
	for _, attr := range []string{"__Host-qali_session=qali_sess_", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !contains(header, attr) {
			t.Fatalf("Set-Cookie %q lacks %q", header, attr)
		}
	}
	if contains(header, "Domain=") {
		t.Fatalf("__Host- cookies must not set Domain: %q", header)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestCSRFTokenIsRequiredAndSessionBound proves the CSRF half of AC-08.
func TestCSRFTokenIsRequiredAndSessionBound(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, _ := s.enrolledOwner()
	other := s.login("owner@example.org", ownerPassword, secretB32)

	token := owner.csrf
	owner.csrf = ""
	if r := owner.do(http.MethodPost, "/api/v1/auth/logout-all", nil); r.status != http.StatusForbidden || r.code() != "csrf_token_invalid" {
		t.Fatalf("missing token: %d %s", r.status, r.raw)
	}
	owner.csrf = other.csrf
	if r := owner.do(http.MethodPost, "/api/v1/auth/logout-all", nil); r.status != http.StatusForbidden || r.code() != "csrf_token_invalid" {
		t.Fatalf("another session's token: %d %s", r.status, r.raw)
	}
	owner.csrf = token
	if sessionStatus(other) != http.StatusOK {
		t.Fatal("rejected requests must not have changed anything")
	}
	expect(t, owner.do(http.MethodPost, "/api/v1/auth/logout-all", nil), http.StatusNoContent)
}

// TestSessionIDRotatesOnEveryStateChange proves the fixation half of AC-08.
func TestSessionIDRotatesOnEveryStateChange(t *testing.T) {
	s := newAuthServer(t)
	c := s.client()
	expect(t, c.do(http.MethodPost, "/api/v1/setup/owner", s.bootstrapBody("owner@example.org")), http.StatusCreated)
	bootstrapCookie := c.cookie()
	begin := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
	secretB32 := begin.body["secret"].(string)
	expect(t, c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": s.totpCode(secretB32)}), http.StatusOK)
	enrolledCookie := c.cookie()
	if enrolledCookie == bootstrapCookie || sessionStatus(s.withCookie(bootstrapCookie)) != http.StatusUnauthorized {
		t.Fatal("the pre-enrollment session survived enrollment")
	}
	s.clock.Advance(31 * time.Second)

	login := s.client()
	expect(t, login.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}), http.StatusOK)
	challengeCookie := login.cookie()
	expect(t, login.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": s.totpCode(secretB32)}), http.StatusOK)
	if login.cookie() == challengeCookie || sessionStatus(s.withCookie(challengeCookie)) != http.StatusUnauthorized {
		t.Fatal("the pre-MFA session survived the challenge (fixation)")
	}
	if sessionStatus(login) != http.StatusOK {
		t.Fatal("the rotated session does not work")
	}
}

// TestRevocationIsImmediate proves AC-09 for logout, logout-all, and
// password change.
func TestRevocationIsImmediate(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, _ := s.enrolledOwner()

	captured := owner.cookie()
	expect(t, owner.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
	if sessionStatus(s.withCookie(captured)) != http.StatusUnauthorized {
		t.Fatal("a logged-out session still works")
	}

	a := s.login("owner@example.org", ownerPassword, secretB32)
	b := s.login("owner@example.org", ownerPassword, secretB32)
	expect(t, a.do(http.MethodPost, "/api/v1/auth/logout-all", nil), http.StatusNoContent)
	if sessionStatus(a) != http.StatusUnauthorized || sessionStatus(b) != http.StatusUnauthorized {
		t.Fatal("log out everywhere left a session alive")
	}

	c := s.login("owner@example.org", ownerPassword, secretB32)
	d := s.login("owner@example.org", ownerPassword, secretB32)
	newPassword := "a different long passphrase"
	r := c.do(http.MethodPost, "/api/v1/auth/password", map[string]any{"currentPassword": ownerPassword, "newPassword": newPassword})
	expect(t, r, http.StatusOK)
	if sessionStatus(c) != http.StatusOK {
		t.Fatal("the session that changed the password must continue (rotated)")
	}
	if sessionStatus(d) != http.StatusUnauthorized {
		t.Fatal("other sessions survived a password change")
	}
	if r := s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword}); r.status != http.StatusUnauthorized {
		t.Fatal("the old password still works")
	}
	s.login("owner@example.org", newPassword, secretB32)

	wrong := c.do(http.MethodPost, "/api/v1/auth/password", map[string]any{"currentPassword": "not the password!", "newPassword": "yet another passphrase"})
	if wrong.status != http.StatusUnauthorized {
		t.Fatalf("password change without the current password: %d", wrong.status)
	}
}

// TestSessionsExpire proves the expiry half of AC-04.
func TestSessionsExpire(t *testing.T) {
	s := newAuthServer(t)
	_, secretB32, _ := s.enrolledOwner()

	idle := s.login("owner@example.org", ownerPassword, secretB32)
	s.clock.Advance(12*time.Hour + time.Second)
	if sessionStatus(idle) != http.StatusUnauthorized {
		t.Fatal("idle session did not expire")
	}

	busy := s.login("owner@example.org", ownerPassword, secretB32)
	for range 16 { // 16 * 11h = 176h > 7 days (168h)
		s.clock.Advance(11 * time.Hour)
		if sessionStatus(busy) != http.StatusOK {
			break
		}
	}
	if sessionStatus(busy) != http.StatusUnauthorized {
		t.Fatal("activity extended a session past its absolute limit")
	}
}
