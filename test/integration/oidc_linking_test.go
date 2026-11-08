//go:build integration

package integration_test

import (
	"net/http"
	"testing"
)

func TestOIDCLinkingAndNoProvisioning(t *testing.T) {
	f := newOIDCFixture(t)
	member, memberID, _ := f.member("member@example.org", "tester")
	f.verify()
	for _, tc := range []struct {
		name, email       string
		verified, success bool
	}{
		{"unverified", "member@example.org", false, false}, {"unknown", "unknown@example.org", true, false}, {"verified", " MEMBER@example.org ", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.s.client()
			r := f.callback(c, f.authorize(f.start(c), "member-sub", tc.email, tc.verified))
			if (r.header.Get("Location") == "/") != tc.success {
				t.Fatalf("callback: %v", r.header)
			}
			if tc.success {
				r = c.do(http.MethodGet, "/api/v1/auth/session", nil)
				expect(t, r, http.StatusOK)
				if r.body["user"].(map[string]any)["id"] != memberID {
					t.Fatal(r.raw)
				}
			}
		})
	}
	r := member.do(http.MethodGet, "/api/v1/auth/oidc/identity", nil)
	expect(t, r, http.StatusOK)
	expect(t, member.do(http.MethodDelete, "/api/v1/auth/oidc/identity", nil), http.StatusNoContent)
	expect(t, member.do(http.MethodPost, "/api/v1/auth/oidc/link", map[string]any{"password": "wrong"}), http.StatusUnauthorized)
	r = member.do(http.MethodPost, "/api/v1/auth/oidc/link", map[string]any{"password": ownerPassword})
	expect(t, r, http.StatusOK)
	r = f.callback(member, f.authorize(r, "explicit-sub", "unverified@example.org", false))
	if r.header.Get("Location") != "/account" {
		t.Fatalf("explicit link: %v", r.header)
	}
	c := f.s.client()
	r = f.callback(c, f.authorize(f.start(c), "explicit-sub", "different@example.org", false))
	if r.header.Get("Location") != "/" {
		t.Fatalf("linked login: %v", r.header)
	}
	r = c.do(http.MethodGet, "/api/v1/auth/session", nil)
	if r.body["user"].(map[string]any)["id"] != memberID {
		t.Fatal(r.raw)
	}
	var count int
	if err := connect(t, f.s.db.admin).QueryRow(t.Context(), "SELECT count(*) FROM qali.users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("JIT created account: %d", count)
	}
}

func TestOIDCInvitationAndPasswordlessUnlink(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.invite("invitee@example.org", "tester")
	f.verify()
	f.disableLocal()
	c := f.s.client()
	start := func() response {
		r := c.do(http.MethodPost, "/api/v1/auth/oidc/start", map[string]any{"purpose": "invitation", "invitationToken": token})
		expect(t, r, http.StatusOK)
		return r
	}
	r := f.callback(c, f.authorize(start(), "invite-sub", "wrong@example.org", true))
	if r.header.Get("Location") != "/login?oidc=failed" {
		t.Fatal("mismatched invitation accepted")
	}
	r = f.callback(c, f.authorize(start(), "invite-sub", "invitee@example.org", false))
	if r.header.Get("Location") != "/login?oidc=failed" {
		t.Fatal("unverified invitation accepted")
	}
	r = f.callback(c, f.authorize(start(), "invite-sub", "invitee@example.org", true))
	if r.header.Get("Location") != "/" {
		t.Fatalf("invitation: %v", r.header)
	}
	r = c.do(http.MethodGet, "/api/v1/auth/session", nil)
	expect(t, r, http.StatusOK)
	if r.state() != "active" {
		t.Fatal(r.raw)
	}
	r = c.do(http.MethodGet, "/api/v1/workspaces", nil)
	expect(t, r, http.StatusOK)
	expect(t, c.do(http.MethodDelete, "/api/v1/auth/oidc/identity", nil), http.StatusConflict)
	var password *string
	if err := connect(t, f.s.db.admin).QueryRow(t.Context(), "SELECT password_hash FROM qali.users WHERE email='invitee@example.org'").Scan(&password); err != nil {
		t.Fatal(err)
	}
	if password != nil {
		t.Fatal("OIDC invitation stored password")
	}
	r = f.owner.do(http.MethodGet, f.path, nil)
	expect(t, f.owner.doWith(http.MethodDelete, f.path, nil, map[string]string{"If-Match": r.header.Get("ETag")}), http.StatusConflict)
}
