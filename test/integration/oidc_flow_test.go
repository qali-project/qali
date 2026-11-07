//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCDefaultMethods(t *testing.T) {
	s := newAuthServer(t)
	r := s.client().do(http.MethodGet, "/api/v1/auth/methods", nil)
	if r.status != http.StatusOK || r.body["localLogin"] != true || r.body["oidc"] != nil {
		t.Fatalf("default sign-in methods: %d %s", r.status, r.raw)
	}
}

func TestOIDCFlowAndMFA(t *testing.T) {
	f := newOIDCFixture(t)
	expect(t, f.s.client().do(http.MethodPost, "/api/v1/auth/oidc/start", map[string]any{"purpose": "login"}), http.StatusConflict)
	f.verify()
	p := f.owner.do(http.MethodGet, f.path, nil)
	expect(t, p, http.StatusOK)
	if p.body["status"] != "verified" {
		t.Fatal(p.raw)
	}
	m := f.s.client().do(http.MethodGet, "/api/v1/auth/methods", nil)
	expect(t, m, http.StatusOK)
	if m.body["oidc"] == nil {
		t.Fatal(m.raw)
	}
	c := f.s.client()
	callback := f.authorize(f.start(c), "owner-sub", "different@example.org", false)
	r := f.callback(c, callback)
	expect(t, r, http.StatusFound)
	if r.header.Get("Location") != "/" {
		t.Fatal(r.header)
	}
	r = c.do(http.MethodGet, "/api/v1/auth/session", nil)
	expect(t, r, http.StatusOK)
	if r.state() != "mfa_challenge" {
		t.Fatalf("OIDC bypassed MFA: %s", r.raw)
	}
	expect(t, c.do(http.MethodGet, f.path, nil), http.StatusForbidden)
	expect(t, c.do(http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]any{"code": f.s.totpCode(f.ownerTOTP)}), http.StatusOK)
	var method string
	if err := connect(t, f.s.db.admin).QueryRow(t.Context(), "SELECT auth_method FROM qali.sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 1", f.ownerID).Scan(&method); err != nil {
		t.Fatal(err)
	}
	if method != "oidc" {
		t.Fatalf("MFA rotation changed OIDC authentication method to %q", method)
	}
	r = c.do(http.MethodGet, "/api/v1/workspaces", nil)
	expect(t, r, http.StatusOK)
	if !strings.Contains(r.raw, f.workspace) {
		t.Fatal(r.raw)
	}
}

func TestOIDCCancellationReplayAndBrowserBinding(t *testing.T) {
	f := newOIDCFixture(t)
	f.verify()
	for _, scenario := range []string{"cancel", "wrong_state", "wrong_browser", "expired", "wrong_issuer", "bad_code"} {
		t.Run(scenario, func(t *testing.T) {
			c := f.s.client()
			callback := f.authorize(f.start(c), "owner-sub", "owner@example.org", true)
			u, _ := url.Parse(callback)
			q := u.Query()
			before := f.issuer.ExchangeCount()
			switch scenario {
			case "cancel":
				q.Del("code")
				q.Set("error", "access_denied")
			case "wrong_state":
				q.Set("state", q.Get("state")+"x")
			case "expired":
				f.s.clock.Advance(11 * time.Minute)
			case "wrong_issuer":
				q.Set("iss", "https://different.example")
			case "bad_code":
				q.Set("code", "bad-code")
			}
			u.RawQuery = q.Encode()
			target := c
			if scenario == "wrong_browser" {
				target = f.s.client()
			}
			r := f.callback(target, u.String())
			expect(t, r, http.StatusFound)
			if r.header.Get("Location") != "/login?oidc=failed" || target.cookie() != "" {
				t.Fatalf("invalid callback accepted: %s", r.raw)
			}
			if scenario != "bad_code" && f.issuer.ExchangeCount() != before {
				t.Fatal("invalid flow reached token endpoint")
			}
			expect(t, target.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
		})
	}
	c := f.s.client()
	callback := f.authorize(f.start(c), "owner-sub", "owner@example.org", true)
	r := f.callback(c, callback)
	expect(t, r, http.StatusFound)
	if r.header.Get("Location") == "/login?oidc=failed" {
		t.Fatal("first callback failed")
	}
	before := f.issuer.ExchangeCount()
	r = f.callback(c, callback)
	if r.header.Get("Location") != "/login?oidc=failed" || f.issuer.ExchangeCount() != before {
		t.Fatal("replayed callback exchanged")
	}
}
