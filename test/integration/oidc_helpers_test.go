//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/qali-project/qali/test/oidctest"
)

type oidcFixture struct {
	*adminFixture
	issuer *oidctest.Issuer
	path   string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	s := newAuthServer(t)
	f := s.adminFixture()
	issuer, err := oidctest.New(s.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(issuer.Close)
	out := &oidcFixture{adminFixture: f, issuer: issuer, path: f.workspaceP + "/security/oidc-provider"}
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	r := f.owner.do(http.MethodPut, out.path, map[string]any{"issuer": issuer.URL(), "clientId": oidctest.ClientID, "clientSecret": oidctest.Credential, "label": "Company sign-in"})
	expect(t, r, http.StatusOK)
	return out
}
func (f *oidcFixture) verify() {
	f.s.t.Helper()
	r := f.owner.do(http.MethodPost, f.path+"/verify", nil)
	expect(f.s.t, r, http.StatusOK)
	callback := f.authorize(r, "owner-sub", "owner@example.org", true)
	r = f.callback(f.owner, callback)
	if r.status != http.StatusFound || r.header.Get("Location") == "/login?oidc=failed" {
		f.s.t.Fatalf("verify: %d %s", r.status, r.raw)
	}
}
func (f *oidcFixture) authorize(r response, subject, email string, verified bool) string {
	f.s.t.Helper()
	raw, ok := r.body["authorizationUrl"].(string)
	if !ok {
		f.s.t.Fatalf("authorization response: %s", r.raw)
	}
	callback, err := f.issuer.Authorize(raw, subject, email, verified)
	if err != nil {
		f.s.t.Fatal(err)
	}
	return callback
}
func (f *oidcFixture) callback(c *client, callback string) response {
	f.s.t.Helper()
	u, err := url.Parse(callback)
	if err != nil {
		f.s.t.Fatal(err)
	}
	old := c.http.CheckRedirect
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer func() { c.http.CheckRedirect = old }()
	return c.do(http.MethodGet, u.RequestURI(), nil)
}
func (f *oidcFixture) start(c *client) response {
	f.s.t.Helper()
	r := c.do(http.MethodPost, "/api/v1/auth/oidc/start", map[string]any{"purpose": "login"})
	expect(f.s.t, r, http.StatusOK)
	return r
}
func (f *oidcFixture) disableLocal() {
	f.s.t.Helper()
	expect(f.s.t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	p := f.owner.do(http.MethodGet, f.workspaceP+"/security/login-policy", nil)
	expect(f.s.t, p, http.StatusOK)
	expect(f.s.t, f.owner.doWith(http.MethodPut, f.workspaceP+"/security/login-policy", map[string]any{"localLogin": false}, map[string]string{"If-Match": p.header.Get("ETag")}), http.StatusOK)
}
