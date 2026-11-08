//go:build integration

package integration_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/qali-project/qali/test/oidctest"
)

func TestOIDCPolicyAndBreakGlass(t *testing.T) {
	f := newOIDCFixture(t)
	member, _, _ := f.member("member@example.org", "tester")
	p := f.owner.do(http.MethodGet, f.workspaceP+"/security/login-policy", nil)
	expect(t, f.owner.doWith(http.MethodPut, f.workspaceP+"/security/login-policy", map[string]any{"localLogin": false}, map[string]string{"If-Match": p.header.Get("ETag")}), http.StatusConflict)
	f.verify()
	f.disableLocal()
	expect(t, f.s.client().do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "member@example.org", "password": ownerPassword}), http.StatusUnauthorized)
	expect(t, member.do(http.MethodDelete, "/api/v1/auth/oidc/identity", nil), http.StatusConflict)
	f.issuer.Close()
	c := f.s.client()
	r := c.do(http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "owner@example.org", "password": ownerPassword})
	expect(t, r, http.StatusOK)
	if r.state() != "mfa_challenge" {
		t.Fatal(r.raw)
	}
	var count int
	if err := connect(t, f.s.db.admin).QueryRow(t.Context(), "SELECT count(*) FROM qali.audit_events WHERE action='auth.break_glass_login' AND metadata->>'severity'='high'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("break-glass was not audited high")
	}
}

func TestOIDCConfigurationVersionsAndRemoval(t *testing.T) {
	f := newOIDCFixture(t)
	f.verify()
	f.disableLocal()
	p := f.owner.do(http.MethodGet, f.path, nil)
	input := map[string]any{"issuer": f.issuer.URL(), "clientId": oidctest.ClientID, "label": "Updated"}
	expect(t, f.owner.do(http.MethodPut, f.path, input), http.StatusPreconditionRequired)
	expect(t, f.owner.doWith(http.MethodPut, f.path, input, map[string]string{"If-Match": "\"0\""}), http.StatusPreconditionFailed)
	r := f.owner.doWith(http.MethodPut, f.path, input, map[string]string{"If-Match": p.header.Get("ETag")})
	expect(t, r, http.StatusOK)
	if r.body["status"] != "verified" {
		t.Fatal("label update reset verification")
	}
	input["clientSecret"] = oidctest.Credential
	r = f.owner.doWith(http.MethodPut, f.path, input, map[string]string{"If-Match": r.header.Get("ETag")})
	expect(t, r, http.StatusOK)
	if r.body["status"] != "draft" {
		t.Fatal(r.raw)
	}
	p = f.owner.do(http.MethodGet, f.workspaceP+"/security/login-policy", nil)
	if p.body["localLogin"] != true {
		t.Fatal(p.raw)
	}
	expect(t, f.owner.doWith(http.MethodDelete, f.path, nil, map[string]string{"If-Match": r.header.Get("ETag")}), http.StatusNoContent)
	expect(t, f.owner.do(http.MethodGet, f.path, nil), http.StatusNotFound)
	if strings.Contains(r.raw, oidctest.Credential) {
		t.Fatal("secret returned")
	}
}
