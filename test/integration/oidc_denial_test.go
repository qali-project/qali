//go:build integration

package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/test/oidctest"
)

func TestOIDCSecurityDenial(t *testing.T) {
	f := newOIDCFixture(t)
	for _, role := range []string{"tester", "viewer"} {
		t.Run(role, func(t *testing.T) {
			c, id, _ := f.member(role+"@example.org", role)
			for _, op := range []struct {
				method, path string
				body         any
			}{
				{http.MethodGet, f.path, nil}, {http.MethodPut, f.path, map[string]any{"issuer": f.issuer.URL(), "clientId": oidctest.ClientID, "label": "SSO"}}, {http.MethodDelete, f.path, nil}, {http.MethodPost, f.path + "/verify", nil},
				{http.MethodGet, f.workspaceP + "/security/login-policy", nil}, {http.MethodPut, f.workspaceP + "/security/login-policy", map[string]any{"localLogin": false}},
				{http.MethodDelete, f.workspaceP + "/members/" + id + "/oidc-identity", nil},
			} {
				expect(t, c.do(op.method, op.path, op.body), http.StatusForbidden)
			}
		})
	}
	other := "/api/v1/workspaces/" + uuid.NewString() + "/security"
	expect(t, f.owner.do(http.MethodDelete, f.workspaceP+"/members/"+uuid.NewString()+"/oidc-identity", nil), http.StatusNotFound)
	expect(t, f.owner.do(http.MethodGet, other+"/oidc-provider", nil), http.StatusNotFound)
	expect(t, f.owner.do(http.MethodGet, other+"/login-policy", nil), http.StatusNotFound)
	f.s.clock.Advance(11 * time.Minute)
	expect(t, f.owner.do(http.MethodPost, f.path+"/verify", nil), http.StatusForbidden)
	expect(t, f.owner.do(http.MethodPut, f.path, map[string]any{"issuer": f.issuer.URL(), "clientId": oidctest.ClientID, "label": "SSO"}), http.StatusForbidden)
	expect(t, f.owner.do(http.MethodDelete, f.path, nil), http.StatusForbidden)
	expect(t, f.owner.do(http.MethodPut, f.workspaceP+"/security/login-policy", map[string]any{"localLogin": false}), http.StatusForbidden)
	expect(t, f.owner.do(http.MethodDelete, f.workspaceP+"/members/"+f.ownerID+"/oidc-identity", nil), http.StatusForbidden)
	expect(t, f.owner.do(http.MethodPost, "/api/v1/auth/oidc/link", map[string]any{}), http.StatusForbidden)
}
