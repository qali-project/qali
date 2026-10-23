//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// adminFixture is a bootstrapped workspace with an enrolled owner.
type adminFixture struct {
	s          *authServer
	owner      *client
	ownerTOTP  string
	ownerID    string
	workspace  string
	workspaceP string // "/api/v1/workspaces/<id>"
}

func (s *authServer) adminFixture() *adminFixture {
	s.t.Helper()
	owner, totp, _ := s.enrolledOwner()
	list := owner.do(http.MethodGet, "/api/v1/workspaces", nil)
	expect(s.t, list, http.StatusOK)
	items := list.body["items"].([]any)
	if len(items) != 1 {
		s.t.Fatalf("owner workspaces: %s", list.raw)
	}
	ws := items[0].(map[string]any)["id"].(string)
	session := owner.do(http.MethodGet, "/api/v1/auth/session", nil)
	ownerID := session.body["user"].(map[string]any)["id"].(string)
	return &adminFixture{s: s, owner: owner, ownerTOTP: totp, ownerID: ownerID, workspace: ws, workspaceP: "/api/v1/workspaces/" + ws}
}

// stepUp records recent MFA for c with the given TOTP secret.
func (f *adminFixture) stepUp(c *client, totp string) response {
	f.s.t.Helper()
	r := c.do(http.MethodPost, "/api/v1/auth/mfa/step-up", map[string]any{"code": f.s.totpCode(totp)})
	f.s.clock.Advance(31 * time.Second)
	return r
}

// invite creates an invitation (stepping up first) and returns its token.
func (f *adminFixture) invite(email, role string) string {
	f.s.t.Helper()
	expect(f.s.t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	r := f.owner.do(http.MethodPost, f.workspaceP+"/invitations", map[string]any{"email": email, "role": role})
	expect(f.s.t, r, http.StatusCreated)
	return r.body["token"].(string)
}

// member invites email with role, accepts as a new account, and returns the
// signed-in client and the user ID. Privileged roles also enroll TOTP; the
// secret is returned for them.
func (f *adminFixture) member(email, role string) (*client, string, string) {
	f.s.t.Helper()
	token := f.invite(email, role)
	c := f.s.client()
	r := c.do(http.MethodPost, "/api/v1/invitations/accept", map[string]any{"token": token, "displayName": "Member " + role, "password": ownerPassword})
	expect(f.s.t, r, http.StatusCreated)
	id := r.body["user"].(map[string]any)["id"].(string)
	totp := ""
	if r.state() == "mfa_enrollment" {
		begin := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
		expect(f.s.t, begin, http.StatusOK)
		totp = begin.body["secret"].(string)
		expect(f.s.t, c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": f.s.totpCode(totp)}), http.StatusOK)
		f.s.clock.Advance(31 * time.Second)
	}
	return c, id, totp
}

// memberVersion returns the If-Match value for a member.
func (f *adminFixture) memberVersion(c *client, userID string) string {
	f.s.t.Helper()
	r := c.do(http.MethodGet, f.workspaceP+"/members", nil)
	expect(f.s.t, r, http.StatusOK)
	for _, it := range r.body["items"].([]any) {
		m := it.(map[string]any)
		if m["userId"] == userID {
			return `"` + strconv.Itoa(int(m["version"].(float64))) + `"`
		}
	}
	f.s.t.Fatalf("member %s not listed: %s", userID, r.raw)
	return ""
}

// patchMember sends a PATCH with If-Match.
func (f *adminFixture) patchMember(c *client, userID, ifMatch string, body map[string]any) response {
	f.s.t.Helper()
	return c.doWith(http.MethodPatch, f.workspaceP+"/members/"+userID, body, map[string]string{"If-Match": ifMatch})
}

// project creates a project as the owner and returns its ID.
func (f *adminFixture) project(code, visibility string) string {
	f.s.t.Helper()
	r := f.owner.do(http.MethodPost, f.workspaceP+"/projects", map[string]any{"code": code, "name": "Project " + code, "visibility": visibility})
	expect(f.s.t, r, http.StatusCreated)
	return r.body["id"].(string)
}

// doWith is do with extra headers.
func (c *client) doWith(method, path string, body any, headers map[string]string) response {
	c.s.t.Helper()
	c.extra = headers
	defer func() { c.extra = nil }()
	return c.do(method, path, body)
}

// secondWorkspace creates another workspace directly in the database with
// the given user as a member with role (the MVP has no workspace-creation
// API).
func (f *adminFixture) secondWorkspace(userID, role string) string {
	f.s.t.Helper()
	conn := connect(f.s.t, f.s.db.migrator)
	ws := uuid.New().String()
	now := f.s.clock.Now()
	steps := []struct {
		sql  string
		args []any
	}{
		{"SELECT set_config('qali.workspace_id', $1, false)", []any{ws}},
		{"INSERT INTO qali.workspaces (id, name, created_at, updated_at) VALUES ($1, 'Other QA', $2, $2)", []any{ws, now}},
		{"INSERT INTO qali.workspace_members (workspace_id, user_id, role, status, created_at, updated_at) VALUES ($1, $2, $4, 'active', $3, $3)", []any{ws, userID, now, role}},
	}
	for _, st := range steps {
		if _, err := conn.Exec(f.s.t.Context(), st.sql, st.args...); err != nil {
			f.s.t.Fatalf("second workspace: %v", err)
		}
	}
	return ws
}

func ids(r response, key string) []string {
	var out []string
	items, _ := r.body["items"].([]any)
	for _, it := range items {
		out = append(out, it.(map[string]any)[key].(string))
	}
	return out
}

func permissionsOf(r response) string {
	var out []string
	perms, _ := r.body["permissions"].([]any)
	for _, p := range perms {
		out = append(out, p.(string))
	}
	return strings.Join(out, ",")
}

// jarURL is the HTTPS origin under which the test clients store cookies.
func jarURL(s *authServer) *url.URL {
	u, _ := url.Parse(s.srv.URL)
	return &url.URL{Scheme: "https", Host: u.Host}
}

// enroll completes TOTP enrollment for c and returns the secret.
func (f *adminFixture) enroll(c *client) string {
	f.s.t.Helper()
	begin := c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
	expect(f.s.t, begin, http.StatusOK)
	secret := begin.body["secret"].(string)
	expect(f.s.t, c.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": f.s.totpCode(secret)}), http.StatusOK)
	f.s.clock.Advance(31 * time.Second)
	return secret
}
