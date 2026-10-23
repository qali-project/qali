//go:build integration

package integration_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestNonAdministratorsAreDeniedEveryAdministrativeOperation proves
// MVP-05.AC-09: Testers and Viewers get 403 on administrative operations
// for resources they can see, and 404 for resources they cannot.
func TestNonAdministratorsAreDeniedEveryAdministrativeOperation(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	_, adminID, _ := f.member("admin@example.org", "workspace_admin")
	public := f.project("PUB", "public")
	restricted := f.project("RES", "restricted")
	f.invite("pending@example.org", "viewer")
	invitationID := ids(f.owner.do(http.MethodGet, f.workspaceP+"/invitations", nil), "id")[0]
	pubMember := f.owner.do(http.MethodPost, f.workspaceP+"/projects/"+public+"/members", map[string]any{"userId": adminID, "level": "contributor"})
	expect(t, pubMember, http.StatusCreated)

	for _, role := range []string{"tester", "viewer", "qa_lead"} {
		c, _, _ := f.member(role+"@example.org", role)
		w := f.workspaceP
		type call struct {
			method, path string
			body         map[string]any
			want         int
		}
		calls := []call{
			{http.MethodGet, w + "/members", nil, http.StatusForbidden},
			{http.MethodPatch, w + "/members/" + adminID, map[string]any{"status": "deactivated"}, http.StatusForbidden},
			{http.MethodPatch, w + "/members/" + adminID, map[string]any{"role": "viewer"}, http.StatusForbidden},
			{http.MethodPatch, w + "/members/" + f.ownerID, map[string]any{"role": "viewer"}, http.StatusForbidden},
			{http.MethodGet, w + "/invitations", nil, http.StatusForbidden},
			{http.MethodPost, w + "/invitations", map[string]any{"email": "friend@example.org"}, http.StatusForbidden},
			{http.MethodPost, w + "/invitations/" + invitationID + "/revoke", nil, http.StatusForbidden},
			{http.MethodPost, w + "/projects", map[string]any{"code": "NEW", "name": "New", "visibility": "public"}, http.StatusForbidden},
			{http.MethodGet, w + "/projects/" + public + "/members", nil, http.StatusForbidden},
			{http.MethodPost, w + "/projects/" + public + "/members", map[string]any{"userId": adminID, "level": "viewer"}, http.StatusForbidden},
			{http.MethodPatch, w + "/projects/" + public + "/members/" + adminID, map[string]any{"level": "viewer"}, http.StatusForbidden},
			{http.MethodDelete, w + "/projects/" + public + "/members/" + adminID, nil, http.StatusForbidden},
			{http.MethodGet, w + "/projects/" + restricted, nil, http.StatusNotFound},
			{http.MethodGet, w + "/projects/" + restricted + "/members", nil, http.StatusNotFound},
			{http.MethodPost, w + "/projects/" + restricted + "/members", map[string]any{"userId": adminID, "level": "viewer"}, http.StatusNotFound},
			{http.MethodDelete, w + "/projects/" + restricted + "/members/" + f.ownerID, nil, http.StatusNotFound},
		}
		for _, cl := range calls {
			var body any
			if cl.body != nil {
				body = cl.body
			}
			r := c.doWith(cl.method, cl.path, body, map[string]string{"If-Match": pubMember.header.Get("ETag")})
			wantCode := map[int]string{http.StatusForbidden: "forbidden", http.StatusNotFound: "not_found"}[cl.want]
			if r.status != cl.want || r.code() != wantCode {
				t.Errorf("%s %s %s: %d %s, want %d", role, cl.method, strings.TrimPrefix(cl.path, w), r.status, r.raw, cl.want)
			}
		}
	}
	// Nothing was changed by the denied calls.
	if got := ids(f.owner.do(http.MethodGet, f.workspaceP+"/projects", nil), "id"); len(got) != 2 {
		t.Fatalf("projects after denied calls: %v", got)
	}
	members := f.owner.do(http.MethodGet, f.workspaceP+"/members", nil)
	if strings.Contains(members.raw, `"deactivated"`) {
		t.Fatalf("a denied call deactivated a member: %s", members.raw)
	}
}
