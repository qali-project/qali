//go:build integration

package integration_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"
)

// TestEveryTenantTableIsIsolated requires forced row-level security on
// every table with a workspace_id column (ADR-0011).
func TestEveryTenantTableIsIsolated(t *testing.T) {
	d := migratedDatabase(t)
	conn := connect(t, d.admin)
	rows, err := conn.Query(t.Context(), `
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
		WHERE n.nspname = 'qali' AND c.relkind = 'r'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	// Global by design: invitation_lookups maps a lookup ID to its workspace
	// and nothing else (ADR-0013); audit events have per-workspace hash
	// chains and insert-only grants (ADR-0011); jobs are leased by the
	// platform worker in the system scope.
	global := []string{"invitation_lookups", "audit_events", "jobs"}
	var tables []string
	for rows.Next() {
		var name string
		var rls, force bool
		if err := rows.Scan(&name, &rls, &force); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
		if !slices.Contains(global, name) && (!rls || !force) {
			t.Errorf("qali.%s has workspace_id but no forced row-level security", name)
		}
	}
	for _, want := range []string{"workspace_members", "invitations", "projects", "project_members"} {
		if !slices.Contains(tables, want) {
			t.Errorf("expected tenant table qali.%s", want)
		}
	}
}

// TestGuessedIDsNeverCrossWorkspaces proves MVP-05.AC-04: a member of one
// workspace who knows or guesses IDs from another gets 404 for every get,
// list, update, and delete, and listings never include foreign rows.
func TestGuessedIDsNeverCrossWorkspaces(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	_, testerID, _ := f.member("tester@example.org", "tester")
	public := f.project("PUB", "public")
	restricted := f.project("RES", "restricted")
	invToken := f.invite("pending@example.org", "viewer")
	_ = invToken
	invitations := f.owner.do(http.MethodGet, f.workspaceP+"/invitations", nil)
	invitationID := ids(invitations, "id")[0]

	// The intruder owns workspace B and is not a member of workspace A.
	intruder, intruderID, _ := f.member("intruder@example.org", "viewer")
	wsB := f.secondWorkspace(intruderID, "owner")
	f.enroll(intruder) // Owners must complete MFA (REVIEW-002)
	conn := connect(t, s.db.admin)
	if _, err := conn.Exec(t.Context(), "DELETE FROM qali.workspace_members WHERE workspace_id = $1 AND user_id = $2", f.workspace, intruderID); err != nil {
		t.Fatal(err)
	}
	a, b := f.workspaceP, "/api/v1/workspaces/"+wsB
	random := "/api/v1/workspaces/" + uuid.NewString()

	type call struct {
		method, path string
		body         map[string]any
		ifMatch      bool
	}
	calls := []call{
		{http.MethodGet, a, nil, false},
		{http.MethodGet, random, nil, false},
		{http.MethodGet, a + "/members", nil, false},
		{http.MethodPatch, a + "/members/" + testerID, map[string]any{"status": "deactivated"}, true},
		{http.MethodPatch, b + "/members/" + testerID, map[string]any{"status": "deactivated"}, true},
		{http.MethodGet, a + "/invitations", nil, false},
		{http.MethodPost, a + "/invitations", map[string]any{"email": "planted@example.org"}, false},
		{http.MethodPost, a + "/invitations/" + invitationID + "/revoke", nil, false},
		{http.MethodPost, b + "/invitations/" + invitationID + "/revoke", nil, false},
		{http.MethodGet, a + "/projects", nil, false},
		{http.MethodPost, a + "/projects", map[string]any{"code": "PLANT", "name": "Planted", "visibility": "public"}, false},
		{http.MethodGet, a + "/projects/" + public, nil, false},
		{http.MethodGet, b + "/projects/" + public, nil, false},
		{http.MethodGet, b + "/projects/" + restricted, nil, false},
		{http.MethodGet, b + "/projects/" + public + "/members", nil, false},
		{http.MethodPost, b + "/projects/" + public + "/members", map[string]any{"userId": intruderID, "level": "contributor"}, false},
		{http.MethodPatch, b + "/projects/" + restricted + "/members/" + f.ownerID, map[string]any{"level": "viewer"}, true},
		{http.MethodDelete, b + "/projects/" + restricted + "/members/" + f.ownerID, nil, true},
	}
	for _, c := range calls {
		headers := map[string]string{}
		if c.ifMatch {
			headers["If-Match"] = `"1"`
		}
		var body any
		if c.body != nil {
			body = c.body
		}
		r := intruder.doWith(c.method, c.path, body, headers)
		if r.status != http.StatusNotFound || r.code() != "not_found" {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.status, r.raw)
		}
	}

	// Listings in the intruder's own workspace contain only its rows.
	if got := ids(intruder.do(http.MethodGet, b+"/projects", nil), "id"); len(got) != 0 {
		t.Fatalf("foreign projects listed: %v", got)
	}
	if got := ids(intruder.do(http.MethodGet, b+"/members", nil), "userId"); !slices.Equal(got, []string{intruderID}) {
		t.Fatalf("foreign members listed: %v", got)
	}
	if got := ids(intruder.do(http.MethodGet, b+"/invitations", nil), "id"); len(got) != 0 {
		t.Fatalf("foreign invitations listed: %v", got)
	}
	if got := ids(intruder.do(http.MethodGet, "/api/v1/workspaces", nil), "id"); !slices.Equal(got, []string{wsB}) {
		t.Fatalf("foreign workspaces listed: %v", got)
	}
	// A project member cannot be added from another workspace either.
	if r := f.owner.do(http.MethodPost, a+"/projects/"+restricted+"/members", map[string]any{"userId": intruderID, "level": "viewer"}); r.status != http.StatusNotFound {
		t.Fatalf("non-member added to a project: %d %s", r.status, r.raw)
	}
	// Nothing changed in workspace A.
	if got := ids(f.owner.do(http.MethodGet, a+"/projects", nil), "id"); len(got) != 2 {
		t.Fatalf("workspace A projects: %v", got)
	}
	if got := ids(f.owner.do(http.MethodGet, a+"/invitations", nil), "id"); !slices.Equal(got, []string{invitationID}) {
		t.Fatalf("workspace A invitations: %v", got)
	}
}

// TestProjectVisibility covers public and restricted projects, direct
// levels, and the restricted creator rule.
func TestProjectVisibility(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	tester, testerID, _ := f.member("tester@example.org", "tester")
	public := f.project("PUB", "public")
	restricted := f.project("RES", "restricted")

	if got := ids(tester.do(http.MethodGet, f.workspaceP+"/projects", nil), "id"); !slices.Equal(got, []string{public}) {
		t.Fatalf("tester sees %v", got)
	}
	if got := ids(f.owner.do(http.MethodGet, f.workspaceP+"/projects", nil), "id"); !slices.Equal(got, []string{public, restricted}) {
		t.Fatalf("owner sees %v", got)
	}
	pub := tester.do(http.MethodGet, f.workspaceP+"/projects/"+public, nil)
	expect(t, pub, http.StatusOK)
	if p := permissionsOf(pub); !slices.Contains(splitPerms(p), "repository.update") || slices.Contains(splitPerms(p), "projects.manage_access") {
		t.Fatalf("tester permissions on a public project: %s", p)
	}
	expect(t, f.owner.do(http.MethodPost, f.workspaceP+"/projects/"+restricted+"/members", map[string]any{"userId": testerID, "level": "viewer"}), http.StatusCreated)
	res := tester.do(http.MethodGet, f.workspaceP+"/projects/"+restricted, nil)
	expect(t, res, http.StatusOK)
	if p := splitPerms(permissionsOf(res)); slices.Contains(p, "repository.update") || !slices.Contains(p, "repository.read") {
		t.Fatalf("a viewer level must cap the tester role: %v", p)
	}
	if r := f.owner.do(http.MethodPost, f.workspaceP+"/projects", map[string]any{"code": "PUB", "name": "Duplicate", "visibility": "public"}); r.status != http.StatusConflict || r.code() != "project_code_taken" {
		t.Fatalf("duplicate code: %d %s", r.status, r.raw)
	}
	if r := f.owner.do(http.MethodPost, f.workspaceP+"/projects", map[string]any{"code": "bad code", "name": "Bad", "visibility": "public"}); r.status != http.StatusBadRequest {
		t.Fatalf("invalid code: %d %s", r.status, r.raw)
	}

	// An administrator who creates a restricted project becomes its
	// contributor, so it does not disappear from their view.
	admin, _, adminTOTP := f.member("admin@example.org", "workspace_admin")
	_ = adminTOTP
	created := admin.do(http.MethodPost, f.workspaceP+"/projects", map[string]any{"code": "ADM", "name": "Admin project", "visibility": "restricted"})
	expect(t, created, http.StatusCreated)
	expect(t, admin.do(http.MethodGet, f.workspaceP+"/projects/"+created.body["id"].(string), nil), http.StatusOK)
	if r := admin.do(http.MethodGet, f.workspaceP+"/projects/"+restricted, nil); r.status != http.StatusNotFound {
		t.Fatalf("administrators need membership for restricted projects: %d", r.status)
	}
}

func splitPerms(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
