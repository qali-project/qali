//go:build integration

package integration_test

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/authz"
)

// TestLastOwnerAndOwnerOnlyRules proves MVP-05.AC-06: the last active Owner
// cannot be demoted or deactivated, and Administrators cannot change Owners
// or grant ownership.
func TestLastOwnerAndOwnerOnlyRules(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()

	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	v := f.memberVersion(f.owner, f.ownerID)
	if r := f.patchMember(f.owner, f.ownerID, v, map[string]any{"role": "workspace_admin"}); r.status != http.StatusConflict || r.code() != "last_owner" {
		t.Fatalf("demoting the last owner: %d %s", r.status, r.raw)
	}
	if r := f.patchMember(f.owner, f.ownerID, v, map[string]any{"status": "deactivated"}); r.status != http.StatusConflict || r.code() != "last_owner" {
		t.Fatalf("deactivating the last owner: %d %s", r.status, r.raw)
	}

	admin, adminID, adminTOTP := f.member("admin@example.org", "workspace_admin")
	_, testerID, _ := f.member("tester@example.org", "tester")
	expect(t, f.stepUp(admin, adminTOTP), http.StatusOK)
	ownerV := f.memberVersion(admin, f.ownerID)
	for name, body := range map[string]map[string]any{
		"demote owner":     {"role": "tester"},
		"deactivate owner": {"status": "deactivated"},
	} {
		if r := f.patchMember(admin, f.ownerID, ownerV, body); r.status != http.StatusForbidden || r.code() != "forbidden" {
			t.Fatalf("admin may not %s: %d %s", name, r.status, r.raw)
		}
	}
	if r := f.patchMember(admin, testerID, f.memberVersion(admin, testerID), map[string]any{"role": "owner"}); r.status != http.StatusForbidden {
		t.Fatalf("admin granted ownership: %d %s", r.status, r.raw)
	}
	if r := f.patchMember(admin, adminID, f.memberVersion(admin, adminID), map[string]any{"role": "owner"}); r.status != http.StatusForbidden {
		t.Fatalf("admin promoted self to owner: %d %s", r.status, r.raw)
	}

	// With a second Owner, the first may step down.
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	expect(t, f.patchMember(f.owner, adminID, f.memberVersion(f.owner, adminID), map[string]any{"role": "owner"}), http.StatusOK)
	expect(t, f.patchMember(f.owner, f.ownerID, f.memberVersion(f.owner, f.ownerID), map[string]any{"role": "workspace_admin"}), http.StatusOK)
}

// TestRoleAndMembershipChangesApplyToTheNextRequest proves MVP-05.AC-07.
func TestRoleAndMembershipChangesApplyToTheNextRequest(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	tester, testerID, _ := f.member("tester@example.org", "tester")
	restricted := f.project("SEC", "restricted")

	if r := tester.do(http.MethodGet, f.workspaceP+"/members", nil); r.status != http.StatusForbidden {
		t.Fatalf("tester listed members: %d", r.status)
	}
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"role": "workspace_admin"}), http.StatusOK)
	// The promotion applies at once, and so does its MFA requirement
	// (REVIEW-002): the old session must enroll before it may administer.
	if r := tester.do(http.MethodGet, f.workspaceP+"/members", nil); r.status != http.StatusForbidden || r.code() != "mfa_required" {
		t.Fatalf("promoted member without MFA: %d %s", r.status, r.raw)
	}
	f.enroll(tester)
	expect(t, tester.do(http.MethodGet, f.workspaceP+"/members", nil), http.StatusOK)
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"role": "viewer"}), http.StatusOK)
	if r := tester.do(http.MethodGet, f.workspaceP+"/members", nil); r.status != http.StatusForbidden {
		t.Fatalf("downgraded member kept access: %d", r.status)
	}

	// Direct project membership: granted, then removed.
	if r := tester.do(http.MethodGet, f.workspaceP+"/projects/"+restricted, nil); r.status != http.StatusNotFound {
		t.Fatalf("restricted project visible to a non-member: %d", r.status)
	}
	add := f.owner.do(http.MethodPost, f.workspaceP+"/projects/"+restricted+"/members", map[string]any{"userId": testerID, "level": "viewer"})
	expect(t, add, http.StatusCreated)
	expect(t, tester.do(http.MethodGet, f.workspaceP+"/projects/"+restricted, nil), http.StatusOK)
	expect(t, f.owner.doWith(http.MethodDelete, f.workspaceP+"/projects/"+restricted+"/members/"+testerID, nil,
		map[string]string{"If-Match": add.header.Get("ETag")}), http.StatusNoContent)
	if r := tester.do(http.MethodGet, f.workspaceP+"/projects/"+restricted, nil); r.status != http.StatusNotFound {
		t.Fatalf("removed project member kept access: %d", r.status)
	}

	// Deactivation blocks the workspace at once; reactivation restores it.
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"status": "deactivated"}), http.StatusOK)
	for _, path := range []string{f.workspaceP, f.workspaceP + "/projects"} {
		if r := tester.do(http.MethodGet, path, nil); r.status != http.StatusNotFound {
			t.Fatalf("deactivated member reached %s: %d", path, r.status)
		}
	}
	if r := tester.do(http.MethodGet, "/api/v1/workspaces", nil); len(ids(r, "id")) != 0 {
		t.Fatalf("deactivated workspace still listed: %s", r.raw)
	}
	expect(t, tester.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // the session itself remains valid
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"status": "active"}), http.StatusOK)
	expect(t, tester.do(http.MethodGet, f.workspaceP, nil), http.StatusOK)
}

// TestSensitiveActionsRequireRecentMFA proves MVP-05.AC-08.
func TestSensitiveActionsRequireRecentMFA(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	_, testerID, _ := f.member("tester@example.org", "tester")

	s.clock.Advance(11 * time.Minute)
	v := f.memberVersion(f.owner, testerID)
	if r := f.patchMember(f.owner, testerID, v, map[string]any{"role": "qa_lead"}); r.status != http.StatusForbidden || r.code() != "recent_mfa_required" {
		t.Fatalf("role change without recent MFA: %d %s", r.status, r.raw)
	}
	if r := f.owner.do(http.MethodPost, f.workspaceP+"/invitations", map[string]any{"email": "admin2@example.org", "role": "workspace_admin"}); r.status != http.StatusForbidden || r.code() != "recent_mfa_required" {
		t.Fatalf("administrator invitation without recent MFA: %d %s", r.status, r.raw)
	}
	// Non-sensitive administration does not need a step-up.
	expect(t, f.owner.do(http.MethodPost, f.workspaceP+"/invitations", map[string]any{"email": "tester2@example.org"}), http.StatusCreated)

	if r := f.owner.do(http.MethodPost, "/api/v1/auth/mfa/step-up", map[string]any{"code": "000000"}); r.status != http.StatusUnauthorized || r.code() != "invalid_code" {
		t.Fatalf("step-up with a wrong code: %d %s", r.status, r.raw)
	}
	before := f.owner.cookie()
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	if f.owner.cookie() == before {
		t.Fatal("step-up must rotate the session")
	}
	stale := s.client()
	stale.http.Jar.SetCookies(jarURL(s), []*http.Cookie{{Name: "__Host-qali_session", Value: before, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}})
	if r := stale.do(http.MethodGet, "/api/v1/auth/session", nil); r.status != http.StatusUnauthorized {
		t.Fatalf("pre-step-up session still valid: %d", r.status)
	}
	r := f.patchMember(f.owner, testerID, v, map[string]any{"role": "qa_lead"})
	expect(t, r, http.StatusOK)
	if r.body["role"] != "qa_lead" || r.header.Get("ETag") != `"2"` {
		t.Fatalf("updated member: %s etag %s", r.raw, r.header.Get("ETag"))
	}

	s.clock.Advance(10 * time.Minute)
	if r := f.patchMember(f.owner, testerID, `"2"`, map[string]any{"role": "tester"}); r.code() != "recent_mfa_required" {
		t.Fatalf("recent MFA must expire after 10 minutes: %d %s", r.status, r.raw)
	}
}

// TestMemberUpdatesUseOptimisticConcurrency covers If-Match (ADR-0003).
func TestMemberUpdatesUseOptimisticConcurrency(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	_, testerID, _ := f.member("tester@example.org", "tester")
	if r := f.patchMember(f.owner, testerID, "", map[string]any{"status": "deactivated"}); r.status != http.StatusPreconditionRequired || r.code() != "if_match_required" {
		t.Fatalf("missing If-Match: %d %s", r.status, r.raw)
	}
	if r := f.patchMember(f.owner, testerID, `"7"`, map[string]any{"status": "deactivated"}); r.status != http.StatusPreconditionFailed || r.code() != "version_mismatch" {
		t.Fatalf("stale If-Match: %d %s", r.status, r.raw)
	}
	if r := f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{}); r.status != http.StatusBadRequest {
		t.Fatalf("empty patch: %d %s", r.status, r.raw)
	}
	if r := f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"role": "superuser"}); r.status != http.StatusBadRequest {
		t.Fatalf("unknown role: %d %s", r.status, r.raw)
	}
}

// TestMembersAndWorkspaceDescribeTheCaller checks listings and the
// permission list the UI uses to hide controls.
func TestMembersAndWorkspaceDescribeTheCaller(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	tester, testerID, _ := f.member("tester@example.org", "tester")
	_, viewerID, _ := f.member("viewer@example.org", "viewer")

	ws := tester.do(http.MethodGet, f.workspaceP, nil)
	expect(t, ws, http.StatusOK)
	if ws.body["role"] != "tester" || !slices.Contains(splitPerms(permissionsOf(ws)), "workspace.read") {
		t.Fatalf("tester workspace view: %s", ws.raw)
	}
	for _, p := range splitPerms(permissionsOf(ws)) {
		if authz.Info(authz.Permission(p)).Administrative {
			t.Fatalf("tester holds administrative %s", p)
		}
	}
	own := f.owner.do(http.MethodGet, f.workspaceP, nil)
	if own.body["role"] != "owner" || permissionsOf(own) == "workspace.read" {
		t.Fatalf("owner workspace view: %s", own.raw)
	}

	// Pagination walks every member exactly once.
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 5; page++ {
		path := f.workspaceP + "/members?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := f.owner.do(http.MethodGet, path, nil)
		expect(t, r, http.StatusOK)
		for _, id := range ids(r, "userId") {
			if seen[id] {
				t.Fatalf("member %s listed twice", id)
			}
			seen[id] = true
		}
		next, _ := r.body["nextCursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	for _, id := range []string{f.ownerID, testerID, viewerID} {
		if !seen[id] {
			t.Fatalf("member %s missing from pages: %v", id, seen)
		}
	}
	if r := f.owner.do(http.MethodGet, f.workspaceP+"/members?cursor=tampered", nil); r.status != http.StatusBadRequest || r.code() != "invalid_cursor" {
		t.Fatalf("tampered cursor: %d %s", r.status, r.raw)
	}
	// A cursor is bound to the principal and the listing.
	first := f.owner.do(http.MethodGet, f.workspaceP+"/members?limit=1", nil)
	next, _ := first.body["nextCursor"].(string)
	if r := f.owner.do(http.MethodGet, f.workspaceP+"/projects?cursor="+next, nil); r.status != http.StatusBadRequest {
		t.Fatalf("cursor reused for another listing: %d", r.status)
	}
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"role": "workspace_admin"}), http.StatusOK)
	f.enroll(tester)
	if r := tester.do(http.MethodGet, f.workspaceP+"/members?cursor="+next, nil); r.status != http.StatusBadRequest {
		t.Fatalf("cursor reused by another principal: %d", r.status)
	}
}

// TestPromotionToPrivilegedRoleRequiresMFA proves REVIEW-002: a session
// created while its user needed no MFA cannot use Owner or Workspace
// Administrator permissions until the user completes MFA, whether the role
// comes from a promotion or from accepting an invitation.
func TestPromotionToPrivilegedRoleRequiresMFA(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	tester, testerID, _ := f.member("tester@example.org", "tester")
	if st := tester.do(http.MethodGet, "/api/v1/auth/session", nil).state(); st != "active" {
		t.Fatalf("tester session state %q", st)
	}

	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	expect(t, f.patchMember(f.owner, testerID, f.memberVersion(f.owner, testerID), map[string]any{"role": "owner"}), http.StatusOK)
	if st := tester.do(http.MethodGet, "/api/v1/auth/session", nil).state(); st != "mfa_enrollment" {
		t.Fatalf("promoted session must require MFA enrollment, got %q", st)
	}
	for _, path := range []string{f.workspaceP, f.workspaceP + "/members", f.workspaceP + "/invitations", "/api/v1/workspaces"} {
		if r := tester.do(http.MethodGet, path, nil); r.status != http.StatusForbidden || r.code() != "mfa_required" {
			t.Fatalf("%s before MFA: %d %s", path, r.status, r.raw)
		}
	}
	if r := tester.do(http.MethodPost, f.workspaceP+"/invitations", map[string]any{"email": "x@example.org"}); r.code() != "mfa_required" {
		t.Fatalf("invite before MFA: %d %s", r.status, r.raw)
	}
	f.enroll(tester)
	expect(t, tester.do(http.MethodGet, f.workspaceP+"/members", nil), http.StatusOK)
	expect(t, tester.do(http.MethodGet, "/api/v1/workspaces", nil), http.StatusOK)

	// Joining with an administrative role through an invitation.
	other, otherID, _ := f.member("other@example.org", "viewer")
	f.secondWorkspace(otherID, "viewer")
	conn := connect(t, s.db.admin)
	if _, err := conn.Exec(t.Context(), "DELETE FROM qali.workspace_members WHERE workspace_id = $1 AND user_id = $2", f.workspace, otherID); err != nil {
		t.Fatal(err)
	}
	if st := other.do(http.MethodGet, "/api/v1/auth/session", nil).state(); st != "active" {
		t.Fatalf("viewer session state %q", st)
	}
	expect(t, other.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": f.invite("other@example.org", "workspace_admin")}), http.StatusOK)
	if r := other.do(http.MethodGet, f.workspaceP+"/members", nil); r.code() != "mfa_required" {
		t.Fatalf("administrator by invitation without MFA: %d %s", r.status, r.raw)
	}
}
