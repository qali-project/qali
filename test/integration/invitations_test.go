//go:build integration

package integration_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func acceptNew(s *authServer, token, password string) response {
	return s.client().do(http.MethodPost, "/api/v1/invitations/accept", map[string]any{"token": token, "displayName": "New Member", "password": password})
}

func expectInvalidInvitation(t *testing.T, name string, r response) {
	t.Helper()
	if r.status != http.StatusGone || r.code() != "invitation_invalid" {
		t.Fatalf("%s: %d %s", name, r.status, r.raw)
	}
	if _, ok := r.body["detail"]; ok {
		t.Fatalf("%s: rejections must not explain which check failed: %s", name, r.raw)
	}
}

// TestInvitationLifecycle proves MVP-05.AC-05: a valid invitation is
// accepted once; expired, revoked, superseded, replayed, tampered, and
// mismatched invitations are rejected uniformly.
func TestInvitationLifecycle(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()

	token := f.invite("New.Person@Example.org", "tester")
	if !strings.HasPrefix(token, "qali_inv_") {
		t.Fatalf("token format: %q", token)
	}
	preview := s.client().do(http.MethodPost, "/api/v1/invitations/preview", map[string]any{"token": token})
	expect(t, preview, http.StatusOK)
	if preview.body["email"] != "new.person@example.org" || preview.body["role"] != "tester" || preview.body["workspaceName"] != "Acme QA" {
		t.Fatalf("preview: %s", preview.raw)
	}
	accepted := acceptNew(s, token, ownerPassword)
	expect(t, accepted, http.StatusCreated)
	if accepted.state() != "active" {
		t.Fatalf("a tester without MFA requirement starts active: %s", accepted.raw)
	}
	expectInvalidInvitation(t, "replay", acceptNew(s, token, ownerPassword))
	expectInvalidInvitation(t, "preview after use", s.client().do(http.MethodPost, "/api/v1/invitations/preview", map[string]any{"token": token}))

	revoked := f.invite("revoked@example.org", "viewer")
	list := f.owner.do(http.MethodGet, f.workspaceP+"/invitations", nil)
	expect(t, list, http.StatusOK)
	if strings.Contains(list.raw, "qali_inv_") || strings.Contains(list.raw, "new.person@example.org") {
		t.Fatalf("listing must hide tokens and accepted invitations: %s", list.raw)
	}
	var revokedID string
	for _, it := range list.body["items"].([]any) {
		if m := it.(map[string]any); m["email"] == "revoked@example.org" {
			revokedID = m["id"].(string)
		}
	}
	expect(t, f.owner.do(http.MethodPost, f.workspaceP+"/invitations/"+revokedID+"/revoke", nil), http.StatusNoContent)
	expectInvalidInvitation(t, "revoked", acceptNew(s, revoked, ownerPassword))
	if r := f.owner.do(http.MethodPost, f.workspaceP+"/invitations/"+revokedID+"/revoke", nil); r.status != http.StatusNotFound {
		t.Fatalf("revoking twice: %d", r.status)
	}

	superseded := f.invite("twice@example.org", "viewer")
	current := f.invite("twice@example.org", "qa_lead")
	expectInvalidInvitation(t, "superseded", acceptNew(s, superseded, ownerPassword))
	expect(t, acceptNew(s, current, ownerPassword), http.StatusCreated)

	tampered := f.invite("tamper@example.org", "viewer")
	forged := tampered[:len(tampered)-4] + "AAAA"
	if forged == tampered {
		forged = tampered[:len(tampered)-4] + "BBBB"
	}
	expectInvalidInvitation(t, "tampered", acceptNew(s, forged, ownerPassword))
	expectInvalidInvitation(t, "garbage", acceptNew(s, "qali_inv_nonsense", ownerPassword))
	expectInvalidInvitation(t, "unknown", acceptNew(s, "qali_inv_aaaaaaaaaaaaaaaa_"+strings.Repeat("A", 43), ownerPassword))
	expect(t, acceptNew(s, tampered, ownerPassword), http.StatusCreated) // the real token still works

	// Existing accounts: the signed-in email must match.
	mismatch := f.invite("someone-else@example.org", "viewer")
	member := s.login("new.person@example.org", ownerPassword, "")
	expectInvalidInvitation(t, "mismatched account", member.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": mismatch}))
	if r := acceptNew(s, f.invite("owner@example.org", "viewer"), ownerPassword); r.status != http.StatusConflict || r.code() != "account_exists" {
		t.Fatalf("new-account acceptance for an existing email: %d %s", r.status, r.raw)
	}
	if r := f.owner.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": f.invite("owner@example.org", "viewer")}); r.status != http.StatusConflict || r.code() != "already_member" {
		t.Fatalf("existing member accepting again: %d %s", r.status, r.raw)
	}

	// Last, because it also outlives every session: expiry after 7 days.
	expired := f.invite("late@example.org", "viewer")
	s.clock.Advance(7*24*time.Hour - time.Minute)
	if r := f.owner.do(http.MethodGet, f.workspaceP+"/invitations", nil); r.status == http.StatusOK && !strings.Contains(r.raw, "late@example.org") {
		t.Fatalf("an unexpired invitation is listed: %s", r.raw)
	}
	s.clock.Advance(time.Minute)
	expectInvalidInvitation(t, "expired", acceptNew(s, expired, ownerPassword))
}

// TestInvitationForExistingAccount joins a user who belongs only to another
// workspace, and keeps reactivation an administrator decision.
func TestInvitationForExistingAccount(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	other, otherID, _ := f.member("other@example.org", "viewer")
	ws2 := f.secondWorkspace(otherID, "viewer")
	// Fixture: the user now belongs to the second workspace only.
	conn := connect(t, s.db.admin)
	if _, err := conn.Exec(t.Context(), "DELETE FROM qali.workspace_members WHERE workspace_id = $1 AND user_id = $2", f.workspace, otherID); err != nil {
		t.Fatal(err)
	}
	token := f.invite("other@example.org", "qa_lead")
	joined := other.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": token})
	expect(t, joined, http.StatusOK)
	if joined.body["id"] != f.workspace || joined.body["role"] != "qa_lead" {
		t.Fatalf("joined workspace: %s", joined.raw)
	}
	if got := ids(other.do(http.MethodGet, "/api/v1/workspaces", nil), "id"); len(got) != 2 || !slices.Contains(got, ws2) {
		t.Fatalf("workspaces after joining: %v", got)
	}
	expectInvalidInvitation(t, "replay", other.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": token}))

	// A deactivated member is reactivated by an administrator, not by an
	// invitation.
	expect(t, f.patchMember(f.owner, otherID, f.memberVersion(f.owner, otherID), map[string]any{"status": "deactivated"}), http.StatusOK)
	if r := other.do(http.MethodPost, "/api/v1/invitations/accept-existing", map[string]any{"token": f.invite("other@example.org", "tester")}); r.status != http.StatusConflict || r.code() != "already_member" {
		t.Fatalf("deactivated member accepted an invitation: %d %s", r.status, r.raw)
	}
}

// TestInvitationRules covers role limits and validation.
func TestInvitationRules(t *testing.T) {
	s := newAuthServer(t)
	f := s.adminFixture()
	expect(t, f.stepUp(f.owner, f.ownerTOTP), http.StatusOK)
	for name, body := range map[string]map[string]any{
		"owner role":    {"email": "x@example.org", "role": "owner"},
		"invalid email": {"email": "not-an-email"},
		"unknown field": {"email": "x@example.org", "admin": true},
	} {
		if r := f.owner.do(http.MethodPost, f.workspaceP+"/invitations", body); r.status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	created := f.owner.do(http.MethodPost, f.workspaceP+"/invitations", map[string]any{"email": "default@example.org"})
	expect(t, created, http.StatusCreated)
	inv := created.body["invitation"].(map[string]any)
	if inv["role"] != "tester" || inv["invitedBy"] != f.ownerID {
		t.Fatalf("default invitation: %s", created.raw)
	}
	if created.header.Get("Cache-Control") != "no-store" {
		t.Fatal("responses carrying a token must not be cached")
	}

	// The raw token is never stored.
	token := created.body["token"].(string)
	conn := connect(t, s.db.admin)
	var n int
	if err := conn.QueryRow(t.Context(), "SELECT count(*) FROM qali.invitations WHERE position($1 in row_to_json(invitations)::text) > 0", token[len("qali_inv_")+17:]).Scan(&n); err != nil || n != 0 {
		t.Fatalf("token secret stored: %d %v", n, err)
	}
	var audited int
	if err := conn.QueryRow(t.Context(), "SELECT count(*) FROM qali.audit_events WHERE action = 'invitation.create'").Scan(&audited); err != nil || audited == 0 {
		t.Fatalf("invitation creation not audited: %d %v", audited, err)
	}
}
