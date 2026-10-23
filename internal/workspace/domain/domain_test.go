package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
	"github.com/qali-project/qali/internal/workspace/domain"
)

func role(r authz.Role) *authz.Role { return &r }
func active(b bool) *bool           { return &b }

func TestMemberChangeOwnershipRules(t *testing.T) {
	owner := domain.Member{UserID: uuid.New(), Role: authz.RoleOwner, Active: true}
	tester := domain.Member{UserID: uuid.New(), Role: authz.RoleTester, Active: true}
	inactiveOwner := domain.Member{UserID: uuid.New(), Role: authz.RoleOwner, Active: false}
	cases := []struct {
		name   string
		actor  authz.Role
		target domain.Member
		change domain.MemberChange
		owners int
		want   error
	}{
		{"owner demotes the last owner", authz.RoleOwner, owner, domain.MemberChange{Role: role(authz.RoleTester)}, 1, domain.ErrLastOwner},
		{"owner deactivates the last owner", authz.RoleOwner, owner, domain.MemberChange{Active: active(false)}, 1, domain.ErrLastOwner},
		{"owner demotes one of two owners", authz.RoleOwner, owner, domain.MemberChange{Role: role(authz.RoleWorkspaceAdmin)}, 2, nil},
		{"owner keeps the owner role", authz.RoleOwner, owner, domain.MemberChange{Role: role(authz.RoleOwner)}, 1, nil},
		{"owner reactivates an owner", authz.RoleOwner, inactiveOwner, domain.MemberChange{Active: active(true)}, 1, nil},
		{"owner demotes an inactive owner", authz.RoleOwner, inactiveOwner, domain.MemberChange{Role: role(authz.RoleTester)}, 1, nil},
		{"owner grants ownership", authz.RoleOwner, tester, domain.MemberChange{Role: role(authz.RoleOwner)}, 1, nil},
		{"admin grants ownership", authz.RoleWorkspaceAdmin, tester, domain.MemberChange{Role: role(authz.RoleOwner)}, 1, domain.ErrOwnerOnly},
		{"admin demotes an owner", authz.RoleWorkspaceAdmin, owner, domain.MemberChange{Role: role(authz.RoleTester)}, 3, domain.ErrOwnerOnly},
		{"admin deactivates an owner", authz.RoleWorkspaceAdmin, owner, domain.MemberChange{Active: active(false)}, 3, domain.ErrOwnerOnly},
		{"admin reactivates an owner", authz.RoleWorkspaceAdmin, inactiveOwner, domain.MemberChange{Active: active(true)}, 1, domain.ErrOwnerOnly},
		{"admin changes a tester", authz.RoleWorkspaceAdmin, tester, domain.MemberChange{Role: role(authz.RoleQALead), Active: active(false)}, 1, nil},
		{"empty change", authz.RoleOwner, tester, domain.MemberChange{}, 1, domain.ErrInvalidInput},
		{"unknown role", authz.RoleOwner, tester, domain.MemberChange{Role: role("superuser")}, 1, domain.ErrInvalidInput},
	}
	for _, c := range cases {
		if got := domain.CheckMemberChange(c.actor, c.target, c.change, c.owners); !errors.Is(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestInvitationState(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	inv := domain.NewInvitationWindow(now)
	if !inv.Pending(now) || !inv.Pending(now.Add(domain.InvitationLifetime-time.Second)) {
		t.Fatal("a fresh invitation is pending for 7 days")
	}
	if inv.Pending(now.Add(domain.InvitationLifetime)) {
		t.Fatal("an invitation expires after 7 days")
	}
	used := inv
	used.AcceptedAt = &now
	revoked := inv
	revoked.RevokedAt = &now
	if used.Pending(now) || revoked.Pending(now) {
		t.Fatal("used and revoked invitations are not pending")
	}
}

func TestInvitableRoles(t *testing.T) {
	for r, want := range map[authz.Role]bool{
		authz.RoleOwner: false, authz.RoleWorkspaceAdmin: true, authz.RoleQALead: true,
		authz.RoleTester: true, authz.RoleViewer: true, "superuser": false, "": false,
	} {
		if domain.Invitable(r) != want {
			t.Errorf("Invitable(%q) != %v", r, want)
		}
	}
}

func TestProjectValidation(t *testing.T) {
	for code, want := range map[string]bool{
		"WEB": true, "A1": true, "ABCDEFGHIJ": true, "A": false, "ABCDEFGHIJK": false,
		"1AB": false, "web": false, "WE B": false, "": false, "WÉB": false,
	} {
		if domain.ValidProjectCode(code) != want {
			t.Errorf("ValidProjectCode(%q) != %v", code, want)
		}
	}
	if _, err := domain.CleanProjectName("  Web app  "); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "   ", string(make([]rune, 121))} {
		if _, err := domain.CleanProjectName(bad); !errors.Is(err, domain.ErrInvalidInput) {
			t.Errorf("CleanProjectName(%q) accepted", bad)
		}
	}
	if !domain.ValidVisibility(authz.Public) || !domain.ValidVisibility(authz.Restricted) || domain.ValidVisibility("secret") {
		t.Fatal("visibility validation")
	}
	if !domain.ValidLevel(authz.Contributor) || !domain.ValidLevel(authz.Viewer) || domain.ValidLevel("admin") {
		t.Fatal("level validation")
	}
}
