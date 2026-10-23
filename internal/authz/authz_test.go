package authz_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/authz"
)

var (
	me    = uuid.MustParse("0199f0c2-1111-7000-8000-000000000001")
	other = uuid.MustParse("0199f0c2-1111-7000-8000-000000000002")
)

func principal(role authz.Role) authz.Principal {
	return authz.Principal{UserID: me, Role: role, Active: true, RecentMFA: true}
}

// ownProject satisfies every project, own, and assigned condition.
func favorable() authz.Resource {
	return authz.Resource{
		Project:   &authz.ProjectAccess{Visibility: authz.Public},
		CreatedBy: me,
		Assignee:  &me,
	}
}

type catalog struct {
	Permissions []struct {
		ID             string `json:"id"`
		Kind           string `json:"kind"`
		Scope          string `json:"scope"`
		Administrative bool   `json:"administrative"`
		Sensitive      bool   `json:"sensitive"`
		OwnerOnly      bool   `json:"ownerOnly"`
	} `json:"permissions"`
	Roles []struct {
		ID     string            `json:"id"`
		Grants map[string]string `json:"grants"`
	} `json:"roles"`
}

func loadCatalog(t *testing.T) catalog {
	t.Helper()
	b, err := os.ReadFile("../../docs/rbac/permission-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var c catalog
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEveryRolePermissionPairMatchesTheCatalog proves the first half of
// MVP-05.AC-01: 5 roles x every permission, decided from generated tables,
// agree with the reviewed JSON catalog, including own/assigned conditions.
func TestEveryRolePermissionPairMatchesTheCatalog(t *testing.T) {
	c := loadCatalog(t)
	if len(authz.Permissions()) != len(c.Permissions) {
		t.Fatalf("generated %d permissions, catalog has %d; run make generate", len(authz.Permissions()), len(c.Permissions))
	}
	pairs := 0
	for _, role := range c.Roles {
		for _, p := range c.Permissions {
			pairs++
			perm := authz.Permission(p.ID)
			condition, granted := role.Grants[p.ID]
			got := authz.Decide(principal(authz.Role(role.ID)), perm, favorable())
			if granted != (got == authz.Allow) {
				t.Fatalf("%s %s: decision %v, catalog grant %v", role.ID, p.ID, got, granted)
			}
			if !granted || p.Scope != "project" {
				continue
			}
			foreign := favorable()
			foreign.CreatedBy = other
			foreign.Assignee = &other
			want := authz.Allow
			if condition != "all" {
				want = authz.Forbidden
			}
			if got := authz.Decide(principal(authz.Role(role.ID)), perm, foreign); got != want {
				t.Fatalf("%s %s (%s) on another user's resource: %v, want %v", role.ID, p.ID, condition, got, want)
			}
		}
	}
	if pairs != 5*len(c.Permissions) {
		t.Fatalf("covered %d pairs", pairs)
	}
}

// administration is written by hand, independent of the catalog, so a
// catalog change that leaks administration fails here (MVP-05 acceptance:
// users, roles, security, integration, credential, project-access, and
// project-settings administration).
var administration = []authz.Permission{
	"workspace.update", "workspace.transfer_ownership",
	"security.read", "security.update", "security.manage_sso", "security.manage_sessions", "security.manage_break_glass",
	"members.read", "members.invite", "members.update_role", "members.deactivate",
	"projects.create", "projects.update", "projects.archive", "projects.manage_access",
	"integrations.read", "integrations.install", "integrations.configure", "integrations.rotate_secret",
	"integrations.retry_delivery", "integrations.remove",
	"credentials.manage_ci", "audit.read", "audit.export", "operations.read_diagnostics", "operations.manage_jobs",
}

func TestNonAdministrativeRolesNeverAdminister(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleQALead, authz.RoleTester, authz.RoleViewer} {
		for _, perm := range administration {
			if got := authz.Decide(principal(role), perm, favorable()); got == authz.Allow {
				t.Fatalf("%s may %s", role, perm)
			}
		}
	}
	for _, perm := range []authz.Permission{"workspace.transfer_ownership", "security.manage_break_glass"} {
		if got := authz.Decide(principal(authz.RoleWorkspaceAdmin), perm, favorable()); got == authz.Allow {
			t.Fatalf("workspace administrator may %s (owner-only)", perm)
		}
		if got := authz.Decide(principal(authz.RoleOwner), perm, favorable()); got != authz.Allow {
			t.Fatalf("owner may not %s", perm)
		}
	}
}

func TestViewerNeverWrites(t *testing.T) {
	for _, perm := range authz.Permissions() {
		if authz.Info(perm).Kind == authz.Write && authz.Decide(principal(authz.RoleViewer), perm, favorable()) == authz.Allow {
			t.Fatalf("viewer may %s", perm)
		}
	}
}

// TestProjectAccessIntersectsWithRole proves MVP-05.AC-02 for project
// visibility and access levels.
func TestProjectAccessIntersectsWithRole(t *testing.T) {
	restricted := func(level authz.AccessLevel) authz.Resource {
		r := favorable()
		r.Project = &authz.ProjectAccess{Visibility: authz.Restricted, MemberLevel: level}
		return r
	}
	public := func(level authz.AccessLevel) authz.Resource {
		r := favorable()
		r.Project = &authz.ProjectAccess{Visibility: authz.Public, MemberLevel: level}
		return r
	}
	cases := []struct {
		name string
		role authz.Role
		perm authz.Permission
		res  authz.Resource
		want authz.Decision
	}{
		{"owner sees restricted without membership", authz.RoleOwner, "repository.update", restricted(""), authz.Allow},
		{"admin does not see restricted without membership", authz.RoleWorkspaceAdmin, "projects.read", restricted(""), authz.NotFound},
		{"admin member of restricted", authz.RoleWorkspaceAdmin, "projects.manage_access", restricted(authz.Contributor), authz.Allow},
		{"tester not a member of restricted", authz.RoleTester, "repository.read", restricted(""), authz.NotFound},
		{"tester contributor of restricted", authz.RoleTester, "repository.update", restricted(authz.Contributor), authz.Allow},
		{"tester viewer level cannot write", authz.RoleTester, "repository.update", restricted(authz.Viewer), authz.Forbidden},
		{"tester viewer level can read", authz.RoleTester, "repository.read", restricted(authz.Viewer), authz.Allow},
		{"public project implies contributor", authz.RoleTester, "repository.create", public(""), authz.Allow},
		{"public viewer membership caps writes", authz.RoleQALead, "runs.create", public(authz.Viewer), authz.Forbidden},
		{"contributor level cannot elevate a viewer role", authz.RoleViewer, "repository.update", restricted(authz.Contributor), authz.Forbidden},
		{"contributor level cannot grant administration", authz.RoleTester, "projects.manage_access", restricted(authz.Contributor), authz.Forbidden},
		{"invisible project hides even denied permissions", authz.RoleViewer, "projects.manage_access", restricted(""), authz.NotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authz.Decide(principal(c.role), c.perm, c.res); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestConditions(t *testing.T) {
	res := favorable()
	res.Assignee = nil // unassigned run cases may be executed
	if got := authz.Decide(principal(authz.RoleTester), "results.submit_manual", res); got != authz.Allow {
		t.Fatalf("unassigned: %v", got)
	}
	res.Assignee = &other
	if got := authz.Decide(principal(authz.RoleTester), "results.submit_manual", res); got != authz.Forbidden {
		t.Fatalf("assigned to someone else: %v", got)
	}
	if got := authz.Decide(principal(authz.RoleQALead), "results.submit_manual", res); got != authz.Allow {
		t.Fatalf("QA lead has condition all: %v", got)
	}
}

func TestCredentialScopeIntersects(t *testing.T) {
	p := principal(authz.RoleOwner)
	p.Limit = map[authz.Permission]bool{"projects.read": true}
	if got := authz.Decide(p, "projects.read", favorable()); got != authz.Allow {
		t.Fatalf("scoped permission: %v", got)
	}
	if got := authz.Decide(p, "repository.read", favorable()); got != authz.Forbidden {
		t.Fatalf("a credential scope must narrow the owner's role: %v", got)
	}
	p.Limit = map[authz.Permission]bool{}
	if got := authz.Decide(p, "projects.read", favorable()); got != authz.Forbidden {
		t.Fatalf("an empty scope set allows nothing: %v", got)
	}
}

func TestSensitivePermissionsNeedRecentMFA(t *testing.T) {
	p := principal(authz.RoleOwner)
	p.RecentMFA = false
	if got := authz.Decide(p, "members.update_role", favorable()); got != authz.RecentMFARequired {
		t.Fatalf("sensitive without recent MFA: %v", got)
	}
	if got := authz.Decide(p, "members.read", favorable()); got != authz.Allow {
		t.Fatalf("non-sensitive without recent MFA: %v", got)
	}
	tester := principal(authz.RoleTester)
	tester.RecentMFA = false
	if got := authz.Decide(tester, "members.update_role", favorable()); got != authz.Forbidden {
		t.Fatalf("missing grant must win over the MFA prompt: %v", got)
	}
}

func TestDenyByDefault(t *testing.T) {
	inactive := principal(authz.RoleOwner)
	inactive.Active = false
	if got := authz.Decide(inactive, "workspace.read", favorable()); got != authz.NotFound {
		t.Fatalf("inactive member: %v", got)
	}
	if got := authz.Decide(principal(authz.RoleOwner), "runs.fly", favorable()); got != authz.Forbidden {
		t.Fatalf("unknown permission: %v", got)
	}
	if got := authz.Decide(principal("intern"), "workspace.read", favorable()); got != authz.Forbidden {
		t.Fatalf("unknown role: %v", got)
	}
	if got := authz.Decide(principal(authz.RoleOwner), "repository.read", authz.Resource{}); got != authz.Forbidden {
		t.Fatalf("project permission without a project: %v", got)
	}
	if got := authz.Decide(principal(authz.RoleTester), "workspace.read", authz.Resource{}); got != authz.Allow {
		t.Fatalf("workspace permission needs no project: %v", got)
	}
}

func TestProjectVisibility(t *testing.T) {
	if !authz.CanSeeProject(principal(authz.RoleViewer), authz.ProjectAccess{Visibility: authz.Public}) {
		t.Fatal("public projects are visible to members")
	}
	if authz.CanSeeProject(principal(authz.RoleWorkspaceAdmin), authz.ProjectAccess{Visibility: authz.Restricted}) {
		t.Fatal("restricted projects are hidden from non-member administrators")
	}
	if !authz.CanSeeProject(principal(authz.RoleOwner), authz.ProjectAccess{Visibility: authz.Restricted}) {
		t.Fatal("owners see every project")
	}
	inactive := principal(authz.RoleOwner)
	inactive.Active = false
	if authz.CanSeeProject(inactive, authz.ProjectAccess{Visibility: authz.Public}) {
		t.Fatal("inactive members see nothing")
	}
}

// An Owner is never narrowed by a project membership level: capping the
// Owner would only risk locking them out of managing access, while the
// intersection rule exists to stop memberships from elevating other roles.
func TestOwnerIsNotCappedByMembershipLevel(t *testing.T) {
	r := favorable()
	r.Project = &authz.ProjectAccess{Visibility: authz.Restricted, MemberLevel: authz.Viewer}
	for _, perm := range []authz.Permission{"repository.update", "projects.manage_access", "repository.read"} {
		if got := authz.Decide(principal(authz.RoleOwner), perm, r); got != authz.Allow {
			t.Fatalf("owner with a viewer level: %s %v", perm, got)
		}
	}
	if got := authz.Decide(principal(authz.RoleWorkspaceAdmin), "repository.update", r); got != authz.Forbidden {
		t.Fatalf("other roles stay capped: %v", got)
	}
}

func TestDecisionNames(t *testing.T) {
	for d, want := range map[authz.Decision]string{
		authz.Allow: "allow", authz.NotFound: "not_found", authz.Forbidden: "forbidden",
		authz.RecentMFARequired: "recent_mfa_required", authz.Decision(0): "invalid",
	} {
		if d.String() != want {
			t.Fatalf("%d.String() = %q, want %q", d, d.String(), want)
		}
	}
}
