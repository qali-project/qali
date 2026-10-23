//go:build integration

package integration_test

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// TestConcurrentBootstrapCreatesExactlyOneOwner proves MVP-04.AC-06.
func TestConcurrentBootstrapCreatesExactlyOneOwner(t *testing.T) {
	s := newAuthServer(t)
	status := s.client().do(http.MethodGet, "/api/v1/setup", nil)
	expect(t, status, http.StatusOK)
	if status.body["bootstrapRequired"] != true {
		t.Fatalf("fresh installation: %s", status.raw)
	}

	const racers = 8
	bodies := make([]map[string]any, racers)
	for i := range racers {
		bodies[i] = s.bootstrapBody(fmt.Sprintf("owner%d@example.org", i))
	}
	late := s.bootstrapBody("late@example.org") // a valid token issued before setup completes
	results := make([]response, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			results[i] = s.client().do(http.MethodPost, "/api/v1/setup/owner", bodies[i])
		})
	}
	wg.Wait()
	created := 0
	for _, r := range results {
		switch {
		case r.status == http.StatusCreated:
			created++
			if r.state() != "mfa_enrollment" {
				t.Fatalf("owner session must require MFA enrollment, got %s", r.state())
			}
		case r.status == http.StatusConflict && r.code() == "already_bootstrapped":
		default:
			t.Fatalf("unexpected bootstrap response %d %s", r.status, r.raw)
		}
	}
	if created != 1 {
		t.Fatalf("%d bootstraps succeeded, want exactly 1", created)
	}

	var users, owners, workspaces, installations int
	admin := connect(t, s.db.admin)
	for q, dst := range map[string]*int{
		"SELECT count(*) FROM qali.users":                                  &users,
		"SELECT count(*) FROM qali.workspace_members WHERE role = 'owner'": &owners,
		"SELECT count(*) FROM qali.workspaces":                             &workspaces,
		"SELECT count(*) FROM qali.installation":                           &installations,
	} {
		if err := admin.QueryRow(t.Context(), q).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	if users != 1 || owners != 1 || workspaces != 1 || installations != 1 {
		t.Fatalf("users %d owners %d workspaces %d installation %d", users, owners, workspaces, installations)
	}

	after := s.client().do(http.MethodGet, "/api/v1/setup", nil)
	if after.body["bootstrapRequired"] != false {
		t.Fatalf("setup still open: %s", after.raw)
	}
	replay := s.client().do(http.MethodPost, "/api/v1/setup/owner", late)
	if replay.status != http.StatusConflict || replay.code() != "already_bootstrapped" {
		t.Fatalf("bootstrap after setup: %d %s", replay.status, replay.raw)
	}
}

func TestBootstrapValidatesInput(t *testing.T) {
	s := newAuthServer(t)
	for name, body := range map[string]map[string]any{
		"weak password": {"email": "o@example.org", "displayName": "O", "password": "short", "workspaceName": "W"},
		"bad email":     {"email": "not-an-email", "displayName": "O", "password": ownerPassword, "workspaceName": "W"},
		"empty name":    {"email": "o@example.org", "displayName": "", "password": ownerPassword, "workspaceName": "W"},
		"empty space":   {"email": "o@example.org", "displayName": "O", "password": ownerPassword, "workspaceName": ""},
		"unknown field": {"email": "o@example.org", "displayName": "O", "password": ownerPassword, "workspaceName": "W", "role": "owner"},
	} {
		r := s.client().do(http.MethodPost, "/api/v1/setup/owner", body)
		if r.status != http.StatusBadRequest {
			t.Fatalf("%s: status %d %s", name, r.status, r.raw)
		}
	}
	if after := s.client().do(http.MethodGet, "/api/v1/setup", nil); after.body["bootstrapRequired"] != true {
		t.Fatal("a rejected bootstrap closed setup")
	}
}
