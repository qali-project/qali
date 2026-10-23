//go:build integration

package integration_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/app"
)

// TestBootstrapRequiresAnOperatorSetupToken proves REVIEW-001: a remote
// caller without the one-time token issued on the server cannot claim a
// fresh installation.
func TestBootstrapRequiresAnOperatorSetupToken(t *testing.T) {
	s := newAuthServer(t)
	body := func(token string) map[string]any {
		b := map[string]any{"email": "owner@example.org", "displayName": "Owner", "password": ownerPassword, "workspaceName": "Acme QA"}
		if token != "" {
			b["setupToken"] = token
		}
		return b
	}
	reject := func(name string, r response) {
		t.Helper()
		if r.status != http.StatusForbidden || r.code() != "setup_token_invalid" {
			t.Fatalf("%s: %d %s", name, r.status, r.raw)
		}
	}
	reject("missing", s.client().do(http.MethodPost, "/api/v1/setup/owner", body("")))
	reject("garbage", s.client().do(http.MethodPost, "/api/v1/setup/owner", body("qali_setup_nonsense")))
	reject("unknown", s.client().do(http.MethodPost, "/api/v1/setup/owner", body("qali_setup_aaaaaaaaaaaaaaaa_"+strings.Repeat("A", 43))))
	token := s.setupToken()
	reject("tampered", s.client().do(http.MethodPost, "/api/v1/setup/owner", body(token[:len(token)-4]+"AAAA")))

	expired := s.setupToken()
	s.clock.Advance(time.Hour + time.Second)
	reject("expired", s.client().do(http.MethodPost, "/api/v1/setup/owner", body(expired)))

	// Nothing was created by the rejected attempts.
	if status := s.client().do(http.MethodGet, "/api/v1/setup", nil); status.body["bootstrapRequired"] != true {
		t.Fatalf("rejected attempts claimed the installation: %s", status.raw)
	}
	fresh := s.setupToken()
	expect(t, s.client().do(http.MethodPost, "/api/v1/setup/owner", body(fresh)), http.StatusCreated)

	// The raw token is never stored, and issuing stops once claimed.
	conn := connect(t, s.db.admin)
	var n int
	if err := conn.QueryRow(t.Context(), "SELECT count(*) FROM qali.setup_tokens WHERE position($1 in row_to_json(setup_tokens)::text) > 0",
		fresh[len("qali_setup_")+17:]).Scan(&n); err != nil || n != 0 {
		t.Fatalf("token secret stored: %d %v", n, err)
	}
	if _, _, err := s.svc.IssueSetupToken(t.Context(), "test"); !errors.Is(err, app.ErrAlreadyBootstrapped) {
		t.Fatalf("issuing after setup: %v", err)
	}
}
