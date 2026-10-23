//go:build integration

package integration_test

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// wrongCode is never the current code for the fixed test clock steps used
// here; the assertion on status codes below would expose a collision.
func wrongCode(s *authServer, secret string) string {
	if s.totpCode(secret) == "000000" {
		return "111111"
	}
	return "000000"
}

// TestTOTPThrottleIsEnforcedOnEveryVerification proves REVIEW-003: after
// five wrong codes every TOTP-verifying operation answers 429 with
// Retry-After, even for the right code, until the delay passes.
func TestTOTPThrottleIsEnforcedOnEveryVerification(t *testing.T) {
	s := newAuthServer(t)
	owner, secret, _ := s.enrolledOwner()

	ops := map[string]string{
		"step-up":             "/api/v1/auth/mfa/step-up",
		"recovery regenerate": "/api/v1/auth/recovery-codes",
	}
	for name, path := range ops {
		for i := range 5 {
			if r := owner.do(http.MethodPost, path, map[string]any{"code": wrongCode(s, secret)}); r.status != http.StatusUnauthorized {
				t.Fatalf("%s attempt %d: %d %s", name, i+1, r.status, r.raw)
			}
		}
		r := owner.do(http.MethodPost, path, map[string]any{"code": s.totpCode(secret)})
		if r.status != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
			t.Fatalf("%s after the threshold: %d %s", name, r.status, r.raw)
		}
		s.clock.Advance(2 * time.Second)
		expect(t, owner.do(http.MethodPost, path, map[string]any{"code": s.totpCode(secret)}), http.StatusOK)
		s.clock.Advance(31 * time.Second)
	}

	// Enrollment confirmation of a new member.
	f := &adminFixture{s: s, owner: owner, ownerTOTP: secret}
	ws := owner.do(http.MethodGet, "/api/v1/workspaces", nil)
	f.workspace = ids(ws, "id")[0]
	f.workspaceP = "/api/v1/workspaces/" + f.workspace
	tester, _, _ := f.member("tester@example.org", "tester")
	begin := tester.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment", nil)
	expect(t, begin, http.StatusOK)
	testerSecret := begin.body["secret"].(string)
	for i := range 5 {
		if r := tester.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": wrongCode(s, testerSecret)}); r.status != http.StatusUnauthorized {
			t.Fatalf("enrollment attempt %d: %d %s", i+1, r.status, r.raw)
		}
	}
	if r := tester.do(http.MethodPost, "/api/v1/auth/mfa/totp/enrollment/confirm", map[string]any{"code": s.totpCode(testerSecret)}); r.status != http.StatusTooManyRequests {
		t.Fatalf("enrollment after the threshold: %d %s", r.status, r.raw)
	}
}

// TestParallelTOTPGuessesCannotOutrunTheThrottle proves the attempt is
// counted atomically before verification: concurrent guesses beyond the
// threshold are refused rather than all passing a shared pre-check.
func TestParallelTOTPGuessesCannotOutrunTheThrottle(t *testing.T) {
	s := newAuthServer(t)
	owner, secret, _ := s.enrolledOwner()
	const parallel = 20
	results := make([]response, parallel)
	var wg sync.WaitGroup
	for i := range parallel {
		wg.Go(func() {
			results[i] = owner.do(http.MethodPost, "/api/v1/auth/mfa/step-up", map[string]any{"code": wrongCode(s, secret)})
		})
	}
	wg.Wait()
	verified := 0
	for _, r := range results {
		switch r.status {
		case http.StatusUnauthorized:
			verified++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("unexpected response %d %s", r.status, r.raw)
		}
	}
	if verified > 5 {
		t.Fatalf("%d guesses were verified; the threshold is 5", verified)
	}
}
