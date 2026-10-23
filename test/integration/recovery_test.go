//go:build integration

package integration_test

import (
	"net/http"
	"testing"
	"time"
)

// TestRecoveryCodesAreSingleUse proves AC-03, AC-09 (recovery revokes
// sessions), and the recovery-code half of AC-10.
func TestRecoveryCodesAreSingleUse(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, codes := s.enrolledOwner()
	if len(codes) != 10 {
		t.Fatalf("got %d recovery codes", len(codes))
	}
	recover := func(code, password string) response {
		return s.client().do(http.MethodPost, "/api/v1/auth/recovery", map[string]any{"email": "owner@example.org", "recoveryCode": code, "newPassword": password})
	}

	expect(t, recover(codes[0], "recovered passphrase one"), http.StatusNoContent)
	if sessionStatus(owner) != http.StatusUnauthorized {
		t.Fatal("recovery did not revoke existing sessions")
	}
	s.login("owner@example.org", "recovered passphrase one", secretB32)

	if r := recover(codes[0], "replayed passphrase two"); r.status != http.StatusUnauthorized || r.code() != "invalid_credentials" {
		t.Fatalf("replayed recovery code: %d %s", r.status, r.raw)
	}
	if r := recover("AAAA-BBBB-CCCC-DDDD", "guessed passphrase three"); r.status != http.StatusUnauthorized {
		t.Fatalf("invalid recovery code: %d", r.status)
	}
	if r := recover(codes[1], "x"); r.status != http.StatusBadRequest {
		t.Fatalf("weak new password must be rejected before the code is consumed: %d", r.status)
	}
	expect(t, recover(codes[1], "recovered passphrase four"), http.StatusNoContent)
}

func TestRegeneratingRecoveryCodesInvalidatesTheOldSet(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, old := s.enrolledOwner()
	if r := owner.do(http.MethodPost, "/api/v1/auth/recovery-codes", map[string]any{"code": "000000"}); r.status != http.StatusUnauthorized {
		t.Fatalf("regeneration without a valid TOTP code: %d", r.status)
	}
	r := owner.do(http.MethodPost, "/api/v1/auth/recovery-codes", map[string]any{"code": s.totpCode(secretB32)})
	expect(t, r, http.StatusOK)
	fresh := r.body["recoveryCodes"].([]any)
	if len(fresh) != 10 {
		t.Fatalf("got %d new codes", len(fresh))
	}
	if r := s.client().do(http.MethodPost, "/api/v1/auth/recovery", map[string]any{"email": "owner@example.org", "recoveryCode": old[0], "newPassword": "should not work at all"}); r.status != http.StatusUnauthorized {
		t.Fatalf("superseded code accepted: %d", r.status)
	}
	expect(t, s.client().do(http.MethodPost, "/api/v1/auth/recovery", map[string]any{"email": "owner@example.org", "recoveryCode": fresh[0].(string), "newPassword": "new set works fine"}), http.StatusNoContent)
}

// TestOperatorResetTokensAreSingleUseAndExpire proves the operator half of
// AC-10.
func TestOperatorResetTokensAreSingleUseAndExpire(t *testing.T) {
	s := newAuthServer(t)
	owner, secretB32, _ := s.enrolledOwner()
	token, expires, err := s.svc.IssuePasswordReset(t.Context(), "owner@example.org", "operator-console")
	if err != nil {
		t.Fatal(err)
	}
	if want := s.clock.Now().Add(30 * time.Minute); !expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v", expires, want)
	}
	redeem := func(tok, password string) response {
		return s.client().do(http.MethodPost, "/api/v1/auth/password-reset", map[string]any{"token": tok, "newPassword": password})
	}
	raw := string(token.Expose())
	expect(t, redeem(raw, "operator reset passphrase"), http.StatusNoContent)
	if sessionStatus(owner) != http.StatusUnauthorized {
		t.Fatal("reset did not revoke sessions")
	}
	s.login("owner@example.org", "operator reset passphrase", secretB32)
	if r := redeem(raw, "replayed reset passphrase"); r.status != http.StatusUnauthorized || r.code() != "invalid_token" {
		t.Fatalf("replayed reset token: %d %s", r.status, r.raw)
	}

	late, _, err := s.svc.IssuePasswordReset(t.Context(), "owner@example.org", "operator-console")
	if err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(30*time.Minute + time.Second)
	if r := redeem(string(late.Expose()), "expired reset passphrase"); r.status != http.StatusUnauthorized {
		t.Fatalf("expired reset token: %d", r.status)
	}
	if r := redeem("qali_reset_aaaaaaaaaaaaaaaa_"+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "forged reset passphrase"); r.status != http.StatusUnauthorized {
		t.Fatalf("forged reset token: %d", r.status)
	}
	if _, _, err := s.svc.IssuePasswordReset(t.Context(), "nobody@example.org", "operator-console"); err == nil {
		t.Fatal("reset issued for an unknown account")
	}
}
