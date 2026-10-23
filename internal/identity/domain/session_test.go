package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/domain"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func TestNewSessionLimits(t *testing.T) {
	s := domain.NewSession(t0, domain.StateActive)
	if !s.IdleExpiresAt.Equal(t0.Add(12*time.Hour)) || !s.ExpiresAt.Equal(t0.Add(7*24*time.Hour)) {
		t.Fatalf("limits = idle %v absolute %v", s.IdleExpiresAt, s.ExpiresAt)
	}
	if err := s.Check(t0); err != nil {
		t.Fatal(err)
	}
}

func TestIdleExpiryAndSlidingRefresh(t *testing.T) {
	s := domain.NewSession(t0, domain.StateActive)
	if err := s.Check(t0.Add(12*time.Hour + time.Second)); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("idle session err = %v", err)
	}
	now := t0.Add(11 * time.Hour)
	if !s.Touch(now) {
		t.Fatal("activity after the refresh interval must extend the session")
	}
	if !s.IdleExpiresAt.Equal(now.Add(12 * time.Hour)) {
		t.Fatalf("idle expiry = %v", s.IdleExpiresAt)
	}
	if s.Touch(now.Add(30 * time.Second)) {
		t.Fatal("touches within a minute must not write")
	}
}

func TestAbsoluteExpiryCannotBeExtended(t *testing.T) {
	s := domain.NewSession(t0, domain.StateActive)
	for h := 10; h < 7*24; h += 10 {
		s.Touch(t0.Add(time.Duration(h) * time.Hour))
	}
	if s.IdleExpiresAt.After(s.ExpiresAt) {
		t.Fatal("idle expiry passed the absolute limit")
	}
	if err := s.Check(t0.Add(7*24*time.Hour + time.Second)); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("absolute expiry err = %v", err)
	}
}

func TestRevokedSessionsFail(t *testing.T) {
	s := domain.NewSession(t0, domain.StateActive)
	s.Revoke(t0.Add(time.Minute), domain.RevokeLogout)
	if err := s.Check(t0.Add(2 * time.Minute)); !errors.Is(err, domain.ErrSessionRevoked) {
		t.Fatalf("err = %v", err)
	}
	if s.RevokeReason != domain.RevokeLogout {
		t.Fatalf("reason = %s", s.RevokeReason)
	}
}

func TestStateAfterPassword(t *testing.T) {
	cases := []struct {
		privileged, enrolled bool
		want                 domain.SessionState
	}{
		{privileged: false, enrolled: false, want: domain.StateActive},
		{privileged: false, enrolled: true, want: domain.StateMFAChallenge},
		{privileged: true, enrolled: false, want: domain.StateMFAEnrollment},
		{privileged: true, enrolled: true, want: domain.StateMFAChallenge},
	}
	for _, c := range cases {
		if got := domain.StateAfterPassword(c.privileged, c.enrolled); got != c.want {
			t.Fatalf("privileged=%v enrolled=%v: %s, want %s", c.privileged, c.enrolled, got, c.want)
		}
	}
}

func TestRequiresMFA(t *testing.T) {
	for role, want := range map[string]bool{"owner": true, "workspace_admin": true, "qa_lead": false, "tester": false, "viewer": false} {
		if got := domain.RoleRequiresMFA(role); got != want {
			t.Fatalf("RoleRequiresMFA(%s) = %v", role, got)
		}
	}
}

func TestEffectiveStateRequiresMFAForCurrentRoles(t *testing.T) {
	cases := []struct {
		stored                         domain.SessionState
		verified, privileged, enrolled bool
		want                           domain.SessionState
	}{
		{domain.StateActive, false, false, false, domain.StateActive},
		{domain.StateActive, false, true, false, domain.StateMFAEnrollment},
		{domain.StateActive, false, true, true, domain.StateMFAChallenge},
		{domain.StateActive, true, true, true, domain.StateActive},
		{domain.StateMFAChallenge, false, true, true, domain.StateMFAChallenge},
		{domain.StateMFAEnrollment, false, false, false, domain.StateMFAEnrollment},
	}
	for _, c := range cases {
		if got := domain.EffectiveState(c.stored, c.verified, c.privileged, c.enrolled); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}
