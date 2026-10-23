package domain

import (
	"errors"
	"time"
)

// SessionState is the authentication stage of a session (ADR-0012).
type SessionState string

const (
	StateMFAEnrollment SessionState = "mfa_enrollment"
	StateMFAChallenge  SessionState = "mfa_challenge"
	StateActive        SessionState = "active"
)

// RevokeReason records why a session ended.
type RevokeReason string

const (
	RevokeLogout          RevokeReason = "logout"
	RevokeLogoutAll       RevokeReason = "logout_all"
	RevokeRotated         RevokeReason = "rotated"
	RevokePasswordChanged RevokeReason = "password_changed"
	RevokeRecovered       RevokeReason = "recovered"
)

const (
	SessionIdle     = 12 * time.Hour
	SessionAbsolute = 7 * 24 * time.Hour
	// touchInterval limits last-seen writes to one per minute per session.
	touchInterval = time.Minute
)

var (
	ErrSessionExpired = errors.New("identity: session expired")
	ErrSessionRevoked = errors.New("identity: session revoked")
)

// Session holds lifetime state; credentials live in the adapter.
type Session struct {
	State         SessionState
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokeReason  RevokeReason
}

// NewSession starts a session at now.
func NewSession(now time.Time, state SessionState) Session {
	return Session{
		State:         state,
		CreatedAt:     now,
		LastSeenAt:    now,
		IdleExpiresAt: now.Add(SessionIdle),
		ExpiresAt:     now.Add(SessionAbsolute),
	}
}

// Check reports whether the session may be used at now.
func (s Session) Check(now time.Time) error {
	if s.RevokedAt != nil {
		return ErrSessionRevoked
	}
	if !now.Before(s.IdleExpiresAt) || !now.Before(s.ExpiresAt) {
		return ErrSessionExpired
	}
	return nil
}

// Touch extends the idle limit, never past the absolute limit. It returns
// whether anything changed and needs persisting.
func (s *Session) Touch(now time.Time) bool {
	if now.Sub(s.LastSeenAt) < touchInterval {
		return false
	}
	s.LastSeenAt = now
	s.IdleExpiresAt = now.Add(SessionIdle)
	if s.IdleExpiresAt.After(s.ExpiresAt) {
		s.IdleExpiresAt = s.ExpiresAt
	}
	return true
}

// Revoke ends the session.
func (s *Session) Revoke(now time.Time, reason RevokeReason) {
	s.RevokedAt = &now
	s.RevokeReason = reason
}

// StateAfterPassword decides the state after a correct password: privileged
// users must enroll in TOTP; anyone enrolled must pass a challenge.
func StateAfterPassword(privileged, enrolled bool) SessionState {
	switch {
	case enrolled:
		return StateMFAChallenge
	case privileged:
		return StateMFAEnrollment
	default:
		return StateActive
	}
}

// EffectiveState is the state a session may act in now. An active session
// that never completed MFA drops back to enrollment or challenge as soon as
// its user holds a role that requires MFA (REVIEW-002: promotion and
// invitation must not bypass ADR-0012).
func EffectiveState(stored SessionState, mfaVerified, privileged, enrolled bool) SessionState {
	if stored != StateActive || mfaVerified || !privileged {
		return stored
	}
	if enrolled {
		return StateMFAChallenge
	}
	return StateMFAEnrollment
}

// RecentMFAWindow is how long a TOTP verification counts as recent strong
// authentication for sensitive actions (ADR-0006, ADR-0013).
const RecentMFAWindow = 10 * time.Minute

// RecentMFA reports whether verifiedAt is recent strong authentication at now.
func RecentMFA(verifiedAt *time.Time, now time.Time) bool {
	return verifiedAt != nil && !now.Before(*verifiedAt) && now.Sub(*verifiedAt) < RecentMFAWindow
}

// RoleRequiresMFA reports whether a workspace role must use MFA (RBAC.md:
// Owner and Workspace Administrator).
func RoleRequiresMFA(role string) bool {
	return role == "owner" || role == "workspace_admin"
}
