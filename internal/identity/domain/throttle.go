package domain

import "time"

// Thresholds of failures before delays start (ADR-0012).
const (
	AccountThreshold = 5
	IPThreshold      = 20
	maxThrottleDelay = 15 * time.Minute
)

// Throttle is the progressive delay state for one account or client IP.
// Delays double from one second and cap at 15 minutes; there is no permanent
// lockout an attacker could trigger against a victim.
type Throttle struct {
	Failures      int
	NextAllowedAt time.Time
}

// Wait returns how long the next attempt must wait at now.
func (t Throttle) Wait(now time.Time) time.Duration {
	if d := t.NextAllowedAt.Sub(now); d > 0 {
		return d
	}
	return 0
}

// Fail records a failed attempt.
func (t *Throttle) Fail(now time.Time, threshold int) {
	t.Failures++
	if t.Failures < threshold {
		return
	}
	delay := maxThrottleDelay
	if n := t.Failures - threshold; n < 10 {
		delay = min(time.Duration(1<<n)*time.Second, maxThrottleDelay)
	}
	t.NextAllowedAt = now.Add(delay)
}

// Succeed clears the state after a successful attempt.
func (t *Throttle) Succeed() {
	t.Failures = 0
	t.NextAllowedAt = time.Time{}
}
