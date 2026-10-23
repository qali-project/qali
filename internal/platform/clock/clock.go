// Package clock is the only place that reads the wall clock (ADR-0004).
// Everything else receives a Clock so tests can control time.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time in UTC.
type Clock interface {
	Now() time.Time
}

// System is the production clock.
type System struct{}

// Now returns the current UTC time.
func (System) Now() time.Time { return time.Now().UTC() }

// Manual is a test clock that moves only when told to.
type Manual struct {
	mu  sync.Mutex
	now time.Time
}

// NewManual returns a clock fixed at t.
func NewManual(t time.Time) *Manual { return &Manual{now: t.UTC()} }

// Now returns the current manual time.
func (m *Manual) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

// Advance moves the clock forward by d.
func (m *Manual) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
}
