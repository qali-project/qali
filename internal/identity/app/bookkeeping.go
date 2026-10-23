package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/identity/domain"
	"github.com/qali-project/qali/internal/platform/db"
)

// This file holds bookkeeping that is not a user action and so uses the
// unaudited platform write path; lint allows PlatformWrite in this file only.

// touch persists a session's sliding expiry.
func (s *Service) touch(ctx context.Context, rec SessionRecord) error {
	return s.cfg.Store.PlatformWrite(ctx, func(ctx context.Context, q db.Querier) error {
		return s.cfg.Repo.TouchSession(ctx, q, rec.ID, rec.Lifetime.LastSeenAt, rec.Lifetime.IdleExpiresAt)
	})
}

// reserveMFAAttempt counts a TOTP attempt against the account before the
// code is checked, under the throttle row lock, so concurrent guesses cannot
// all pass a shared pre-check (REVIEW-003). A correct code clears the count
// in the caller's transaction; a wrong one only needs auditing. It returns
// the throttle key.
func (s *Service) reserveMFAAttempt(ctx context.Context, user uuid.UUID) ([]byte, error) {
	key := s.accountKey("mfa", user.String())
	var wait time.Duration
	err := s.cfg.Store.PlatformWrite(ctx, func(ctx context.Context, q db.Querier) error {
		now := s.now()
		t, err := s.cfg.Repo.LockThrottle(ctx, q, key, "account", now)
		if err != nil {
			return err
		}
		if wait = t.Wait(now); wait > 0 {
			return nil
		}
		t.Fail(now, domain.AccountThreshold)
		return s.cfg.Repo.SaveThrottle(ctx, q, key, t, now)
	})
	if err != nil {
		return nil, err
	}
	if wait > 0 {
		return nil, &ThrottledError{RetryAfter: wait}
	}
	return key, nil
}
