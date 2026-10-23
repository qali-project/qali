// Package jobs is the PostgreSQL-backed job queue (IMPLEMENTATION_PLAN 4.2):
// FOR UPDATE SKIP LOCKED claims with leases, bounded retries with exponential
// backoff, dead-letter state, and idempotent enqueue.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/jobs/jobsdb"
)

const (
	DefaultQueue       = "default"
	DefaultMaxAttempts = 5
	maxErrorText       = 2000
	baseBackoff        = 10 * time.Second
	maxBackoff         = time.Hour
)

var (
	kindPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	queuePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// Backoff returns the delay before retrying after the given attempt:
// 10s, 20s, 40s, ... capped at one hour.
func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := baseBackoff
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// Job is a claimed job.
type Job struct {
	ID          uuid.UUID
	Queue       string
	Kind        string
	Payload     json.RawMessage
	WorkspaceID *uuid.UUID
	Attempts    int
	MaxAttempts int
	RunAt       time.Time
}

// EnqueueParams describes a new job. Zero values select defaults.
type EnqueueParams struct {
	Queue          string
	Kind           string
	Payload        any
	WorkspaceID    *uuid.UUID
	MaxAttempts    int
	RunAt          time.Time
	IdempotencyKey string
}

// Queue performs job state transitions inside the caller's transaction.
type Queue struct {
	clock clock.Clock
	newID func() (uuid.UUID, error)
}

// NewQueue returns a queue using c for all timestamps.
func NewQueue(c clock.Clock, newID func() (uuid.UUID, error)) *Queue {
	return &Queue{clock: c, newID: newID}
}

// Enqueue inserts a job. With an idempotency key, a repeated enqueue of the
// same kind returns the existing job and created == false.
func (q *Queue) Enqueue(ctx context.Context, tx jobsdb.DBTX, p EnqueueParams) (id uuid.UUID, created bool, err error) {
	if p.Queue == "" {
		p.Queue = DefaultQueue
	}
	if p.MaxAttempts == 0 {
		p.MaxAttempts = DefaultMaxAttempts
	}
	switch {
	case !kindPattern.MatchString(p.Kind):
		return uuid.Nil, false, fmt.Errorf("jobs: invalid kind %q", p.Kind)
	case !queuePattern.MatchString(p.Queue):
		return uuid.Nil, false, fmt.Errorf("jobs: invalid queue %q", p.Queue)
	case p.MaxAttempts < 1 || p.MaxAttempts > 100:
		return uuid.Nil, false, errors.New("jobs: max attempts must be between 1 and 100")
	}
	payload, err := json.Marshal(p.Payload)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("jobs: encode payload: %w", err)
	}
	if p.Payload == nil {
		payload = []byte("{}")
	}
	if id, err = q.newID(); err != nil {
		return uuid.Nil, false, err
	}
	now := q.clock.Now()
	if p.RunAt.IsZero() {
		p.RunAt = now
	}
	var key *string
	if p.IdempotencyKey != "" {
		key = &p.IdempotencyKey
	}
	db := jobsdb.New(tx)
	inserted, err := db.InsertJob(ctx, jobsdb.InsertJobParams{
		ID: id, Queue: p.Queue, Kind: p.Kind, Payload: payload, WorkspaceID: p.WorkspaceID,
		MaxAttempts: int32(p.MaxAttempts), RunAt: p.RunAt, IdempotencyKey: key, Now: now, //nolint:gosec // G115: bounded to 1..100 above
	})
	if errors.Is(err, pgx.ErrNoRows) && key != nil {
		existing, err := db.JobByIdempotencyKey(ctx, jobsdb.JobByIdempotencyKeyParams{Kind: p.Kind, IdempotencyKey: key})
		return existing, false, err
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	return inserted, true, nil
}

// Claim leases up to n due jobs from queue for lease.
func (q *Queue) Claim(ctx context.Context, tx jobsdb.DBTX, queue string, n int, lease time.Duration) ([]Job, error) {
	now := q.clock.Now()
	until := now.Add(lease)
	rows, err := jobsdb.New(tx).ClaimJobs(ctx, jobsdb.ClaimJobsParams{
		LockedUntil: &until, Now: now, Queue: queue, MaxJobs: int32(min(max(n, 0), 1000)), //nolint:gosec // G115: clamped to 0..1000
	})
	if err != nil {
		return nil, err
	}
	out := make([]Job, 0, len(rows))
	for _, r := range rows {
		out = append(out, Job{
			ID: r.ID, Queue: r.Queue, Kind: r.Kind, Payload: r.Payload, WorkspaceID: r.WorkspaceID,
			Attempts: int(r.Attempts), MaxAttempts: int(r.MaxAttempts), RunAt: r.RunAt,
		})
	}
	return out, nil
}

// Complete marks a claimed job as succeeded.
func (q *Queue) Complete(ctx context.Context, tx jobsdb.DBTX, id uuid.UUID) error {
	now := q.clock.Now()
	n, err := jobsdb.New(tx).CompleteJob(ctx, jobsdb.CompleteJobParams{Now: &now, ID: id})
	if err == nil && n == 0 {
		err = errors.New("jobs: job is no longer leased")
	}
	return err
}

// Fail records a failed attempt: the job is retried after Backoff, or
// dead-lettered when its attempts are exhausted. It reports whether the job
// is now dead.
func (q *Queue) Fail(ctx context.Context, tx jobsdb.DBTX, j Job, cause error) (bool, error) {
	now := q.clock.Now()
	msg := truncate(cause.Error())
	db := jobsdb.New(tx)
	if j.Attempts >= j.MaxAttempts {
		n, err := db.KillJob(ctx, jobsdb.KillJobParams{Now: &now, LastError: &msg, ID: j.ID})
		if err == nil && n == 0 {
			err = errors.New("jobs: job is no longer leased")
		}
		return err == nil, err
	}
	n, err := db.RetryJob(ctx, jobsdb.RetryJobParams{RunAt: now.Add(Backoff(j.Attempts)), LastError: &msg, Now: now, ID: j.ID})
	if err == nil && n == 0 {
		err = errors.New("jobs: job is no longer leased")
	}
	return false, err
}

// DeadLetterExpired dead-letters running jobs whose lease expired on their
// final attempt, returning how many changed.
func (q *Queue) DeadLetterExpired(ctx context.Context, tx jobsdb.DBTX) (int64, error) {
	now := q.clock.Now()
	return jobsdb.New(tx).DeadLetterExpired(ctx, &now)
}

func truncate(s string) string {
	if len(s) <= maxErrorText {
		return s
	}
	return s[:maxErrorText]
}
