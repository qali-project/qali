//go:build integration

package integration_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/jobs"
	"github.com/qali-project/qali/internal/platform/metrics"
)

var t0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func jobQueue(c clock.Clock) *jobs.Queue { return jobs.NewQueue(c, uuid.NewV7) }

func enqueue(t *testing.T, s *db.Store, q *jobs.Queue, p jobs.EnqueueParams) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	var created bool
	err := s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
		var err error
		if id, created, err = q.Enqueue(ctx, tx, p); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Entry{Action: "job.enqueue", Outcome: audit.Success})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, created
}

func claim(t *testing.T, s *db.Store, q *jobs.Queue, n int) []jobs.Job {
	t.Helper()
	var claimed []jobs.Job
	err := s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
		var err error
		claimed, err = q.Claim(ctx, tx, "default", n, 30*time.Second)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return claimed
}

func jobStatus(t *testing.T, d testDatabase, id uuid.UUID) (status string, attempts int) {
	t.Helper()
	if err := connect(t, d.admin).QueryRow(t.Context(), "SELECT status, attempts FROM qali.jobs WHERE id = $1", id).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	return status, attempts
}

func TestEnqueueIsIdempotent(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.NewManual(t0))
	first, created := enqueue(t, s, q, jobs.EnqueueParams{Kind: "webhook.deliver", Payload: map[string]any{"n": 1}, IdempotencyKey: "evt-1"})
	second, createdAgain := enqueue(t, s, q, jobs.EnqueueParams{Kind: "webhook.deliver", Payload: map[string]any{"n": 2}, IdempotencyKey: "evt-1"})
	if !created || createdAgain || first != second {
		t.Fatalf("first %v (%v), second %v (%v)", first, created, second, createdAgain)
	}
	other, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "webhook.deliver", IdempotencyKey: "evt-2"})
	if other == first {
		t.Fatal("different keys must create different jobs")
	}
}

func TestEnqueueValidation(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.NewManual(t0))
	for name, p := range map[string]jobs.EnqueueParams{
		"no kind":      {},
		"bad kind":     {Kind: "Bad Kind"},
		"bad queue":    {Kind: "a.b", Queue: "Bad"},
		"max attempts": {Kind: "a.b", MaxAttempts: 101},
	} {
		err := s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
			_, _, err := q.Enqueue(ctx, tx, p)
			return err
		})
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestConcurrentClaimsNeverOverlap(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.NewManual(t0))
	const total = 120
	for range total {
		enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.run"})
	}
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				batch := claim(t, s, q, 4)
				if len(batch) == 0 {
					return
				}
				mu.Lock()
				for _, j := range batch {
					seen[j.ID]++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(seen) != total {
		t.Fatalf("claimed %d distinct jobs, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("job %s claimed %d times", id, n)
		}
	}
}

func TestFailedJobsRetryWithBackoffThenDeadLetter(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	c := clock.NewManual(t0)
	q := jobQueue(c)
	id, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.run", MaxAttempts: 2})

	fail := func(j jobs.Job) bool {
		var dead bool
		err := s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
			var err error
			dead, err = q.Fail(ctx, tx, j, errors.New("provider timeout"))
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return dead
	}

	first := claim(t, s, q, 1)
	if len(first) != 1 || first[0].Attempts != 1 {
		t.Fatalf("first claim = %+v", first)
	}
	if fail(first[0]) {
		t.Fatal("first failure dead-lettered")
	}
	if got := claim(t, s, q, 1); len(got) != 0 {
		t.Fatal("job retried before its backoff elapsed")
	}
	c.Advance(jobs.Backoff(1) - time.Second)
	if got := claim(t, s, q, 1); len(got) != 0 {
		t.Fatal("job retried one second early")
	}
	c.Advance(time.Second)
	second := claim(t, s, q, 1)
	if len(second) != 1 || second[0].Attempts != 2 {
		t.Fatalf("retry claim = %+v", second)
	}
	if !fail(second[0]) {
		t.Fatal("exhausted job was not dead-lettered")
	}
	if status, attempts := jobStatus(t, d, id); status != "dead" || attempts != 2 {
		t.Fatalf("status %s attempts %d", status, attempts)
	}
	c.Advance(24 * time.Hour)
	if got := claim(t, s, q, 1); len(got) != 0 {
		t.Fatal("dead job was claimed")
	}
}

func TestExpiredLeasesAreReclaimedOrDeadLettered(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	c := clock.NewManual(t0)
	q := jobQueue(c)
	id, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.run", MaxAttempts: 2})

	if got := claim(t, s, q, 1); len(got) != 1 {
		t.Fatal("not claimed")
	}
	if got := claim(t, s, q, 1); len(got) != 0 {
		t.Fatal("a leased job was claimed twice")
	}
	c.Advance(31 * time.Second) // the worker crashed; the lease expired
	again := claim(t, s, q, 1)
	if len(again) != 1 || again[0].ID != id || again[0].Attempts != 2 {
		t.Fatalf("reclaim = %+v", again)
	}
	c.Advance(31 * time.Second) // crashed again with no attempts left
	var dead int64
	err := s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
		var err error
		dead, err = q.DeadLetterExpired(ctx, tx)
		return err
	})
	if err != nil || dead != 1 {
		t.Fatalf("dead-lettered %d, %v", dead, err)
	}
	if status, _ := jobStatus(t, d, id); status != "dead" {
		t.Fatalf("status = %s, want dead", status)
	}
}

func TestWorkerRunsHandlersAndRecordsMetrics(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.System{})
	ok, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.ok"})
	bad, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.bad", MaxAttempts: 1})
	m := metrics.NewMemory()
	w := jobs.NewWorker(s, q, jobs.WorkerOptions{Poll: 20 * time.Millisecond, Metrics: m})
	done := make(chan struct{}, 2)
	w.Handle("probe.ok", func(context.Context, jobs.Job) error { done <- struct{}{}; return nil })
	w.Handle("probe.bad", func(context.Context, jobs.Job) error { done <- struct{}{}; return errors.New("broken") })

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- w.Run(ctx) }()
	for range 2 {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("handlers did not run")
		}
	}
	waitFor(t, func() bool {
		a, _ := jobStatus(t, d, ok)
		b, _ := jobStatus(t, d, bad)
		return a == "succeeded" && b == "dead"
	})
	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if m.Counter("jobs_finished_total", metrics.Labels{"kind": "probe.ok", "outcome": "succeeded"}) != 1 ||
		m.Counter("jobs_finished_total", metrics.Labels{"kind": "probe.bad", "outcome": "dead"}) != 1 {
		t.Fatal("job outcomes were not recorded")
	}
	var deadEvents int
	if err := connect(t, d.admin).QueryRow(t.Context(),
		"SELECT count(*) FROM qali.audit_events WHERE action = 'job.dead_letter' AND target_id = $1", bad.String()).Scan(&deadEvents); err != nil || deadEvents != 1 {
		t.Fatalf("dead-letter audit events = %d, %v", deadEvents, err)
	}
}

// TestWorkerDrainsInFlightJobsOnShutdown proves the worker part of
// MVP-03.AC-11: cancellation stops claiming, but running jobs finish.
func TestWorkerDrainsInFlightJobsOnShutdown(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.System{})
	running, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.slow"})
	w := jobs.NewWorker(s, q, jobs.WorkerOptions{Poll: 20 * time.Millisecond, Concurrency: 1})
	started, release := make(chan struct{}), make(chan struct{})
	w.Handle("probe.slow", func(ctx context.Context, _ jobs.Job) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- w.Run(ctx) }()
	<-started
	cancel()
	later, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.slow"})
	select {
	case <-stopped:
		t.Fatal("worker stopped before its in-flight job finished")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if status, _ := jobStatus(t, d, running); status != "succeeded" {
		t.Fatalf("in-flight job status = %s", status)
	}
	if status, _ := jobStatus(t, d, later); status != "pending" {
		t.Fatalf("job enqueued after shutdown began has status %s; the worker kept claiming", status)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 { // up to ~10s
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within 10s")
}

func lastError(t *testing.T, d testDatabase, id uuid.UUID) string {
	t.Helper()
	var msg *string
	if err := connect(t, d.admin).QueryRow(t.Context(), "SELECT last_error FROM qali.jobs WHERE id = $1", id).Scan(&msg); err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		return ""
	}
	return *msg
}

func TestWorkerSurvivesPanicsAndUnknownKinds(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.System{})
	panicky, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.panic", MaxAttempts: 3})
	unknown, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.unregistered", MaxAttempts: 3})
	w := jobs.NewWorker(s, q, jobs.WorkerOptions{Poll: 20 * time.Millisecond})
	w.Handle("probe.panic", func(context.Context, jobs.Job) error { panic("nil map in handler") })

	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	go func() { stopped <- w.Run(ctx) }()
	waitFor(t, func() bool {
		a, _ := jobStatus(t, d, panicky)
		b, _ := jobStatus(t, d, unknown)
		return a == "pending" && b == "pending" && lastError(t, d, panicky) != "" && lastError(t, d, unknown) != ""
	})
	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if msg := lastError(t, d, panicky); msg != "handler panic: nil map in handler" {
		t.Fatalf("panic recorded as %q", msg)
	}
	if msg := lastError(t, d, unknown); msg != `no handler for job kind "probe.unregistered"` {
		t.Fatalf("unknown kind recorded as %q", msg)
	}
}

// A worker whose lease expired must not overwrite the outcome of the worker
// that reclaimed the job.
func TestStaleWorkerCannotOverwriteAReclaimedJob(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	c := clock.NewManual(t0)
	q := jobQueue(c)
	enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.run", MaxAttempts: 3})
	stale := claim(t, s, q, 1)[0]
	c.Advance(31 * time.Second)
	fresh := claim(t, s, q, 1)[0]

	complete := func(j jobs.Job) error {
		return s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
			return q.Complete(ctx, tx, j.ID)
		})
	}
	if err := complete(fresh); err != nil {
		t.Fatal(err)
	}
	if err := complete(stale); err == nil {
		t.Fatal("completing a job that is no longer leased succeeded")
	}
	err := s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
		_, err := q.Fail(ctx, tx, stale, errors.New("late failure"))
		return err
	})
	if err == nil {
		t.Fatal("failing a job that is no longer leased succeeded")
	}
	if status, _ := jobStatus(t, d, fresh.ID); status != "succeeded" {
		t.Fatalf("status = %s, the stale worker overwrote the outcome", status)
	}
	stale.Attempts = stale.MaxAttempts
	err = s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
		_, err := q.Fail(ctx, tx, stale, errors.New("late final failure"))
		return err
	})
	if err == nil {
		t.Fatal("dead-lettering a job that is no longer leased succeeded")
	}
}

func TestLongErrorsAreTruncated(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	q := jobQueue(clock.NewManual(t0))
	id, _ := enqueue(t, s, q, jobs.EnqueueParams{Kind: "probe.run", MaxAttempts: 3})
	j := claim(t, s, q, 1)[0]
	err := s.PlatformWrite(t.Context(), func(ctx context.Context, tx db.Querier) error {
		_, err := q.Fail(ctx, tx, j, errors.New(strings.Repeat("e", 3000)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(lastError(t, d, id)); got != 2000 {
		t.Fatalf("stored error length = %d, want 2000", got)
	}
}
