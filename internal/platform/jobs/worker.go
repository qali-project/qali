package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/metrics"
)

// Handler processes one job. Returning an error retries or dead-letters it.
type Handler func(ctx context.Context, j Job) error

// WorkerOptions configures a worker. Zero values select defaults.
type WorkerOptions struct {
	Queue       string
	Poll        time.Duration
	Lease       time.Duration
	Concurrency int
	Metrics     metrics.Recorder
	Logger      *slog.Logger
	Clock       clock.Clock
}

// Worker claims and runs jobs until its context is cancelled, then stops
// claiming and waits for in-flight jobs.
type Worker struct {
	store    *db.Store
	queue    *Queue
	opts     WorkerOptions
	handlers map[string]Handler
}

// NewWorker returns a worker for one queue.
func NewWorker(store *db.Store, q *Queue, opts WorkerOptions) *Worker {
	if opts.Queue == "" {
		opts.Queue = DefaultQueue
	}
	if opts.Poll <= 0 {
		opts.Poll = time.Second
	}
	if opts.Lease <= 0 {
		opts.Lease = 5 * time.Minute
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.Nop{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Clock == nil {
		opts.Clock = clock.System{}
	}
	return &Worker{store: store, queue: q, opts: opts, handlers: map[string]Handler{}}
}

// Handle registers the handler for a job kind. Register before Run.
func (w *Worker) Handle(kind string, h Handler) { w.handlers[kind] = h }

// Run processes jobs until ctx is cancelled. In-flight jobs keep running
// with an uncancelled context bounded by the lease, and Run returns after
// they finish.
func (w *Worker) Run(ctx context.Context) error {
	slots := make(chan struct{}, w.opts.Concurrency)
	var inFlight sync.WaitGroup
	defer inFlight.Wait()
	ticker := time.NewTicker(w.opts.Poll)
	defer ticker.Stop()

	for {
		if err := w.reap(ctx); err != nil && ctx.Err() == nil {
			w.opts.Logger.Error("dead-letter expired jobs", "error", err)
		}
		free := w.opts.Concurrency - len(slots)
		if free > 0 && ctx.Err() == nil {
			claimed, err := w.claim(ctx, free)
			if err != nil && ctx.Err() == nil {
				w.opts.Logger.Error("claim jobs", "queue", w.opts.Queue, "error", err)
			}
			for _, j := range claimed {
				slots <- struct{}{}
				inFlight.Go(func() {
					defer func() { <-slots }()
					w.process(context.WithoutCancel(ctx), j)
				})
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *Worker) claim(ctx context.Context, n int) ([]Job, error) {
	var claimed []Job
	err := w.store.PlatformWrite(ctx, func(ctx context.Context, tx db.Querier) error {
		var err error
		claimed, err = w.queue.Claim(ctx, tx, w.opts.Queue, n, w.opts.Lease)
		return err
	})
	return claimed, err
}

func (w *Worker) reap(ctx context.Context) error {
	return w.store.PlatformWrite(ctx, func(ctx context.Context, tx db.Querier) error {
		_, err := w.queue.DeadLetterExpired(ctx, tx)
		return err
	})
}

func (w *Worker) process(ctx context.Context, j Job) {
	ctx, cancel := context.WithTimeout(ctx, w.opts.Lease)
	defer cancel()
	start := w.opts.Clock.Now()
	err := w.run(ctx, j)
	outcome := "succeeded"
	if err == nil {
		err = w.store.PlatformWrite(ctx, func(ctx context.Context, tx db.Querier) error {
			return w.queue.Complete(ctx, tx, j.ID)
		})
	} else {
		outcome = "retried"
		var dead bool
		dead, err = w.fail(ctx, j, err)
		if dead {
			outcome = "dead"
		}
	}
	if err != nil {
		w.opts.Logger.Error("record job outcome", "job_id", j.ID, "kind", j.Kind, "error", err)
	}
	labels := metrics.Labels{"kind": j.Kind, "outcome": outcome}
	w.opts.Metrics.Count("jobs_finished_total", labels)
	w.opts.Metrics.Observe("job_duration_seconds", w.opts.Clock.Now().Sub(start).Seconds(), metrics.Labels{"kind": j.Kind})
}

func (w *Worker) run(ctx context.Context, j Job) (err error) {
	h, ok := w.handlers[j.Kind]
	if !ok {
		return fmt.Errorf("no handler for job kind %q", j.Kind)
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panic: %v", p)
		}
	}()
	return h(ctx, j)
}

// fail records the failure; a dead-lettered job also gets an audit event.
func (w *Worker) fail(ctx context.Context, j Job, cause error) (bool, error) {
	if j.Attempts < j.MaxAttempts {
		return false, w.store.PlatformWrite(ctx, func(ctx context.Context, tx db.Querier) error {
			_, err := w.queue.Fail(ctx, tx, j, cause)
			return err
		})
	}
	scope, err := db.SystemScope(audit.Actor{Type: audit.ActorSystem, ID: "worker"}, db.RequestInfo{})
	if err != nil {
		return false, err
	}
	err = w.store.Write(ctx, scope, func(ctx context.Context, tx *db.WriteTx) error {
		dead, err := w.queue.Fail(ctx, tx, j, cause)
		if err != nil {
			return err
		}
		if !dead {
			return errors.New("jobs: expected the job to be dead-lettered")
		}
		return tx.Audit(ctx, audit.Entry{
			Action: "job.dead_letter", TargetType: "job", TargetID: j.ID.String(), Outcome: audit.Failure,
			Metadata: map[string]any{"kind": j.Kind, "attempts": j.Attempts},
		})
	})
	return err == nil, err
}
