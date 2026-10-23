package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, s)
}

type fakeServer struct {
	rec      *recorder
	stop     chan struct{}
	shutdown sync.Once
}

func (f *fakeServer) ListenAndServe() error { <-f.stop; return http.ErrServerClosed }
func (f *fakeServer) Shutdown(context.Context) error {
	f.shutdown.Do(func() { f.rec.add("http"); close(f.stop) })
	return nil
}

type fakeWorker struct{ rec *recorder }

func (f fakeWorker) Run(ctx context.Context) error {
	<-ctx.Done()
	time.Sleep(10 * time.Millisecond) // draining in-flight jobs
	f.rec.add("worker")
	return nil
}

// TestShutdownOrder proves the process part of MVP-03.AC-11: stop accepting
// HTTP, drain jobs, then close the database pool.
func TestShutdownOrder(t *testing.T) {
	rec := &recorder{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, &fakeServer{rec: rec, stop: make(chan struct{})}, fakeWorker{rec: rec}, func() { rec.add("db") })
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if want := []string{"http", "worker", "db"}; !slices.Equal(rec.steps, want) {
		t.Fatalf("shutdown order = %v, want %v", rec.steps, want)
	}
}

type failingServer struct{ err error }

func (f failingServer) ListenAndServe() error        { return f.err }
func (failingServer) Shutdown(context.Context) error { return nil }

func TestListenFailureStillStopsWorkerAndPool(t *testing.T) {
	rec := &recorder{}
	bind := errors.New("address in use")
	err := serve(t.Context(), failingServer{err: bind}, fakeWorker{rec: rec}, func() { rec.add("db") })
	if !errors.Is(err, bind) {
		t.Fatalf("err = %v, want the listen error", err)
	}
	if want := []string{"worker", "db"}; !slices.Equal(rec.steps, want) {
		t.Fatalf("cleanup = %v, want %v", rec.steps, want)
	}
}

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			t.Errorf("healthcheck requested %s", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	if err := healthcheck(t.Context(), srv.URL+"/health/ready"); err != nil {
		t.Fatalf("ready instance reported unhealthy: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := healthcheck(t.Context(), srv.URL+"/health/ready"); err == nil {
		t.Fatal("not-ready instance reported healthy")
	}
	srv.Close()
	if err := healthcheck(t.Context(), srv.URL+"/health/ready"); err == nil {
		t.Fatal("unreachable instance reported healthy")
	}
}

func TestHealthcheckURL(t *testing.T) {
	for addr, want := range map[string]string{
		"":             "http://127.0.0.1:8080/health/ready",
		":8080":        "http://127.0.0.1:8080/health/ready",
		"0.0.0.0:9000": "http://127.0.0.1:9000/health/ready",
		"[::]:9000":    "http://127.0.0.1:9000/health/ready",
		"10.1.2.3:81":  "http://10.1.2.3:81/health/ready",
	} {
		if got := healthcheckURL(addr); got != want {
			t.Fatalf("healthcheckURL(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestDispatchRejectsUnknownCommands(t *testing.T) {
	if code := dispatch(t.Context(), nil, emptySource(), []string{"teleport"}); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if code := dispatch(t.Context(), nil, emptySource(), []string{"migrate", "sideways"}); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if code := dispatch(t.Context(), nil, emptySource(), []string{"migrate", "up"}); code != 2 {
		t.Fatalf("migrate without configuration exit code = %d, want 2", code)
	}
}
