package metrics_test

import (
	"testing"

	"github.com/qali-project/qali/internal/platform/metrics"
)

func TestMemoryRecorderCountsByLabels(t *testing.T) {
	m := metrics.NewMemory()
	m.Count("jobs_finished_total", metrics.Labels{"kind": "a", "outcome": "succeeded"})
	m.Count("jobs_finished_total", metrics.Labels{"outcome": "succeeded", "kind": "a"})
	m.Count("jobs_finished_total", metrics.Labels{"kind": "a", "outcome": "retried"})
	m.Observe("http_request_seconds", 0.25, metrics.Labels{"route": "/health/live"})
	m.Observe("http_request_seconds", 0.5, metrics.Labels{"route": "/health/live"})

	if got := m.Counter("jobs_finished_total", metrics.Labels{"kind": "a", "outcome": "succeeded"}); got != 2 {
		t.Fatalf("counter = %d, want 2 (label order must not matter)", got)
	}
	if got := m.Counter("jobs_finished_total", metrics.Labels{"kind": "b"}); got != 0 {
		t.Fatalf("unrelated counter = %d", got)
	}
	n, sum := m.Observations("http_request_seconds", metrics.Labels{"route": "/health/live"})
	if n != 2 || sum != 0.75 {
		t.Fatalf("observations = %d, %v", n, sum)
	}
}

func TestNopRecorderAcceptsEverything(t *testing.T) {
	var r metrics.Recorder = metrics.Nop{}
	r.Count("x", nil)
	r.Observe("y", 1, metrics.Labels{"a": "b"})
}
