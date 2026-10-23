// Package metrics defines the recording hooks platform code calls. A
// Prometheus-backed recorder and the protected exposition endpoint arrive with
// operational diagnostics (MVP-15); until then production uses Nop.
package metrics

import (
	"sort"
	"strings"
	"sync"
)

// Labels are low-cardinality dimensions. Never put IDs, users, or paths with
// identifiers in labels.
type Labels map[string]string

// Recorder receives counter increments and observations.
type Recorder interface {
	Count(name string, labels Labels)
	Observe(name string, value float64, labels Labels)
}

// Nop discards everything.
type Nop struct{}

func (Nop) Count(string, Labels)            {}
func (Nop) Observe(string, float64, Labels) {}

// Memory keeps values in memory for tests and diagnostics.
type Memory struct {
	mu       sync.Mutex
	counters map[string]int
	count    map[string]int
	sum      map[string]float64
}

// NewMemory returns an empty in-memory recorder.
func NewMemory() *Memory {
	return &Memory{counters: map[string]int{}, count: map[string]int{}, sum: map[string]float64{}}
}

func key(name string, labels Labels) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

func (m *Memory) Count(name string, labels Labels) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key(name, labels)]++
}

func (m *Memory) Observe(name string, value float64, labels Labels) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(name, labels)
	m.count[k]++
	m.sum[k] += value
}

// Counter returns a counter's value.
func (m *Memory) Counter(name string, labels Labels) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[key(name, labels)]
}

// Observations returns the number and sum of observed values.
func (m *Memory) Observations(name string, labels Labels) (int, float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(name, labels)
	return m.count[k], m.sum[k]
}
