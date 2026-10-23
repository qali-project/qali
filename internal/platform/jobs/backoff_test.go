package jobs_test

import (
	"testing"
	"time"

	"github.com/qali-project/qali/internal/platform/jobs"
)

func TestBackoffIsExponentialAndBounded(t *testing.T) {
	cases := map[int]time.Duration{
		1:  10 * time.Second,
		2:  20 * time.Second,
		3:  40 * time.Second,
		4:  80 * time.Second,
		9:  2560 * time.Second, // 10s * 2^8, still below the cap
		10: time.Hour,          // 10s * 2^9 exceeds one hour
		60: time.Hour,
	}
	for attempt, want := range cases {
		if got := jobs.Backoff(attempt); got != want {
			t.Fatalf("Backoff(%d) = %v, want %v", attempt, got, want)
		}
	}
	if jobs.Backoff(0) != 10*time.Second || jobs.Backoff(-3) != 10*time.Second {
		t.Fatal("non-positive attempts must use the base delay")
	}
}
