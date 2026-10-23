package domain_test

import (
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/domain"
)

func TestThrottleAllowsUntilThreshold(t *testing.T) {
	var th domain.Throttle
	for i := range domain.AccountThreshold {
		if wait := th.Wait(t0); wait != 0 {
			t.Fatalf("attempt %d delayed by %v", i+1, wait)
		}
		th.Fail(t0, domain.AccountThreshold)
	}
	if wait := th.Wait(t0); wait != time.Second {
		t.Fatalf("first delay = %v, want 1s", wait)
	}
}

func TestThrottleDelaysDoubleAndCap(t *testing.T) {
	var th domain.Throttle
	now := t0
	var delays []time.Duration
	for range domain.AccountThreshold + 14 {
		now = now.Add(th.Wait(now))
		th.Fail(now, domain.AccountThreshold)
		delays = append(delays, th.Wait(now))
	}
	want := []time.Duration{1, 2, 4, 8, 16}
	for i, w := range want {
		if delays[domain.AccountThreshold-1+i] != w*time.Second {
			t.Fatalf("delay after failure %d = %v, want %v", domain.AccountThreshold+i, delays[domain.AccountThreshold-1+i], w*time.Second)
		}
	}
	if last := delays[len(delays)-1]; last != 15*time.Minute {
		t.Fatalf("delay is not capped: %v", last)
	}
}

func TestThrottleNeverLocksOutPermanently(t *testing.T) {
	var th domain.Throttle
	for range 1000 {
		th.Fail(t0, domain.AccountThreshold)
	}
	if wait := th.Wait(t0.Add(15 * time.Minute)); wait != 0 {
		t.Fatalf("still blocked after the maximum delay: %v", wait)
	}
}

func TestThrottleResetsOnSuccess(t *testing.T) {
	var th domain.Throttle
	for range 10 {
		th.Fail(t0, domain.AccountThreshold)
	}
	th.Succeed()
	if th.Failures != 0 || th.Wait(t0) != 0 {
		t.Fatalf("after success: %+v", th)
	}
}
