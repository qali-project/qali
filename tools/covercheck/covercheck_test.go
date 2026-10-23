package main

import (
	"strings"
	"testing"
)

const profile = `mode: atomic
github.com/qali-project/qali/internal/platform/crypto/a.go:10.2,12.3 3 1
github.com/qali-project/qali/internal/platform/crypto/a.go:13.2,14.3 1 0
github.com/qali-project/qali/internal/platform/crypto/b.go:5.2,8.3 6 4
github.com/qali-project/qali/internal/platform/secret/s.go:1.1,2.2 2 0
github.com/qali-project/qali/internal/platform/secret/s.go:3.1,4.2 2 5
`

func TestCoverageIsComputedPerPackage(t *testing.T) {
	cov, err := Parse(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	if got := cov["github.com/qali-project/qali/internal/platform/crypto"]; got != 90 {
		t.Fatalf("crypto coverage = %v, want 90", got)
	}
	if got := cov["github.com/qali-project/qali/internal/platform/secret"]; got != 50 {
		t.Fatalf("secret coverage = %v, want 50", got)
	}
}

func TestDuplicateBlocksAreMergedByMaximumCount(t *testing.T) {
	dup := profile + "github.com/qali-project/qali/internal/platform/secret/s.go:1.1,2.2 2 3\n"
	cov, err := Parse(strings.NewReader(dup))
	if err != nil {
		t.Fatal(err)
	}
	if got := cov["github.com/qali-project/qali/internal/platform/secret"]; got != 100 {
		t.Fatalf("secret coverage = %v, want 100 after merging", got)
	}
}

func TestConcatenatedProfilesAreMerged(t *testing.T) {
	integration := `mode: atomic
github.com/qali-project/qali/internal/platform/secret/s.go:1.1,2.2 2 7
`
	cov, err := Parse(strings.NewReader(profile + integration))
	if err != nil {
		t.Fatal(err)
	}
	if got := cov["github.com/qali-project/qali/internal/platform/secret"]; got != 100 {
		t.Fatalf("secret coverage = %v, want 100 with both profiles", got)
	}
}

func TestThresholds(t *testing.T) {
	cov, err := Parse(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	failures := Check(cov, "github.com/qali-project/qali", map[string]float64{
		"internal/platform/crypto": 90,
		"internal/platform/secret": 90,
		"internal/platform/config": 80,
	})
	if len(failures) != 2 {
		t.Fatalf("failures = %v, want secret below threshold and config missing", failures)
	}
	if !strings.Contains(failures[0], "internal/platform/config") || !strings.Contains(failures[0], "no coverage data") {
		t.Fatalf("missing package not reported: %v", failures)
	}
	if !strings.Contains(failures[1], "internal/platform/secret") || !strings.Contains(failures[1], "50.0%") {
		t.Fatalf("low coverage not reported: %v", failures)
	}
}

func TestParseThresholdArguments(t *testing.T) {
	got, err := ParseThresholds([]string{"internal/platform/crypto=90", "internal/platform/httpserver=80.5"})
	if err != nil || got["internal/platform/crypto"] != 90 || got["internal/platform/httpserver"] != 80.5 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"crypto", "x=", "x=abc", "x=101", "x=-1"} {
		if _, err := ParseThresholds([]string{bad}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestMalformedProfilesAreErrors(t *testing.T) {
	for name, p := range map[string]string{
		"empty":       "",
		"no mode":     "github.com/x/a.go:1.1,2.2 1 1\n",
		"bad line":    "mode: set\ngarbage\n",
		"bad numbers": "mode: set\ngithub.com/x/a.go:1.1,2.2 x 1\n",
	} {
		if _, err := Parse(strings.NewReader(p)); err == nil {
			t.Fatalf("%s profile accepted", name)
		}
	}
}
