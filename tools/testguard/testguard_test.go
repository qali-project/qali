package main

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Patterns are assembled from pieces so this file does not trip the guard
// when the guard scans the repository.
const (
	skipCall   = "t." + "Skip(\"later\")"
	skipfCall  = "t." + "Skipf(\"%s\", x)"
	skipNow    = "tb." + "SkipNow()"
	shortCheck = "testing." + "Short()"
	itOnly     = "it." + "only("
	testSkip   = "test." + "skip("
	descOnly   = "describe." + "only("
	pwFixme    = "test." + "fixme("
	pwDescSkip = "test.describe." + "skip("
	todoCase   = "it." + "todo("
	skipIf     = "it." + "skipIf(true)("
	xitCase    = "x" + "it("
	fdescCase  = "f" + "describe("
	allowTag   = "testguard:" + "allow"
)

var today = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

func scan(t *testing.T, files map[string]string) []Finding {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	findings, err := Scan(fsys, today)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	return findings
}

func TestScanReportsSkippedAndFocusedTests(t *testing.T) {
	cases := []struct {
		name string
		path string
		line string
	}{
		{"go skip", "internal/a/a_test.go", skipCall},
		{"go skipf", "internal/a/a_test.go", skipfCall},
		{"go skipnow", "internal/a/a_test.go", skipNow},
		{"go short mode", "internal/a/a_test.go", "if " + shortCheck + " {"},
		{"vitest only", "web/src/App.test.tsx", itOnly + "\"x\", () => {})"},
		{"vitest skip", "web/src/App.test.ts", testSkip + "\"x\", () => {})"},
		{"describe only", "web/src/a.spec.ts", descOnly + "\"x\", () => {})"},
		{"vitest todo", "web/src/a.test.ts", todoCase + "\"x\")"},
		{"vitest skipIf", "web/src/a.test.ts", skipIf + "\"x\", () => {})"},
		{"playwright fixme", "web/e2e/home.spec.ts", pwFixme + "\"x\", async () => {})"},
		{"playwright describe skip", "web/e2e/home.spec.ts", pwDescSkip + "\"x\", () => {})"},
		{"jasmine xit", "web/src/a.test.js", xitCase + "\"x\", () => {})"},
		{"jasmine fdescribe", "tools/x/a.test.mjs", fdescCase + "\"x\", () => {})"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := scan(t, map[string]string{tc.path: "line one\n" + tc.line + "\n"})
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
			}
			f := findings[0]
			if f.Path != tc.path || f.Line != 2 {
				t.Fatalf("want %s:2, got %s:%d", tc.path, f.Path, f.Line)
			}
		})
	}
}

func TestScanIgnoresNonTestFilesAndBuildOutputs(t *testing.T) {
	findings := scan(t, map[string]string{
		"internal/a/a.go":                     skipCall,
		"web/src/App.tsx":                     itOnly,
		"web/node_modules/x/a.test.js":        itOnly,
		"web/dist/a.test.js":                  itOnly,
		"internal/a/testdata/fixture_test.go": skipCall,
		"internal/a/ok_test.go":               "func TestOK(t *testing.T) { t.Log(\"only\") }\n",
		"web/src/ok.test.ts":                  "it(\"skips nothing\", () => { expect(onlyOne).toBe(1) })\n",
	})
	if len(findings) != 0 {
		t.Fatalf("want no findings, got %+v", findings)
	}
}

func TestAllowanceWithIssueAndFutureExpiryIsAccepted(t *testing.T) {
	findings := scan(t, map[string]string{
		"internal/a/a_test.go": skipCall + " // " + allowTag + " QALI-12 2026-11-01\n",
	})
	if len(findings) != 0 {
		t.Fatalf("want no findings, got %+v", findings)
	}
}

func TestExpiredOrMalformedAllowanceIsReported(t *testing.T) {
	cases := map[string]string{
		"expired":        skipCall + " // " + allowTag + " QALI-12 2026-10-21\n",
		"missing expiry": skipCall + " // " + allowTag + " QALI-12\n",
		"bad date":       skipCall + " // " + allowTag + " QALI-12 2026-13-40\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			findings := scan(t, map[string]string{"internal/a/a_test.go": content})
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %+v", findings)
			}
			if !strings.Contains(findings[0].Rule, "allowance") {
				t.Fatalf("want an allowance finding, got %q", findings[0].Rule)
			}
		})
	}
}

func TestFindingStringIsActionable(t *testing.T) {
	findings := scan(t, map[string]string{"web/src/App.test.tsx": itOnly + "\"x\")\n"})
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %+v", findings)
	}
	got := findings[0].String()
	if !strings.HasPrefix(got, "web/src/App.test.tsx:1: ") {
		t.Fatalf("finding should start with path:line, got %q", got)
	}
}
