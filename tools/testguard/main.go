// Command testguard rejects skipped and focused tests.
//
// docs/TESTING_POLICY.md forbids skipping, focusing, or marking tests pending
// without an approved issue and expiry. An exception is written on the same
// line as:
//
//	// testguard:allow <issue> <YYYY-MM-DD>
//
// and stops being accepted after the expiry date.
//
// Usage: go run ./tools/testguard [root]
package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Finding is one rejected line.
type Finding struct {
	Path string
	Line int
	Rule string
	Text string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.Path, f.Line, f.Rule, strings.TrimSpace(f.Text))
}

type rule struct {
	name    string
	pattern *regexp.Regexp
}

var (
	goRules = []rule{
		{"skipped Go test", regexp.MustCompile(`\b\w+\.(Skip|Skipf|SkipNow)\(`)},
		{"short-mode skip", regexp.MustCompile(`\btesting\.Short\(\)`)},
	}
	jsRules = []rule{
		{"focused, skipped, or pending test", regexp.MustCompile(`\b(?:it|test|describe|suite|bench)(?:\.describe)?\.(?:only|skip|todo|fixme|skipIf|runIf)\b`)},
		{"focused or skipped test alias", regexp.MustCompile(`(?:^|[^\w.$])(?:xit|xtest|xdescribe|fit|fdescribe)\(`)},
	}
	jsTestFile = regexp.MustCompile(`\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$`)
	allowance  = regexp.MustCompile(`testguard:allow\b(?:[ \t]+(\S+))?(?:[ \t]+(\S+))?`)

	skippedDirs = map[string]bool{"node_modules": true, "dist": true, "testdata": true, "coverage": true}
)

// Scan returns findings for every test file under fsys, sorted by path and line.
func Scan(fsys fs.FS, today time.Time) ([]Finding, error) {
	var findings []Finding
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && (skippedDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		var rules []rule
		switch {
		case strings.HasSuffix(p, "_test.go"):
			rules = goRules
		case jsTestFile.MatchString(path.Base(p)):
			rules = jsRules
		default:
			return nil
		}
		fileFindings, err := scanFile(fsys, p, rules, today)
		findings = append(findings, fileFindings...)
		return err
	})
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, err
}

func scanFile(fsys fs.FS, p string, rules []rule, today time.Time) ([]Finding, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only; close errors carry no data loss

	var findings []Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, r := range rules {
			if !r.pattern.MatchString(line) {
				continue
			}
			if ok, reason := allowed(line, today); !ok {
				name := r.name
				if reason != "" {
					name = reason
				}
				findings = append(findings, Finding{Path: p, Line: n, Rule: name, Text: line})
			}
			break
		}
	}
	return findings, sc.Err()
}

// allowed reports whether the line carries a valid, unexpired allowance. When
// an allowance is present but invalid, reason explains why.
func allowed(line string, today time.Time) (ok bool, reason string) {
	m := allowance.FindStringSubmatch(line)
	if m == nil {
		return false, ""
	}
	if m[1] == "" || m[2] == "" {
		return false, "invalid allowance: needs an issue and an expiry date"
	}
	expiry, err := time.Parse(time.DateOnly, m[2])
	if err != nil {
		return false, "invalid allowance: expiry must be YYYY-MM-DD"
	}
	if expiry.Before(today) {
		return false, "expired allowance for " + m[1]
	}
	return true, ""
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	findings, err := Scan(os.DirFS(root), today)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testguard:", err)
		os.Exit(2)
	}
	for _, f := range findings {
		fmt.Fprintln(os.Stderr, f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "testguard: %d skipped or focused test(s); see docs/TESTING_POLICY.md\n", len(findings))
		os.Exit(1)
	}
	fmt.Println("testguard: OK")
}
