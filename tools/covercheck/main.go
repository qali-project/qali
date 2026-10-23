// Command covercheck enforces per-package statement coverage thresholds from
// docs/TESTING_POLICY.md section 6 on a `go test -coverprofile` file.
//
// Usage: go run ./tools/covercheck <profile[,profile...]> <module> <pkg=percent>...
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

type block struct {
	stmts int
	count int
}

// Parse returns statement coverage in percent per package import path. The
// input may concatenate several profiles (unit and integration); blocks listed
// more than once are merged by their highest count.
func Parse(r io.Reader) (map[string]float64, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() || !strings.HasPrefix(sc.Text(), "mode: ") {
		return nil, errors.New("coverage profile must start with a mode line")
	}
	blocks := map[string]block{}
	for n := 2; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "mode: ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], ":") {
			return nil, fmt.Errorf("profile line %d is malformed", n)
		}
		stmts, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil || stmts < 0 || count < 0 {
			return nil, fmt.Errorf("profile line %d has invalid numbers", n)
		}
		b := blocks[fields[0]]
		b.stmts = stmts
		b.count = max(b.count, count)
		blocks[fields[0]] = b
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	total, covered := map[string]int{}, map[string]int{}
	for key, b := range blocks {
		file := key[:strings.LastIndex(key, ":")]
		pkg := path.Dir(file)
		total[pkg] += b.stmts
		if b.count > 0 {
			covered[pkg] += b.stmts
		}
	}
	out := make(map[string]float64, len(total))
	for pkg, t := range total {
		if t == 0 {
			out[pkg] = 100
			continue
		}
		out[pkg] = float64(covered[pkg]) * 100 / float64(t)
	}
	return out, nil
}

// ParseThresholds reads "relative/package=percent" arguments.
func ParseThresholds(args []string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, a := range args {
		pkg, pct, ok := strings.Cut(a, "=")
		if !ok || pkg == "" {
			return nil, fmt.Errorf("threshold %q must be package=percent", a)
		}
		v, err := strconv.ParseFloat(pct, 64)
		if err != nil || v < 0 || v > 100 {
			return nil, fmt.Errorf("threshold %q must be a percentage between 0 and 100", a)
		}
		out[pkg] = v
	}
	return out, nil
}

// Check returns one failure per package below its threshold or missing from
// the profile, sorted by package.
func Check(cov map[string]float64, module string, thresholds map[string]float64) []string {
	pkgs := make([]string, 0, len(thresholds))
	for p := range thresholds {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	var failures []string
	for _, p := range pkgs {
		got, ok := cov[module+"/"+p]
		switch {
		case !ok:
			failures = append(failures, fmt.Sprintf("%s: no coverage data; its tests did not run", p))
		case got < thresholds[p]:
			failures = append(failures, fmt.Sprintf("%s: %.1f%% coverage, threshold %.1f%%", p, got, thresholds[p]))
		}
	}
	return failures
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: covercheck <profile[,profile...]> <module> <pkg=percent>...")
		os.Exit(2)
	}
	thresholds, err := ParseThresholds(os.Args[3:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "covercheck:", err)
		os.Exit(2)
	}
	var readers []io.Reader
	for _, name := range strings.Split(os.Args[1], ",") {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "covercheck:", err)
			os.Exit(2)
		}
		defer func() { _ = f.Close() }()
		readers = append(readers, f, strings.NewReader("\n"))
	}
	cov, err := Parse(io.MultiReader(readers...))
	if err != nil {
		fmt.Fprintln(os.Stderr, "covercheck:", err)
		os.Exit(2)
	}
	failures := Check(cov, os.Args[2], thresholds)
	for _, msg := range failures {
		fmt.Fprintln(os.Stderr, msg)
	}
	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "covercheck: %d package(s) below threshold (docs/TESTING_POLICY.md section 6)\n", len(failures))
		os.Exit(1)
	}
	fmt.Println("covercheck: OK")
}
