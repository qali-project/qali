// Command e2eenv runs a command against disposable, migrated PostgreSQL
// databases prepared like production, one per E2E suite so that every
// journey starts from a fresh installation. It writes each suite's secret
// files into <secrets-dir>/<suite>, exports QALI_E2E_SECRETS_DIR, runs the
// command, removes the database container, and exits with the command's
// status.
//
// Usage: go run ./tools/e2eenv [-C dir] [-suites a,b] <secrets-dir> -- <command> [args...]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/db/dbtest"
	"github.com/qali-project/qali/tools/internal/secretsdir"
)

func main() {
	os.Exit(run())
}

func run() int {
	workdir := flag.String("C", ".", "directory to run the command in")
	suites := flag.String("suites", "auth,admin", "comma-separated suites, one database each")
	flag.Parse()
	args := flag.Args()
	if len(args) < 3 || args[1] != "--" {
		fmt.Fprintln(os.Stderr, "usage: e2eenv [-C dir] <secrets-dir> -- <command> [args...]")
		return 2
	}
	secrets, err := filepath.Abs(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2eenv:", err)
		return 2
	}

	ctx := context.Background()
	cluster, err := dbtest.Start(ctx, os.Getenv("QALI_TEST_POSTGRES_MAJOR"), ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2eenv:", err)
		return 1
	}
	defer func() { _ = cluster.Close(ctx) }()
	for _, suite := range strings.Split(*suites, ",") {
		database, err := cluster.NewDatabase(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "e2eenv:", err)
			return 1
		}
		if _, err := db.Migrate(ctx, database.Migrator); err != nil {
			fmt.Fprintln(os.Stderr, "e2eenv:", err)
			return 1
		}
		urls := secretsdir.URLs{App: string(database.App.Expose()), Migration: string(database.Migrator.Expose())}
		if err := secretsdir.Write(filepath.Join(secrets, suite), urls); err != nil {
			fmt.Fprintln(os.Stderr, "e2eenv:", err)
			return 1
		}
	}

	cmd := exec.CommandContext(ctx, args[2], args[3:]...) //nolint:gosec // G204: developer-supplied test command
	cmd.Dir = *workdir
	cmd.Env = append(os.Environ(), "QALI_E2E_SECRETS_DIR="+secrets)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "e2eenv:", err)
		return 1
	}
	return 0
}
