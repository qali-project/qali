//go:build integration

// Package integration holds tests that need real infrastructure. They start
// disposable containers and never depend on a developer's local services.
// Run with `make test-integration`.
package integration_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/db/dbtest"
	"github.com/qali-project/qali/internal/platform/secret"
)

// cluster is the PostgreSQL server shared by the package's tests. Roles are
// created by the production bootstrap script; each test gets its own database.
var cluster *dbtest.Cluster

func TestMain(m *testing.M) {
	os.Exit(runWithPostgres(m))
}

func runWithPostgres(m *testing.M) int {
	ctx := context.Background()
	var err error
	cluster, err = dbtest.Start(ctx, os.Getenv("QALI_TEST_POSTGRES_MAJOR"), "../..")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = cluster.Close(ctx) }()
	return m.Run()
}

func connect(t *testing.T, d secret.Value) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), string(d.Expose()))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// testDatabase is a fresh database prepared like a production one.
type testDatabase struct {
	name                 string
	admin, migrator, app secret.Value
}

func newDatabase(t *testing.T) testDatabase {
	t.Helper()
	d, err := cluster.NewDatabase(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cluster.DropDatabase(context.Background(), d.Name) })
	return testDatabase{name: d.Name, admin: d.Admin, migrator: d.Migrator, app: d.App}
}

// migratedDatabase returns a database with all migrations applied.
func migratedDatabase(t *testing.T) testDatabase {
	t.Helper()
	d := newDatabase(t)
	if _, err := db.Migrate(t.Context(), d.migrator); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

func TestDisposablePostgresRunsSupportedMajor(t *testing.T) {
	conn := connect(t, newDatabase(t).app)
	var versionNum int
	if err := conn.QueryRow(t.Context(), "SELECT current_setting('server_version_num')::int").Scan(&versionNum); err != nil {
		t.Fatalf("query server version: %v", err)
	}
	if got := strconv.Itoa(versionNum / 10000); got != cluster.Major {
		t.Fatalf("server major = %s, want %s", got, cluster.Major)
	}
}
