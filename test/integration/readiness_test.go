//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/qali-project/qali/internal/platform/db"
)

// TestReadinessDistinguishesFailures proves the database half of
// MVP-03.AC-09.
func TestReadinessDistinguishesFailures(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	if err := s.Ready(t.Context()); err != nil {
		t.Fatalf("migrated database not ready: %v", err)
	}

	if err := db.Rollback(t.Context(), d.migrator, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(t.Context()); !errors.Is(err, db.ErrMigrationsPending) {
		t.Fatalf("after rollback: %v, want ErrMigrationsPending", err)
	}
	if _, err := db.Migrate(t.Context(), d.migrator); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(t.Context()); err != nil {
		t.Fatalf("after re-migration: %v", err)
	}

	if err := cluster.DropDatabase(context.Background(), d.name); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(t.Context()); !errors.Is(err, db.ErrDatabaseUnavailable) {
		t.Fatalf("after dropping the database: %v, want ErrDatabaseUnavailable", err)
	}
}
