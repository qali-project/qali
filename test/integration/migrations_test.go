//go:build integration

package integration_test

import (
	"slices"
	"sync"
	"testing"

	"github.com/qali-project/qali/internal/platform/db"
)

func tableExists(t *testing.T, d testDatabase, table string) bool {
	t.Helper()
	var exists bool
	if err := connect(t, d.admin).QueryRow(t.Context(), "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func appliedVersions(t *testing.T, d testDatabase) []int64 {
	t.Helper()
	rows, err := connect(t, d.admin).Query(t.Context(),
		"SELECT version_id FROM qali.goose_db_version WHERE version_id > 0 AND is_applied ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// allVersions lists every embedded migration version (1..latest).
func allVersions() []int64 {
	var out []int64
	for v := int64(1); v <= db.LatestMigration(); v++ {
		out = append(out, v)
	}
	return out
}

func TestMigrationsApplyFromEmptyDatabase(t *testing.T) {
	d := newDatabase(t)
	applied, err := db.Migrate(t.Context(), d.migrator)
	if err != nil {
		t.Fatal(err)
	}
	want := allVersions()
	if !slices.Equal(applied, want) || len(want) < 4 {
		t.Fatalf("applied %v, latest %d; want %v", applied, db.LatestMigration(), want)
	}
	for _, table := range []string{"qali.audit_events", "qali.jobs", "qali.users", "qali.sessions"} {
		if !tableExists(t, d, table) {
			t.Fatalf("%s missing after migration", table)
		}
	}
	again, err := db.Migrate(t.Context(), d.migrator)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run applied %v, err %v; want nothing", again, err)
	}
}

func TestMigrationsRollBackAndReapply(t *testing.T) {
	d := migratedDatabase(t)
	if err := db.Rollback(t.Context(), d.migrator, 0); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	for _, table := range []string{"qali.audit_events", "qali.jobs", "qali.users", "qali.sessions"} {
		if tableExists(t, d, table) {
			t.Fatalf("%s still exists after rollback", table)
		}
	}
	if _, err := db.Migrate(t.Context(), d.migrator); err != nil {
		t.Fatalf("re-apply after rollback: %v", err)
	}
	if got := appliedVersions(t, d); !slices.Equal(got, allVersions()) {
		t.Fatalf("versions after re-apply = %v", got)
	}
}

func TestConcurrentMigrationsApplyEachVersionOnce(t *testing.T) {
	d := newDatabase(t)
	const runners = 6
	var wg sync.WaitGroup
	errs := make([]error, runners)
	applied := make([][]int64, runners)
	for i := range runners {
		wg.Go(func() {
			applied[i], errs[i] = db.Migrate(t.Context(), d.migrator)
		})
	}
	wg.Wait()
	total := 0
	for i := range runners {
		if errs[i] != nil {
			t.Fatalf("runner %d: %v", i, errs[i])
		}
		total += len(applied[i])
	}
	if total != len(allVersions()) {
		t.Fatalf("runners applied %d migrations in total, want exactly %d", total, len(allVersions()))
	}
	if got := appliedVersions(t, d); !slices.Equal(got, allVersions()) {
		t.Fatalf("version table = %v, want each version once", got)
	}
}

func TestRuntimeRoleCannotMigrate(t *testing.T) {
	d := newDatabase(t)
	if _, err := db.Migrate(t.Context(), d.app); err == nil {
		t.Fatal("the runtime role applied migrations")
	}
	if tableExists(t, d, "qali.jobs") {
		t.Fatal("runtime role created a table")
	}
}
