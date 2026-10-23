//go:build integration

package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/db"
)

// probeTable is a test-only tenant table built with the production isolation
// helper, standing in for future feature tables.
func probeTable(t *testing.T, d testDatabase) {
	t.Helper()
	_, err := connect(t, d.migrator).Exec(t.Context(), `
		CREATE TABLE qali.probe_items (
			workspace_id uuid NOT NULL,
			id           uuid NOT NULL,
			name         text NOT NULL,
			PRIMARY KEY (workspace_id, id)
		);
		SELECT qali.enable_workspace_isolation('qali.probe_items');`)
	if err != nil {
		t.Fatal(err)
	}
}

var touched = audit.Entry{Action: "probe.write", TargetType: "probe", Outcome: audit.Success}

func insertProbe(t *testing.T, s *db.Store, ws, id uuid.UUID, name string) {
	t.Helper()
	err := s.Write(t.Context(), workspaceScope(t, ws), func(ctx context.Context, tx *db.WriteTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO probe_items (workspace_id, id, name) VALUES ($1, $2, $3)", ws, id, name); err != nil {
			return err
		}
		return tx.Audit(ctx, touched)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestWrongWorkspaceNeverSeesOrChangesData proves MVP-03.AC-05.
func TestWrongWorkspaceNeverSeesOrChangesData(t *testing.T) {
	d := migratedDatabase(t)
	probeTable(t, d)
	s := openStore(t, d)
	wsA, wsB := uuid.New(), uuid.New()
	secretA := uuid.New()
	insertProbe(t, s, wsA, secretA, "alpha confidential")
	insertProbe(t, s, wsB, uuid.New(), "beta visible")

	asB := workspaceScope(t, wsB)
	read := func(query string, args ...any) int {
		t.Helper()
		var n int
		err := s.Read(t.Context(), asB, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx, query, args...).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Reads: guessed ID with and without the workspace filter, counts, search.
	if n := read("SELECT count(*) FROM probe_items WHERE id = $1 AND workspace_id = $2", secretA, wsA); n != 0 {
		t.Fatal("guessed ID with forged workspace filter was readable")
	}
	if n := read("SELECT count(*) FROM probe_items WHERE id = $1", secretA); n != 0 {
		t.Fatal("guessed ID was readable through a query without a workspace filter")
	}
	if n := read("SELECT count(*) FROM probe_items"); n != 1 {
		t.Fatalf("count saw %d rows, want only workspace B's 1", n)
	}
	if n := read("SELECT count(*) FROM probe_items WHERE name ILIKE '%confidential%'"); n != 0 {
		t.Fatal("search matched another workspace's row")
	}

	// Writes: update, delete, and inserting into another workspace.
	affected := func(stmt string, args ...any) (int64, error) {
		var rows int64
		err := s.Write(t.Context(), asB, func(ctx context.Context, tx *db.WriteTx) error {
			if err := tx.Audit(ctx, touched); err != nil {
				return err
			}
			tag, err := tx.Exec(ctx, stmt, args...)
			rows = tag.RowsAffected()
			return db.MapError(err)
		})
		return rows, err
	}
	if n, err := affected("UPDATE probe_items SET name = 'pwned' WHERE id = $1", secretA); err != nil || n != 0 {
		t.Fatalf("update of a foreign row: %d rows, %v", n, err)
	}
	if n, err := affected("DELETE FROM probe_items WHERE id = $1", secretA); err != nil || n != 0 {
		t.Fatalf("delete of a foreign row: %d rows, %v", n, err)
	}
	if n, err := affected("UPDATE probe_items SET workspace_id = $1", wsA); !errors.Is(err, db.ErrForbidden) || n != 0 {
		t.Fatalf("moving rows into another workspace: %d rows, %v", n, err)
	}
	if _, err := affected("INSERT INTO probe_items (workspace_id, id, name) VALUES ($1, $2, 'planted')", wsA, uuid.New()); !errors.Is(err, db.ErrForbidden) {
		t.Fatalf("insert into another workspace: %v", err)
	}

	// Workspace A's row is untouched.
	var name string
	err := s.Read(t.Context(), workspaceScope(t, wsA), func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, "SELECT name FROM probe_items WHERE id = $1", secretA).Scan(&name)
	})
	if err != nil || name != "alpha confidential" {
		t.Fatalf("workspace A row = %q, %v", name, err)
	}
}

func TestUnscopedAccessSeesNoTenantRows(t *testing.T) {
	d := migratedDatabase(t)
	probeTable(t, d)
	s := openStore(t, d)
	insertProbe(t, s, uuid.New(), uuid.New(), "row")

	var n int
	err := s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, "SELECT count(*) FROM probe_items").Scan(&n)
	})
	if err != nil || n != 0 {
		t.Fatalf("system scope saw %d tenant rows (%v)", n, err)
	}
	if err := connect(t, d.app).QueryRow(t.Context(), "SELECT count(*) FROM probe_items").Scan(&n); err != nil || n != 0 {
		t.Fatalf("a raw runtime connection saw %d tenant rows (%v)", n, err)
	}
}

func TestWorkspaceSettingDoesNotLeakBetweenTransactions(t *testing.T) {
	d := migratedDatabase(t)
	probeTable(t, d)
	s, err := db.Open(t.Context(), d.app, db.Options{MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	insertProbe(t, s, uuid.New(), uuid.New(), "row")
	var n int
	err = s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, "SELECT count(*) FROM probe_items").Scan(&n)
	})
	if err != nil || n != 0 {
		t.Fatalf("the next transaction on the same connection saw %d rows (%v)", n, err)
	}
}

// A user-attributed scope exposes qali.user_id so the member_self policy can
// show a user their own memberships across workspaces, and nothing else.
func TestUserScopeSeesOnlyOwnMemberships(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	admin := connect(t, d.admin)
	me, other := uuid.New(), uuid.New()
	wsA, wsB := uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO qali.users (id, email, display_name, status, created_at, updated_at) VALUES ($1, 'me@example.org', 'Me', 'active', now(), now()), ($2, 'other@example.org', 'Other', 'active', now(), now())", []any{me, other}},
		{"INSERT INTO qali.workspaces (id, name, created_at, updated_at) VALUES ($1, 'A', now(), now()), ($2, 'B', now(), now())", []any{wsA, wsB}},
		{`INSERT INTO qali.workspace_members (workspace_id, user_id, role, status, created_at, updated_at) VALUES
		  ($1, $3, 'owner', 'active', now(), now()), ($2, $3, 'tester', 'active', now(), now()), ($2, $4, 'viewer', 'active', now(), now())`, []any{wsA, wsB, me, other}},
	} {
		if _, err := admin.Exec(t.Context(), stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sc db.Scope, query string) int {
		var n int
		if err := s.Read(t.Context(), sc, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx, query).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	mine, err := db.SystemScope(audit.Actor{Type: audit.ActorUser, ID: me.String()}, db.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(mine, "SELECT count(*) FROM workspace_members"); n != 2 {
		t.Fatalf("user scope saw %d memberships, want own 2", n)
	}
	if n := count(mine, "SELECT count(*) FROM workspaces"); n != 2 {
		t.Fatalf("user scope saw %d workspaces, want 2", n)
	}
	if n := count(systemScope(t), "SELECT count(*) FROM workspace_members"); n != 0 {
		t.Fatalf("system scope saw %d memberships", n)
	}
	nonUser, err := db.SystemScope(audit.Actor{Type: audit.ActorCI, ID: me.String()}, db.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(nonUser, "SELECT count(*) FROM workspace_members"); n != 0 {
		t.Fatalf("a non-user actor with a user's ID saw %d memberships", n)
	}
}
