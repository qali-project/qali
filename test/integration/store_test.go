//go:build integration

package integration_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/db"
)

var testActor = audit.Actor{Type: audit.ActorUser, ID: "user-1"}

func openStore(t *testing.T, d testDatabase) *db.Store {
	t.Helper()
	s, err := db.Open(t.Context(), d.app, db.Options{
		Clock: clock.NewManual(time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func workspaceScope(t *testing.T, ws uuid.UUID) db.Scope {
	t.Helper()
	sc, err := db.WorkspaceScope(ws, testActor, db.RequestInfo{RequestID: "req-1", SourceIP: netip.MustParseAddr("203.0.113.9")})
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func systemScope(t *testing.T) db.Scope {
	t.Helper()
	sc, err := db.SystemScope(audit.Actor{Type: audit.ActorSystem, ID: "worker"}, db.RequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

const insertJob = `INSERT INTO jobs (id, queue, kind, status, max_attempts, run_at, created_at, updated_at, idempotency_key)
	VALUES ($1, 'default', 'probe', 'pending', 1, now(), now(), now(), $2)`

func countJobs(t *testing.T, s *db.Store) int {
	t.Helper()
	var n int
	err := s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, "SELECT count(*) FROM jobs").Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func countAudit(t *testing.T, d testDatabase) int {
	t.Helper()
	var n int
	if err := connect(t, d.admin).QueryRow(t.Context(), "SELECT count(*) FROM qali.audit_events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var created = audit.Entry{Action: "job.create", TargetType: "job", Outcome: audit.Success}

func TestWriteCommitsWithAuditEvent(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	ws := uuid.New()
	err := s.Write(t.Context(), workspaceScope(t, ws), func(ctx context.Context, tx *db.WriteTx) error {
		if _, err := tx.Exec(ctx, insertJob, uuid.New(), nil); err != nil {
			return err
		}
		return tx.Audit(ctx, created)
	})
	if err != nil {
		t.Fatal(err)
	}
	if countJobs(t, s) != 1 {
		t.Fatal("write was not committed")
	}
	var actorType, actorID, requestID, sourceIP, chain string
	err = connect(t, d.admin).QueryRow(t.Context(),
		"SELECT actor_type, actor_id, request_id, host(source_ip), chain FROM qali.audit_events").
		Scan(&actorType, &actorID, &requestID, &sourceIP, &chain)
	if err != nil {
		t.Fatal(err)
	}
	if actorType != "user" || actorID != "user-1" || requestID != "req-1" || sourceIP != "203.0.113.9" || chain != ws.String() {
		t.Fatalf("audit attribution = %s %s %s %s %s", actorType, actorID, requestID, sourceIP, chain)
	}
}

func TestWriteWithoutAuditIsRolledBack(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	err := s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
		_, err := tx.Exec(ctx, insertJob, uuid.New(), nil)
		return err
	})
	if !errors.Is(err, db.ErrUnaudited) {
		t.Fatalf("err = %v, want ErrUnaudited", err)
	}
	if countJobs(t, s) != 0 || countAudit(t, d) != 0 {
		t.Fatal("unaudited write was committed")
	}
}

func TestWriteRollsBackOnErrorAndPanic(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	boom := errors.New("boom")
	err := s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
		if _, err := tx.Exec(ctx, insertJob, uuid.New(), nil); err != nil {
			return err
		}
		if err := tx.Audit(ctx, created); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the callback error", err)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was swallowed")
			}
		}()
		_ = s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
			if _, err := tx.Exec(ctx, insertJob, uuid.New(), nil); err != nil {
				return err
			}
			_ = tx.Audit(ctx, created)
			panic("handler bug")
		})
	}()
	if countJobs(t, s) != 0 || countAudit(t, d) != 0 {
		t.Fatal("failed writes were committed")
	}
}

func TestReadIsReadOnly(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	err := s.Read(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, insertJob, uuid.New(), nil)
		return db.MapError(err)
	})
	if !errors.Is(err, db.ErrReadOnly) {
		t.Fatalf("err = %v, want ErrReadOnly", err)
	}
}

func TestDatabaseErrorsMapWithoutLeakingSQL(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	write := func(stmt string, args ...any) error {
		return s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
			if err := tx.Audit(ctx, created); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, stmt, args...)
			return db.MapError(err)
		})
	}
	if err := write(insertJob, uuid.New(), "key-1"); err != nil {
		t.Fatal(err)
	}
	dup := write(insertJob, uuid.New(), "key-1")
	if !errors.Is(dup, db.ErrConflict) || strings.Contains(dup.Error(), "jobs") {
		t.Fatalf("duplicate = %v", dup)
	}
	bad := write(`INSERT INTO jobs (id, queue, kind, status, max_attempts, run_at, created_at, updated_at)
		VALUES ($1, 'default', 'probe', 'exploded', 1, now(), now(), now())`, uuid.New())
	if !errors.Is(bad, db.ErrInvalid) || strings.Contains(bad.Error(), "exploded") {
		t.Fatalf("check violation = %v", bad)
	}
	missing := s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
		var id uuid.UUID
		return db.MapError(q.QueryRow(ctx, "SELECT id FROM jobs WHERE id = $1", uuid.New()).Scan(&id))
	})
	if !errors.Is(missing, db.ErrNotFound) {
		t.Fatalf("missing row = %v", missing)
	}
}

func TestStoreRefusesPrivilegedRoles(t *testing.T) {
	d := migratedDatabase(t)
	for name, dsn := range map[string]testDatabase{"superuser": {app: d.admin}} {
		if _, err := db.Open(t.Context(), dsn.app, db.Options{}); err == nil {
			t.Fatalf("%s connection accepted as the runtime role", name)
		}
	}
	if _, err := db.Open(t.Context(), d.migrator, db.Options{}); err == nil {
		t.Fatal("schema owner accepted as the runtime role")
	}
}

func TestScopeValidation(t *testing.T) {
	if _, err := db.WorkspaceScope(uuid.Nil, testActor, db.RequestInfo{}); err == nil {
		t.Fatal("nil workspace accepted")
	}
	if _, err := db.WorkspaceScope(uuid.New(), audit.Actor{Type: "robot"}, db.RequestInfo{}); err == nil {
		t.Fatal("invalid actor accepted")
	}
}

func TestWriteTxQueriesSeeTheirOwnChanges(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	if err := s.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	ws := uuid.New()
	id := uuid.New()
	err := s.Write(t.Context(), workspaceScope(t, ws), func(ctx context.Context, tx *db.WriteTx) error {
		if tx.Scope().Workspace() != ws {
			t.Fatal("write scope lost its workspace")
		}
		if _, err := tx.Exec(ctx, insertJob, id, nil); err != nil {
			return err
		}
		var kind string
		if err := tx.QueryRow(ctx, "SELECT kind FROM jobs WHERE id = $1", id).Scan(&kind); err != nil || kind != "probe" {
			t.Fatalf("QueryRow inside the transaction: %q, %v", kind, err)
		}
		rows, err := tx.Query(ctx, "SELECT id FROM jobs")
		if err != nil {
			return err
		}
		n := 0
		for rows.Next() {
			n++
		}
		rows.Close()
		if n != 1 {
			t.Fatalf("Query saw %d rows", n)
		}
		return tx.Audit(ctx, created)
	})
	if err != nil {
		t.Fatal(err)
	}
}
