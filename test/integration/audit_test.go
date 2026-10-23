//go:build integration

package integration_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
)

func writeAudited(t *testing.T, s *db.Store, ws uuid.UUID, entries ...audit.Entry) {
	t.Helper()
	err := s.Write(t.Context(), workspaceScope(t, ws), func(ctx context.Context, tx *db.WriteTx) error {
		for _, e := range entries {
			if err := tx.Audit(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuditMetadataIsRedactedInStorage(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	writeAudited(t, s, uuid.New(), audit.Entry{
		Action: "credential.issue", TargetType: "ci_credential", Outcome: audit.Success,
		Metadata: map[string]any{
			"token":    secret.New([]byte("qali_ci_raw-token-value")),
			"password": "plain-password-value",
			"name":     "nightly",
		},
	})
	var stored string
	if err := connect(t, d.admin).QueryRow(t.Context(), "SELECT metadata::text FROM qali.audit_events").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "raw-token-value") || strings.Contains(stored, "plain-password-value") || !strings.Contains(stored, "nightly") {
		t.Fatalf("stored metadata = %s", stored)
	}
}

func TestAuditEventsAreImmutable(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	writeAudited(t, s, uuid.New(), created)

	for role, conn := range map[string]testDatabase{"runtime": {app: d.app}, "owner": {app: d.migrator}} {
		c := connect(t, conn.app)
		for _, stmt := range []string{
			"UPDATE qali.audit_events SET action = 'job.delete'",
			"DELETE FROM qali.audit_events",
			"TRUNCATE qali.audit_events",
		} {
			_, err := c.Exec(t.Context(), stmt)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("%s role: %q err = %v, want insufficient privilege", role, stmt, err)
			}
		}
	}
	if countAudit(t, d) != 1 {
		t.Fatal("audit event was modified or removed")
	}
}

func TestAuditChainVerifiesAndDetectsTampering(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	ws := uuid.New()
	writeAudited(t, s, ws, created, created)
	writeAudited(t, s, ws, audit.Entry{Action: "job.update", Outcome: audit.Success, Metadata: map[string]any{"n": 1.5}})
	writeAudited(t, s, uuid.New(), created) // another chain

	verify := func() error {
		var err error
		readErr := s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
			events, loadErr := audit.LoadChain(ctx, q, ws.String())
			if loadErr != nil {
				return loadErr
			}
			if len(events) != 3 {
				t.Fatalf("chain has %d events, want 3", len(events))
			}
			err = audit.VerifyChain(events)
			return nil
		})
		if readErr != nil {
			t.Fatal(readErr)
		}
		return err
	}
	if err := verify(); err != nil {
		t.Fatalf("untampered chain: %v", err)
	}

	// A database superuser bypasses the trigger and edits history.
	admin := connect(t, d.admin)
	if _, err := admin.Exec(t.Context(), `
		ALTER TABLE qali.audit_events DISABLE TRIGGER audit_events_no_update_delete;
		UPDATE qali.audit_events SET action = 'job.delete' WHERE seq = (SELECT min(seq) + 1 FROM qali.audit_events);
		ALTER TABLE qali.audit_events ENABLE TRIGGER audit_events_no_update_delete;`); err != nil {
		t.Fatal(err)
	}
	if err := verify(); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("tampered chain verified: %v", err)
	}
}

func TestAuditEntryValidationRollsBack(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	err := s.Write(t.Context(), workspaceScope(t, uuid.New()), func(ctx context.Context, tx *db.WriteTx) error {
		return tx.Audit(ctx, audit.Entry{Action: "Bad Action", Outcome: audit.Success})
	})
	if err == nil || countAudit(t, d) != 0 {
		t.Fatalf("invalid audit entry accepted: %v", err)
	}
}

func TestSystemScopeEventsUseTheSystemChain(t *testing.T) {
	d := migratedDatabase(t)
	s := openStore(t, d)
	for range 2 {
		err := s.Write(t.Context(), systemScope(t), func(ctx context.Context, tx *db.WriteTx) error {
			if tx.Scope().Workspace() != uuid.Nil {
				t.Fatal("system scope has a workspace")
			}
			return tx.Audit(ctx, audit.Entry{Action: "job.dead_letter", Outcome: audit.Failure})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	err := s.Read(t.Context(), systemScope(t), func(ctx context.Context, q db.Querier) error {
		events, err := audit.LoadChain(ctx, q, audit.SystemChain)
		if err != nil {
			return err
		}
		if len(events) != 2 || events[0].WorkspaceID != nil || events[1].SourceIP.IsValid() {
			t.Fatalf("system chain = %+v", events)
		}
		return audit.VerifyChain(events)
	})
	if err != nil {
		t.Fatal(err)
	}
}
