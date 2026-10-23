package audit_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/clock"
)

// Rejections happen before any statement runs, so no database is needed; a
// nil DBTX would panic if the writer reached the database.
func TestAppendRejectsBeforeTouchingTheDatabase(t *testing.T) {
	ok := func() (uuid.UUID, error) { return uuid.New(), nil }
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	w := audit.NewWriter(clock.NewManual(at), ok)
	valid := audit.Context{Actor: audit.Actor{Type: audit.ActorUser, ID: "u"}}
	entry := audit.Entry{Action: "case.update", Outcome: audit.Success}

	if _, err := w.Append(t.Context(), nil, valid, audit.Entry{Action: "bad", Outcome: audit.Success}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	if _, err := w.Append(t.Context(), nil, audit.Context{Actor: audit.Actor{Type: "robot"}}, entry); err == nil {
		t.Fatal("invalid actor accepted")
	}
	big := entry
	big.Metadata = map[string]any{"blob": strings.Repeat("x", 20000)}
	if _, err := w.Append(t.Context(), nil, valid, big); !errors.Is(err, audit.ErrMetadataTooLarge) {
		t.Fatalf("oversized metadata: %v", err)
	}
	idErr := errors.New("entropy exhausted")
	failing := audit.NewWriter(clock.NewManual(at), func() (uuid.UUID, error) { return uuid.Nil, idErr })
	if _, err := failing.Append(t.Context(), nil, valid, entry); !errors.Is(err, idErr) {
		t.Fatalf("ID generation failure: %v", err)
	}
}
