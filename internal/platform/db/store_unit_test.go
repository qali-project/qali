package db_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/db"
	"github.com/qali-project/qali/internal/platform/secret"
)

const leakyDSN = "postgres://qali_app:pa55-word-value@db.example.org:notaport/qali"

func TestConnectionStringErrorsDoNotRevealPasswords(t *testing.T) {
	dsn := secret.New([]byte(leakyDSN))
	if _, err := db.Open(t.Context(), dsn, db.Options{}); err == nil || strings.Contains(err.Error(), "pa55-word-value") {
		t.Fatalf("Open error = %v", err)
	}
	if _, err := db.Migrate(t.Context(), dsn); err == nil || strings.Contains(err.Error(), "pa55-word-value") {
		t.Fatalf("Migrate error = %v", err)
	}
	if err := db.Rollback(t.Context(), dsn, 0); err == nil || strings.Contains(err.Error(), "pa55-word-value") {
		t.Fatalf("Rollback error = %v", err)
	}
}

func TestScopes(t *testing.T) {
	ws := uuid.New()
	sc, err := db.WorkspaceScope(ws, audit.Actor{Type: audit.ActorCI, ID: "cred-1"}, db.RequestInfo{})
	if err != nil || sc.Workspace() != ws {
		t.Fatalf("workspace scope = %v, %v", sc.Workspace(), err)
	}
	sys, err := db.SystemScope(audit.Actor{Type: audit.ActorSystem}, db.RequestInfo{})
	if err != nil || sys.Workspace() != uuid.Nil {
		t.Fatalf("system scope = %v, %v", sys.Workspace(), err)
	}
	if _, err := db.SystemScope(audit.Actor{Type: "robot"}, db.RequestInfo{}); err == nil {
		t.Fatal("system scope accepted an unknown actor type")
	}
}

func TestLatestMigrationMatchesEmbeddedFiles(t *testing.T) {
	if db.LatestMigration() < 3 {
		t.Fatalf("LatestMigration = %d, want at least 3", db.LatestMigration())
	}
}
