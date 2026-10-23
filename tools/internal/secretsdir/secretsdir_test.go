package secretsdir_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/config"
	"github.com/qali-project/qali/tools/internal/secretsdir"
)

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestGeneratedSecretsSatisfyBothConfigurations(t *testing.T) {
	dir := t.TempDir()
	if err := secretsdir.Write(dir, secretsdir.URLs{}); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, name := range []string{"kek", "token_pepper", "password_pepper"} {
		raw, err := base64.StdEncoding.DecodeString(read(t, dir, name))
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s is not base64 of 32 bytes", name)
		}
		keys[string(raw)] = true
	}
	if len(keys) != 3 {
		t.Fatal("generated keys must be distinct")
	}
	env := map[string]string{
		"QALI_ENV":                         "development",
		"QALI_PUBLIC_URL":                  "http://127.0.0.1:18473",
		"QALI_DATABASE_URL_FILE":           filepath.Join(dir, "database_url"),
		"QALI_MIGRATION_DATABASE_URL_FILE": filepath.Join(dir, "migration_database_url"),
		"QALI_KEK_FILE":                    filepath.Join(dir, "kek"),
		"QALI_TOKEN_PEPPER_FILE":           filepath.Join(dir, "token_pepper"),
		"QALI_PASSWORD_PEPPER_FILE":        filepath.Join(dir, "password_pepper"),
	}
	src := config.Source{Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }, ReadFile: os.ReadFile}
	if _, err := config.Load(src); err != nil {
		t.Fatalf("server configuration rejected: %v", err)
	}
	if _, err := config.LoadMigration(src); err != nil {
		t.Fatalf("migration configuration rejected: %v", err)
	}
}

func TestDefaultURLsUseTheGeneratedRolePasswords(t *testing.T) {
	dir := t.TempDir()
	if err := secretsdir.Write(dir, secretsdir.URLs{}); err != nil {
		t.Fatal(err)
	}
	app, migrator, admin := read(t, dir, "app_password"), read(t, dir, "migrator_password"), read(t, dir, "postgres_password")
	if len(app) < 32 || len(migrator) < 32 || len(admin) < 32 || app == migrator || app == admin || migrator == admin {
		t.Fatal("role passwords must be long and distinct")
	}
	if got := read(t, dir, "database_url"); got != "postgres://qali_app:"+app+"@postgres:5432/qali?sslmode=disable" {
		t.Fatal("database_url does not use the runtime role")
	}
	if got := read(t, dir, "migration_database_url"); got != "postgres://qali_migrator:"+migrator+"@postgres:5432/qali?sslmode=disable" {
		t.Fatal("migration_database_url does not use the migration role")
	}
}

func TestExplicitURLsAreWritten(t *testing.T) {
	dir := t.TempDir()
	urls := secretsdir.URLs{App: "postgres://a@localhost/x", Migration: "postgres://m@localhost/x"}
	if err := secretsdir.Write(dir, urls); err != nil {
		t.Fatal(err)
	}
	if read(t, dir, "database_url") != urls.App || read(t, dir, "migration_database_url") != urls.Migration {
		t.Fatal("explicit URLs were not written")
	}
}

func TestExistingSecretsAreNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secretsdir.Write(dir, secretsdir.URLs{}); err == nil {
		t.Fatal("Write must refuse to overwrite an existing key file")
	}
	if read(t, dir, "kek") != "existing" {
		t.Fatal("existing key file was modified")
	}
}
