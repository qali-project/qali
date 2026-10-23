package config_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/config"
)

func randomKeyFile(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b) + "\n"
}

type fixture struct {
	env   map[string]string
	files map[string]string
}

func validFixture(t *testing.T) fixture {
	t.Helper()
	return fixture{
		env: map[string]string{
			"QALI_PUBLIC_URL":           "https://qali.example.org",
			"QALI_DATABASE_URL_FILE":    "/run/secrets/database_url",
			"QALI_KEK_FILE":             "/run/secrets/kek",
			"QALI_TOKEN_PEPPER_FILE":    "/run/secrets/token_pepper",
			"QALI_PASSWORD_PEPPER_FILE": "/run/secrets/password_pepper",
		},
		files: map[string]string{
			"/run/secrets/database_url":    "postgres://qali_app:db-password-value@postgres:5432/qali?sslmode=disable\n",
			"/run/secrets/kek":             randomKeyFile(t),
			"/run/secrets/token_pepper":    randomKeyFile(t),
			"/run/secrets/password_pepper": randomKeyFile(t),
		},
	}
}

func (f fixture) source() config.Source {
	return config.Source{
		Getenv: func(k string) (string, bool) { v, ok := f.env[k]; return v, ok },
		ReadFile: func(p string) ([]byte, error) {
			v, ok := f.files[p]
			if !ok {
				return nil, fmt.Errorf("open %s: %w", p, fs.ErrNotExist)
			}
			return []byte(v), nil
		},
	}
}

func load(t *testing.T, f fixture) (config.Config, error) {
	t.Helper()
	return config.Load(f.source())
}

func mustFail(t *testing.T, f fixture, wants ...string) {
	t.Helper()
	_ = failure(t, f, wants...) // failure already asserts; the error is not needed here
}

// failure asserts that loading fails and that the error names every want.
func failure(t *testing.T, f fixture, wants ...string) error {
	t.Helper()
	_, err := load(t, f)
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not mention %q", err, w)
		}
	}
	return err
}

func TestValidProductionConfiguration(t *testing.T) {
	f := validFixture(t)
	cfg, err := load(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL.String() != "https://qali.example.org" || cfg.HTTPAddr != ":8080" || cfg.Environment != config.Production {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.KEK.Len() != 32 || cfg.TokenPepper.Len() != 32 || cfg.PasswordPepper.Len() != 32 {
		t.Fatal("key material was not decoded to 32 bytes")
	}
	if !strings.HasPrefix(string(cfg.DatabaseURL.Expose()), "postgres://qali_app:") {
		t.Fatal("database URL not loaded")
	}
	printed := fmt.Sprintf("%+v %#v", cfg, cfg)
	for _, file := range f.files {
		if strings.Contains(printed, strings.TrimSpace(file)) {
			t.Fatalf("printing the configuration leaked a secret: %s", printed)
		}
	}
	if strings.Contains(printed, "db-password-value") {
		t.Fatal("printing the configuration leaked the database password")
	}
}

func TestMissingRequiredSettingsAreAllReported(t *testing.T) {
	f := validFixture(t)
	delete(f.env, "QALI_PUBLIC_URL")
	delete(f.env, "QALI_KEK_FILE")
	delete(f.env, "QALI_PASSWORD_PEPPER_FILE")
	mustFail(t, f, "QALI_PUBLIC_URL", "QALI_KEK_FILE", "QALI_PASSWORD_PEPPER_FILE")
}

func TestPlainEnvironmentSecretsAreRejected(t *testing.T) {
	for _, name := range []string{"QALI_KEK", "QALI_TOKEN_PEPPER", "QALI_PASSWORD_PEPPER", "QALI_DATABASE_URL"} {
		t.Run(name, func(t *testing.T) {
			f := validFixture(t)
			f.env[name] = "anything"
			mustFail(t, f, name, name+"_FILE")
		})
	}
}

func TestUnreadableSecretFileNamesTheSetting(t *testing.T) {
	f := validFixture(t)
	delete(f.files, "/run/secrets/token_pepper")
	mustFail(t, f, "QALI_TOKEN_PEPPER_FILE")
}

func TestWeakKeyMaterialFailsClosed(t *testing.T) {
	cases := map[string]string{
		"not base64":  "this is not base64 ###",
		"too short":   base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":    base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"all zero":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"low entropy": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("ab", 16))),
		"empty":       "",
		"placeholder": "CHANGE_ME",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFixture(t)
			f.files["/run/secrets/kek"] = content
			err := failure(t, f, "QALI_KEK_FILE")
			if content != "" && strings.Contains(err.Error(), content) {
				t.Fatalf("error leaked key file content: %v", err)
			}
		})
	}
}

func TestReusedKeyMaterialIsRejected(t *testing.T) {
	f := validFixture(t)
	f.files["/run/secrets/token_pepper"] = f.files["/run/secrets/kek"]
	mustFail(t, f, "distinct", "QALI_KEK_FILE", "QALI_TOKEN_PEPPER_FILE")
}

func TestPublicURLRules(t *testing.T) {
	cases := []struct {
		env, url string
		ok       bool
	}{
		{"production", "https://qali.example.org", true},
		{"production", "https://qali.example.org/", true},
		{"production", "http://qali.example.org", false},
		{"production", "https://qali.example.org/sub?x=1", false},
		{"production", "qali.example.org", false},
		{"production", "https://user:pw@qali.example.org", false},
		{"development", "http://localhost:8080", true},
		{"development", "http://127.0.0.1:8080", true},
		{"development", "http://qali.example.org", false},
	}
	for _, tc := range cases {
		t.Run(tc.env+" "+tc.url, func(t *testing.T) {
			f := validFixture(t)
			f.env["QALI_ENV"] = tc.env
			f.env["QALI_PUBLIC_URL"] = tc.url
			_, err := load(t, f)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "QALI_PUBLIC_URL")) {
				t.Fatalf("want a QALI_PUBLIC_URL error, got %v", err)
			}
		})
	}
}

func TestDatabaseURLRules(t *testing.T) {
	cases := map[string]struct {
		url string
		ok  bool
	}{
		"private compose host without TLS": {"postgres://u:p@postgres:5432/qali?sslmode=disable", true},
		"remote host with verify-full":     {"postgres://u:p@db.example.org:5432/qali?sslmode=verify-full", true},
		"remote host without TLS":          {"postgres://u:p@db.example.org:5432/qali?sslmode=disable", false},
		"remote host with default sslmode": {"postgres://u:p@db.example.org:5432/qali", false},
		"remote host with require":         {"postgres://u:p@db.example.org/qali?sslmode=require", false},
		"wrong scheme":                     {"mysql://u:p@postgres/qali", false},
		"not a URL":                        {"::::", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := validFixture(t)
			f.files["/run/secrets/database_url"] = tc.url
			_, err := load(t, f)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok {
				if err == nil || !strings.Contains(err.Error(), "QALI_DATABASE_URL_FILE") {
					t.Fatalf("want a QALI_DATABASE_URL_FILE error, got %v", err)
				}
				if strings.Contains(err.Error(), ":p@") {
					t.Fatalf("error leaked database credentials: %v", err)
				}
			}
		})
	}
}

func TestOptionalSettings(t *testing.T) {
	f := validFixture(t)
	f.env["QALI_HTTP_ADDR"] = "0.0.0.0:9000"
	f.env["QALI_TRUSTED_PROXIES"] = "10.0.0.0/8, 172.20.0.2/32"
	cfg, err := load(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != "0.0.0.0:9000" || len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[1].String() != "172.20.0.2/32" {
		t.Fatalf("cfg = %+v", cfg)
	}

	f.env["QALI_TRUSTED_PROXIES"] = "10.0.0.0/8,not-a-cidr"
	mustFail(t, f, "QALI_TRUSTED_PROXIES")

	f = validFixture(t)
	f.env["QALI_ENV"] = "staging"
	mustFail(t, f, "QALI_ENV")
}

func TestLoadErrorIsTyped(t *testing.T) {
	f := validFixture(t)
	delete(f.env, "QALI_PUBLIC_URL")
	_, err := load(t, f)
	var cerr *config.Error
	if !errors.As(err, &cerr) || len(cerr.Problems) != 1 {
		t.Fatalf("err = %#v, want *config.Error with one problem", err)
	}
}

func TestMigrationConfiguration(t *testing.T) {
	f := fixture{
		env: map[string]string{"QALI_MIGRATION_DATABASE_URL_FILE": "/run/secrets/migration_database_url"},
		files: map[string]string{
			"/run/secrets/migration_database_url": "postgres://qali_migrator:pw@postgres:5432/qali?sslmode=disable",
		},
	}
	cfg, err := config.LoadMigration(f.source())
	if err != nil {
		t.Fatalf("migration config without server keys must load: %v", err)
	}
	if !strings.HasPrefix(string(cfg.DatabaseURL.Expose()), "postgres://qali_migrator:") {
		t.Fatal("migration URL not loaded")
	}

	f.env["QALI_MIGRATION_DATABASE_URL"] = "postgres://x"
	if _, err := config.LoadMigration(f.source()); err == nil || !strings.Contains(err.Error(), "QALI_MIGRATION_DATABASE_URL_FILE") {
		t.Fatalf("plain migration URL accepted: %v", err)
	}
	if _, err := config.LoadMigration(fixture{env: map[string]string{}}.source()); err == nil {
		t.Fatal("missing migration URL accepted")
	}
	remote := fixture{
		env:   map[string]string{"QALI_MIGRATION_DATABASE_URL_FILE": "/m"},
		files: map[string]string{"/m": "postgres://m:pw@db.example.org/qali?sslmode=disable"},
	}
	if _, err := config.LoadMigration(remote.source()); err == nil {
		t.Fatal("remote migration connection without TLS accepted")
	}
}
