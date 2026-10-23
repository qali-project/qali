// Package secretsdir writes a complete set of throwaway secret files for
// local development, E2E tests, and the Compose deployment check. Production
// operators generate their own keys and passwords and keep them outside the
// repository.
package secretsdir

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// URLs overrides the database connection strings. Empty values select the
// Compose database with the generated role passwords.
type URLs struct {
	App       string
	Migration string
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Write creates dir and every secret file the Compose stack expects. It
// never overwrites an existing file.
func Write(dir string, urls URLs) error {
	files := map[string]string{}
	for _, name := range []string{"postgres_password", "migrator_password", "app_password"} {
		pw, err := randomHex(24)
		if err != nil {
			return err
		}
		files[name] = pw
	}
	for _, name := range []string{"kek", "token_pepper", "password_pepper"} {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		files[name] = base64.StdEncoding.EncodeToString(b)
	}
	if urls.App == "" {
		urls.App = "postgres://qali_app:" + files["app_password"] + "@postgres:5432/qali?sslmode=disable"
	}
	if urls.Migration == "" {
		urls.Migration = "postgres://qali_migrator:" + files["migrator_password"] + "@postgres:5432/qali?sslmode=disable"
	}
	files["database_url"] = urls.App
	files["migration_database_url"] = urls.Migration

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s already exists; remove the directory to regenerate", filepath.Join(dir, name))
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}
