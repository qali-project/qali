// Package db is the only package that opens PostgreSQL connections. It owns
// migrations, the runtime pool, transactions, workspace scoping, and error
// mapping; feature repositories receive a scoped transaction from it.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/qali-project/qali/internal/platform/secret"
	"github.com/qali-project/qali/migrations"
)

// LatestMigration returns the highest embedded migration version.
func LatestMigration() int64 {
	var latest int64
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		panic(err) // embedded directory; cannot fail
	}
	for _, e := range entries {
		prefix, _, ok := strings.Cut(e.Name(), "_")
		if !ok {
			continue
		}
		if v, err := strconv.ParseInt(prefix, 10, 64); err == nil && v > latest {
			latest = v
		}
	}
	return latest
}

// provider opens a migration session for the migrator role. A PostgreSQL
// advisory lock serializes concurrent runs across replicas.
func provider(dsn secret.Value) (*goose.Provider, *sql.DB, error) {
	cfg, err := pgx.ParseConfig(string(dsn.Expose()))
	if err != nil {
		return nil, nil, fmt.Errorf("parse migration database URL: %w", redactParseError(err))
	}
	conn := stdlib.OpenDB(*cfg)
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return p, conn, nil
}

// Migrate applies all pending migrations and returns the versions it applied.
func Migrate(ctx context.Context, dsn secret.Value) ([]int64, error) {
	p, conn, err := provider(dsn)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	results, err := p.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	applied := make([]int64, 0, len(results))
	for _, r := range results {
		applied = append(applied, r.Source.Version)
	}
	return applied, nil
}

// Rollback migrates down to version (0 removes every migration).
func Rollback(ctx context.Context, dsn secret.Value, version int64) error {
	p, conn, err := provider(dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := p.DownTo(ctx, version); err != nil {
		return fmt.Errorf("roll back migrations: %w", err)
	}
	return nil
}

// redactParseError keeps connection-string parse errors from echoing the
// URL, which contains a password.
func redactParseError(err error) error {
	return fmt.Errorf("invalid connection string (%T)", err)
}
