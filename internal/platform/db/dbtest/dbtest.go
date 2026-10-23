// Package dbtest starts disposable PostgreSQL servers prepared exactly like a
// production one: the bootstrap script creates the roles and each database
// gets the production per-database setup. Integration tests and the E2E
// environment use it; production code must not.
package dbtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/qali-project/qali/internal/platform/secret"
)

// Images are the supported PostgreSQL majors (ADR-0002), pinned by digest.
var Images = map[string]string{
	"17": "postgres:17.11-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24",
	"18": "postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873",
}

// DefaultMajor is used when no major is requested.
const DefaultMajor = "18"

// Cluster is a running PostgreSQL server with the Qali roles.
type Cluster struct {
	Major                      string
	host, port                 string
	adminPW, migratorPW, appPW string
	repoRoot                   string
	container                  *postgres.PostgresContainer
}

// Database is a fresh database prepared like a production one.
type Database struct {
	Name                 string
	Admin, Migrator, App secret.Value
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b)
}

// Start runs a PostgreSQL server for major. repoRoot locates
// deploy/postgres, whose bootstrap files are used unchanged.
func Start(ctx context.Context, major, repoRoot string) (*Cluster, error) {
	if major == "" {
		major = DefaultMajor
	}
	image, ok := Images[major]
	if !ok {
		return nil, fmt.Errorf("PostgreSQL %q is not a supported major (ADR-0002)", major)
	}
	c := &Cluster{Major: major, adminPW: randomHex(24), migratorPW: randomHex(24), appPW: randomHex(24), repoRoot: repoRoot}

	secrets, err := os.MkdirTemp("", "qali-pg-secrets-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(secrets) }()
	for name, value := range map[string]string{"migrator_password": c.migratorPW, "app_password": c.appPW} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte(value), 0o600); err != nil {
			return nil, err
		}
	}

	ctr, err := postgres.Run(ctx, image,
		postgres.WithDatabase("qali"),
		postgres.WithUsername("qali_admin"),
		postgres.WithPassword(c.adminPW),
		postgres.WithInitScripts(filepath.Join(repoRoot, "deploy/postgres/initdb/10-qali-roles.sh")),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{HostFilePath: filepath.Join(secrets, "migrator_password"), ContainerFilePath: "/run/secrets/migrator_password", FileMode: 0o444},
			testcontainers.ContainerFile{HostFilePath: filepath.Join(secrets, "app_password"), ContainerFilePath: "/run/secrets/app_password", FileMode: 0o444},
			testcontainers.ContainerFile{HostFilePath: filepath.Join(repoRoot, "deploy/postgres/sql/qali-database.sql"), ContainerFilePath: "/opt/qali/qali-database.sql", FileMode: 0o444},
		),
		postgres.BasicWaitStrategies(),
	)
	c.container = ctr
	if err != nil {
		_ = c.Close(ctx)
		return nil, fmt.Errorf("start PostgreSQL %s: %w", major, err)
	}
	if c.host, err = ctr.Host(ctx); err != nil {
		_ = c.Close(ctx)
		return nil, err
	}
	mapped, err := ctr.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = c.Close(ctx)
		return nil, err
	}
	c.port = mapped.Port()
	return c, nil
}

// Close removes the container.
func (c *Cluster) Close(_ context.Context) error {
	if c.container == nil {
		return nil
	}
	return testcontainers.TerminateContainer(c.container)
}

// DSN returns a connection string for the given role and database.
func (c *Cluster) DSN(user, password, database string) secret.Value {
	return secret.New(fmt.Appendf(nil, "postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, c.host, c.port, database))
}

// AdminDSN connects as the superuser to the bootstrap database.
func (c *Cluster) AdminDSN() secret.Value { return c.DSN("qali_admin", c.adminPW, "qali") }

// NewDatabase creates a database and applies the production per-database
// setup. It does not run migrations.
func (c *Cluster) NewDatabase(ctx context.Context) (Database, error) {
	name := "t_" + randomHex(8)
	if err := exec(ctx, c.AdminDSN(), "CREATE DATABASE "+name); err != nil {
		return Database{}, err
	}
	setup, err := os.ReadFile(filepath.Join(c.repoRoot, "deploy/postgres/sql/qali-database.sql"))
	if err != nil {
		return Database{}, err
	}
	admin := c.DSN("qali_admin", c.adminPW, name)
	if err := exec(ctx, admin, string(setup)); err != nil {
		return Database{}, fmt.Errorf("database setup: %w", err)
	}
	return Database{
		Name:     name,
		Admin:    admin,
		Migrator: c.DSN("qali_migrator", c.migratorPW, name),
		App:      c.DSN("qali_app", c.appPW, name),
	}, nil
}

// DropDatabase removes a database created by NewDatabase.
func (c *Cluster) DropDatabase(ctx context.Context, name string) error {
	return exec(ctx, c.AdminDSN(), "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
}

func exec(ctx context.Context, dsn secret.Value, sql string) error {
	conn, err := pgx.Connect(ctx, string(dsn.Expose()))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	_, err = conn.Exec(ctx, sql)
	return err
}
