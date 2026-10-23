//go:build integration

package integration_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestRuntimeRoleHasDataAccessOnly proves MVP-03.AC-03.
func TestRuntimeRoleHasDataAccessOnly(t *testing.T) {
	d := migratedDatabase(t)
	app := connect(t, d.app)

	// Positive control: ordinary data access works.
	if _, err := app.Exec(t.Context(),
		`INSERT INTO jobs (id, queue, kind, status, max_attempts, run_at, created_at, updated_at)
		 VALUES (gen_random_uuid(), 'default', 'probe', 'pending', 1, now(), now(), now())`); err != nil {
		t.Fatalf("runtime role cannot insert: %v", err)
	}

	denied := map[string]string{
		"create table":       "CREATE TABLE qali.evil (id int)",
		"create public":      "CREATE TABLE public.evil (id int)",
		"create temp":        "CREATE TEMP TABLE evil (id int)",
		"create schema":      "CREATE SCHEMA evil",
		"create extension":   "CREATE EXTENSION pgcrypto",
		"create role":        "CREATE ROLE evil",
		"create function":    "CREATE FUNCTION qali.evil() RETURNS int LANGUAGE sql AS 'SELECT 1'",
		"alter table":        "ALTER TABLE jobs ADD COLUMN evil int",
		"drop table":         "DROP TABLE jobs",
		"truncate":           "TRUNCATE jobs",
		"disable rls helper": "SELECT qali.enable_workspace_isolation('qali.jobs')",
		"bypass rls":         "ALTER ROLE qali_app BYPASSRLS",
	}
	for name, stmt := range denied {
		t.Run(name, func(t *testing.T) {
			_, err := app.Exec(t.Context(), stmt)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || (pgErr.Code != "42501" && pgErr.Code != "42P01") {
				t.Fatalf("%q: err = %v, want permission denied", stmt, err)
			}
		})
	}
}

// A non-owner GRANT only warns in PostgreSQL, so assert the resulting state.
func TestRuntimeRoleCannotGrantAccess(t *testing.T) {
	d := migratedDatabase(t)
	if _, err := connect(t, d.app).Exec(t.Context(), "GRANT SELECT ON jobs TO PUBLIC"); err != nil {
		t.Logf("GRANT rejected: %v", err)
	}
	var publicGrants int
	err := connect(t, d.admin).QueryRow(t.Context(),
		`SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
		 WHERE c.oid = 'qali.jobs'::regclass AND a.grantee = 0`).Scan(&publicGrants)
	if err != nil {
		t.Fatal(err)
	}
	if publicGrants != 0 {
		t.Fatalf("PUBLIC gained %d privilege(s) on qali.jobs", publicGrants)
	}
}

func TestMigratorCannotEscalate(t *testing.T) {
	d := newDatabase(t)
	migrator := connect(t, d.migrator)
	for name, stmt := range map[string]string{
		"create role":      "CREATE ROLE evil",
		"create database":  "CREATE DATABASE evil",
		"create extension": "CREATE EXTENSION pgcrypto",
		"bypass rls":       "ALTER ROLE qali_migrator BYPASSRLS",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := migrator.Exec(t.Context(), stmt); err == nil {
				t.Fatalf("%q succeeded for the migration role", stmt)
			}
		})
	}
}
