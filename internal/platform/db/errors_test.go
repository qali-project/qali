package db_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qali-project/qali/internal/platform/db"
)

func TestMapErrorKinds(t *testing.T) {
	pg := func(code string) error {
		return &pgconn.PgError{Code: code, Message: "duplicate key value violates unique constraint \"jobs_kind_idempotency_key_key\"", TableName: "jobs", Detail: "Key (kind)=(secret-value) already exists."}
	}
	cases := []struct {
		in   error
		want error
	}{
		{pgx.ErrNoRows, db.ErrNotFound},
		{fmt.Errorf("wrapped: %w", pgx.ErrNoRows), db.ErrNotFound},
		{pg("23505"), db.ErrConflict},
		{pg("23503"), db.ErrInvalid},
		{pg("23514"), db.ErrInvalid},
		{pg("23502"), db.ErrInvalid},
		{pg("22P02"), db.ErrInvalid},
		{pg("22001"), db.ErrInvalid},
		{pg("42501"), db.ErrForbidden},
		{pg("40001"), db.ErrRetry},
		{pg("40P01"), db.ErrRetry},
		{pg("25006"), db.ErrReadOnly},
		{pg("XX000"), db.ErrInternal},
		{errors.New("connection reset"), db.ErrInternal},
	}
	for _, tc := range cases {
		got := db.MapError(tc.in)
		if !errors.Is(got, tc.want) {
			t.Fatalf("MapError(%v) = %v, want %v", tc.in, got, tc.want)
		}
		msg := got.Error()
		for _, leak := range []string{"jobs", "secret-value", "duplicate key", "constraint"} {
			if strings.Contains(msg, leak) {
				t.Fatalf("mapped error %q leaks %q", msg, leak)
			}
		}
	}
	if db.MapError(nil) != nil {
		t.Fatal("MapError(nil) must be nil")
	}
}

func TestMappedErrorKeepsCauseForLogs(t *testing.T) {
	cause := &pgconn.PgError{Code: "23505"}
	var pgErr *pgconn.PgError
	if !errors.As(db.MapError(cause), &pgErr) {
		t.Fatal("the original error must stay reachable with errors.As for internal logs")
	}
}

func TestMapErrorIsIdempotent(t *testing.T) {
	once := db.MapError(&pgconn.PgError{Code: "23505"})
	if twice := db.MapError(once); !errors.Is(twice, db.ErrConflict) {
		t.Fatalf("mapping twice = %v", twice)
	}
}
