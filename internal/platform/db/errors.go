package db

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Stable error kinds. Their messages never contain SQL, table, constraint, or
// row data; the original error stays reachable with errors.As for logs.
var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("conflicts with existing data")
	ErrInvalid   = errors.New("violates a data rule")
	ErrForbidden = errors.New("not permitted")
	ErrRetry     = errors.New("transient conflict; retry")
	ErrReadOnly  = errors.New("write attempted in a read-only unit of work")
	ErrInternal  = errors.New("internal database error")
	// ErrUnaudited is returned when a write unit of work records no audit event.
	ErrUnaudited = errors.New("write without an audit event")
)

// Error carries a stable kind and the underlying cause.
type Error struct {
	kind  error
	cause error
}

func (e *Error) Error() string        { return "db: " + e.kind.Error() }
func (e *Error) Is(target error) bool { return target == e.kind }
func (e *Error) Unwrap() error        { return e.cause }

// MapError converts driver and PostgreSQL errors into stable kinds.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	var mapped *Error
	if errors.As(err, &mapped) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return &Error{kind: ErrNotFound, cause: err}
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return &Error{kind: kindOf(pgErr.Code), cause: err}
	}
	return &Error{kind: ErrInternal, cause: err}
}

func kindOf(code string) error {
	switch code {
	case "23505":
		return ErrConflict
	case "23503", "23514", "23502", "22P02", "22001", "22003", "22007", "22023":
		return ErrInvalid
	case "42501":
		return ErrForbidden
	case "40001", "40P01":
		return ErrRetry
	case "25006":
		return ErrReadOnly
	default:
		return ErrInternal
	}
}
