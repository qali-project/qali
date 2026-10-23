// Package pagination implements the ADR-0003 cursor rules: keyset pages
// over UUID keys, limits of 1-200 (default 50), and opaque cursors bound to
// the listing and the principal with a keyed MAC, so a tampered or
// transplanted cursor is rejected.
package pagination

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
	macLen       = 16
)

var (
	// ErrInvalidCursor rejects tampered, foreign, or malformed cursors.
	ErrInvalidCursor = errors.New("pagination: invalid cursor")
	// ErrInvalidLimit rejects limits outside 1-200.
	ErrInvalidLimit = errors.New("pagination: limit must be between 1 and 200")
)

// Codec signs and verifies cursors. mac is a keyed digest such as
// crypto.Tokens.Digest.
type Codec struct {
	mac func(purpose string, data []byte) []byte
}

// NewCodec returns a codec over the keyed digest.
func NewCodec(mac func(purpose string, data []byte) []byte) Codec { return Codec{mac: mac} }

func (c Codec) tag(binding string, key []byte) []byte {
	return c.mac("cursor", append([]byte(binding+"\x00"), key...))[:macLen]
}

// Encode returns a cursor that resumes after key for this binding (listing
// plus principal).
func (c Codec) Encode(binding string, after uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString(append(after[:], c.tag(binding, after[:])...))
}

// Decode returns the key to resume after; an empty cursor is uuid.Nil.
func (c Codec) Decode(binding, cursor string) (uuid.UUID, error) {
	if cursor == "" {
		return uuid.Nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) != 16+macLen {
		return uuid.Nil, ErrInvalidCursor
	}
	if !hmac.Equal(raw[16:], c.tag(binding, raw[:16])) {
		return uuid.Nil, ErrInvalidCursor
	}
	return uuid.UUID(raw[:16]), nil
}

// Limit validates an optional page size.
func Limit(n *int) (int, error) {
	if n == nil {
		return DefaultLimit, nil
	}
	if *n < 1 || *n > MaxLimit {
		return 0, ErrInvalidLimit
	}
	return *n, nil
}

// Page trims rows fetched with limit+1 to limit and returns the next cursor,
// or nil on the last page.
func Page[T any](c Codec, binding string, rows []T, limit int, key func(T) uuid.UUID) ([]T, *string) {
	if len(rows) <= limit {
		return rows, nil
	}
	rows = rows[:limit]
	next := c.Encode(binding, key(rows[limit-1]))
	return rows, &next
}
