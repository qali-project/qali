// Package secret provides a value type for sensitive bytes that cannot be
// printed, logged, or serialized by accident. Code that needs the bytes calls
// Expose explicitly, which keeps every use visible in review.
package secret

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// Redacted replaces the value in every formatted, logged, or serialized form.
const Redacted = "[REDACTED]"

// Value holds sensitive bytes. The zero value is empty.
type Value struct {
	b []byte
}

// New returns a Value holding a copy of b.
func New(b []byte) Value {
	return Value{b: append([]byte(nil), b...)}
}

// Expose returns a copy of the sensitive bytes. Callers must not log, store,
// or return the result to clients.
func (v Value) Expose() []byte {
	return append([]byte(nil), v.b...)
}

// Len reports the length of the value in bytes.
func (v Value) Len() int { return len(v.b) }

// IsZero reports whether the value is empty.
func (v Value) IsZero() bool { return len(v.b) == 0 }

// Equal compares two values in constant time.
func (v Value) Equal(o Value) bool {
	return subtle.ConstantTimeCompare(v.b, o.b) == 1
}

func (Value) String() string   { return Redacted }
func (Value) GoString() string { return Redacted }

// Format redacts every fmt verb, including %x and %#v.
func (Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Value) LogValue() slog.Value         { return slog.StringValue(Redacted) }
