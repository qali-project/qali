// Package domain holds identity rules: email and password policy, TOTP,
// recovery codes, session lifetime, and login throttling (ADR-0006,
// ADR-0012). It has no HTTP or SQL dependencies.
package domain

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrInvalidEmail = errors.New("identity: invalid email address")
	ErrWeakPassword = errors.New("identity: password does not meet the policy")
)

const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
	maxEmailLength    = 254
	maxLocalPart      = 64
)

// NormalizeEmail trims, NFKC-normalizes, and lower-cases an address and
// checks its basic shape. Deliverability is not checked (no email in MVP).
func NormalizeEmail(raw string) (string, error) {
	e := strings.ToLower(norm.NFKC.String(strings.TrimSpace(raw)))
	if len(e) == 0 || len(e) > maxEmailLength || strings.Count(e, "@") != 1 {
		return "", ErrInvalidEmail
	}
	local, host, _ := strings.Cut(e, "@")
	if local == "" || len(local) > maxLocalPart || host == "" || !strings.Contains(host, ".") ||
		strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return "", ErrInvalidEmail
	}
	for _, r := range e {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", ErrInvalidEmail
		}
	}
	return e, nil
}

// ValidatePassword applies ADR-0006: 12 to 256 characters after NFKC
// normalization, no control characters, and not the account's email or its
// local part. There are no composition rules.
func ValidatePassword(password, email string) error {
	p := norm.NFKC.String(password)
	n := utf8.RuneCountInString(p)
	if n < MinPasswordLength || n > MaxPasswordLength {
		return ErrWeakPassword
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return ErrWeakPassword
		}
	}
	lower := strings.ToLower(p)
	if normalized, err := NormalizeEmail(email); err == nil {
		local, _, _ := strings.Cut(normalized, "@")
		if lower == normalized || lower == local {
			return ErrWeakPassword
		}
	}
	return nil
}
