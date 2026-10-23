package domain

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

// RecoveryCodeCount is the number of codes issued per set (ADR-0006).
const RecoveryCodeCount = 10

var ErrInvalidRecoveryCode = errors.New("identity: invalid recovery code")

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// RecoveryCode is shown once as Display. Lookup is stored in clear to find
// the row; Secret is stored only as an Argon2id hash.
type RecoveryCode struct {
	Lookup  string
	Secret  string
	Display string
}

// NewRecoveryCodes returns a set with distinct lookup IDs.
func NewRecoveryCodes() []RecoveryCode {
	codes := make([]RecoveryCode, 0, RecoveryCodeCount)
	seen := map[string]bool{}
	for len(codes) < RecoveryCodeCount {
		b := make([]byte, 10) // 80 bits -> 16 base32 characters
		_, _ = rand.Read(b)   // crypto/rand.Read never returns an error
		s := recoveryEncoding.EncodeToString(b)
		if seen[s[:4]] {
			continue
		}
		seen[s[:4]] = true
		codes = append(codes, RecoveryCode{
			Lookup:  s[:4],
			Secret:  s[4:],
			Display: s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16],
		})
	}
	return codes
}

// ParseRecoveryCode accepts any case, spaces, and hyphens.
func ParseRecoveryCode(input string) (lookup, secret string, err error) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(input)))
	if len(s) != 16 {
		return "", "", ErrInvalidRecoveryCode
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return "", "", ErrInvalidRecoveryCode
		}
	}
	return s[:4], s[4:], nil
}
