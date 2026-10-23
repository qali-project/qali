package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/qali-project/qali/internal/platform/secret"
)

// PasswordParams are Argon2id cost parameters.
type PasswordParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

var (
	// DefaultPasswordParams are the installation defaults from ADR-0006.
	DefaultPasswordParams = PasswordParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 1}
	// MinPasswordParams is the floor from ADR-0006; weaker settings are refused.
	MinPasswordParams = PasswordParams{MemoryKiB: 19 * 1024, Time: 2, Threads: 1}
	// maxPasswordParams bounds stored parameters so a tampered hash cannot
	// force huge memory or time costs.
	maxPasswordParams = PasswordParams{MemoryKiB: 1024 * 1024, Time: 64, Threads: 16}
)

// ErrInvalidHash is returned for stored hashes that are not well-formed
// Argon2id PHC strings within accepted bounds.
var ErrInvalidHash = errors.New("crypto: invalid password hash")

const (
	saltBytes = 16
	hashBytes = 32
	minPepper = 32
)

// Passwords hashes and verifies passwords. The KDF input is
// HMAC-SHA-256(pepper, NFKC(password)), so a database dump alone cannot be
// attacked offline.
type Passwords struct {
	pepper secret.Value
	params PasswordParams
}

// NewPasswords validates the pepper and parameters.
func NewPasswords(pepper secret.Value, params PasswordParams) (*Passwords, error) {
	if pepper.Len() < minPepper || allZero(pepper) {
		return nil, fmt.Errorf("crypto: password pepper must be at least %d non-zero bytes", minPepper)
	}
	if params.MemoryKiB < MinPasswordParams.MemoryKiB || params.Time < MinPasswordParams.Time || params.Threads < 1 ||
		params.MemoryKiB > maxPasswordParams.MemoryKiB || params.Time > maxPasswordParams.Time || params.Threads > maxPasswordParams.Threads {
		return nil, fmt.Errorf("crypto: Argon2id parameters %+v are outside the accepted range", params)
	}
	return &Passwords{pepper: pepper, params: params}, nil
}

// Hash returns a PHC-formatted Argon2id hash.
func (p *Passwords) Hash(password secret.Value) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := p.derive(password, salt, p.params)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		p.params.MemoryKiB, p.params.Time, p.params.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded, and whether a successful
// match should be rehashed with the current parameters.
func (p *Passwords) Verify(password secret.Value, encoded string) (ok, needsRehash bool, err error) {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got := p.derive(password, salt, params)
	defer clear(got)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = params.MemoryKiB < p.params.MemoryKiB || params.Time < p.params.Time || params.Threads != p.params.Threads
	return true, needsRehash, nil
}

func (p *Passwords) derive(password secret.Value, salt []byte, params PasswordParams) []byte {
	pw := password.Expose()
	defer clear(pw)
	normalized := norm.NFKC.Bytes(pw)
	defer clear(normalized)
	pepper := p.pepper.Expose()
	defer clear(pepper)
	mac := hmac.New(sha256.New, pepper)
	mac.Write(normalized)
	prehash := mac.Sum(nil)
	defer clear(prehash)
	return argon2.IDKey(prehash, salt, params.Time, params.MemoryKiB, params.Threads, hashBytes)
}

func decodeHash(encoded string) (PasswordParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	var params PasswordParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.MemoryKiB, &params.Time, &params.Threads); err != nil ||
		fmt.Sprintf("m=%d,t=%d,p=%d", params.MemoryKiB, params.Time, params.Threads) != parts[3] {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	if params.MemoryKiB < 8*uint32(params.Threads) || params.Time < 1 || params.Threads < 1 ||
		params.MemoryKiB > maxPasswordParams.MemoryKiB || params.Time > maxPasswordParams.Time || params.Threads > maxPasswordParams.Threads {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < saltBytes {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) != hashBytes {
		return PasswordParams{}, nil, nil, ErrInvalidHash
	}
	return params, salt, hash, nil
}
