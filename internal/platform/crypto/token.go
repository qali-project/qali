package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"maps"
	"strconv"
	"strings"

	"github.com/qali-project/qali/internal/platform/secret"
)

// TokenType is one bearer credential type from ADR-0006. Each type has its own
// prefix and its own derived verification key.
type TokenType struct {
	Name   string
	Prefix string
}

// Credential types issued in the MVP (docs/rbac/permission-catalog.json).
var (
	TokenSession       = TokenType{Name: "session", Prefix: "qali_sess_"}
	TokenPasswordReset = TokenType{Name: "password_reset", Prefix: "qali_reset_"}
	TokenInvitation    = TokenType{Name: "invitation", Prefix: "qali_inv_"}
	TokenSetup         = TokenType{Name: "setup", Prefix: "qali_setup_"}
	TokenCI            = TokenType{Name: "ci", Prefix: "qali_ci_"}
	TokenMCP           = TokenType{Name: "mcp", Prefix: "qali_mcp_"}
)

// TokenTypes lists every credential type the MVP issues.
func TokenTypes() []TokenType {
	return []TokenType{TokenSession, TokenPasswordReset, TokenInvitation, TokenSetup, TokenCI, TokenMCP}
}

// ErrInvalidToken is returned for every verification failure.
var ErrInvalidToken = errors.New("crypto: invalid token")

const (
	lookupBytes = 10 // 80 bits -> 16 base32 characters
	lookupLen   = 16
	secretBytes = 32 // 256 bits -> 43 base64url characters
	secretLen   = 43
)

var (
	lookupEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	secretEncoding = base64.RawURLEncoding.Strict()
)

// TokenRecord is what the database stores for an issued token: a non-secret
// lookup ID and a keyed verifier. Neither allows recreating or checking a
// token without the pepper.
type TokenRecord struct {
	Type       string
	LookupID   string
	Verifier   []byte
	KeyVersion uint32
}

// Tokens issues and verifies bearer tokens with a versioned pepper.
type Tokens struct {
	current uint32
	peppers map[uint32]secret.Value
}

// NewTokens validates the peppers and returns a token service.
func NewTokens(current uint32, peppers map[uint32]secret.Value) (*Tokens, error) {
	if err := validateKeys("token pepper", current, peppers); err != nil {
		return nil, err
	}
	copied := make(map[uint32]secret.Value, len(peppers))
	maps.Copy(copied, peppers)
	return &Tokens{current: current, peppers: copied}, nil
}

// Issue creates a new token. The raw value is shown to its holder once and
// never stored.
func (t *Tokens) Issue(tt TokenType) (secret.Value, TokenRecord, error) {
	lookup := make([]byte, lookupBytes)
	sec := make([]byte, secretBytes)
	defer clear(sec)
	if _, err := rand.Read(lookup); err != nil {
		return secret.Value{}, TokenRecord{}, err
	}
	if _, err := rand.Read(sec); err != nil {
		return secret.Value{}, TokenRecord{}, err
	}
	lookupID := lookupEncoding.EncodeToString(lookup)
	raw := []byte(tt.Prefix + lookupID + "_" + secretEncoding.EncodeToString(sec))
	defer clear(raw)
	verifier, err := t.verifier(tt, t.current, raw)
	if err != nil {
		return secret.Value{}, TokenRecord{}, err
	}
	rec := TokenRecord{Type: tt.Name, LookupID: lookupID, Verifier: verifier, KeyVersion: t.current}
	return secret.New(raw), rec, nil
}

// LookupID extracts the non-secret lookup ID used to find the stored record.
func LookupID(tt TokenType, raw secret.Value) (string, error) {
	b := raw.Expose()
	defer clear(b)
	return parse(tt, b)
}

func parse(tt TokenType, raw []byte) (string, error) {
	s := string(raw)
	if !strings.HasPrefix(s, tt.Prefix) {
		return "", ErrInvalidToken
	}
	rest := s[len(tt.Prefix):]
	if len(rest) != lookupLen+1+secretLen || rest[lookupLen] != '_' {
		return "", ErrInvalidToken
	}
	lookupID, sec := rest[:lookupLen], rest[lookupLen+1:]
	if b, err := lookupEncoding.DecodeString(lookupID); err != nil || len(b) != lookupBytes {
		return "", ErrInvalidToken
	}
	b, err := secretEncoding.DecodeString(sec)
	if err != nil || len(b) != secretBytes {
		return "", ErrInvalidToken
	}
	clear(b)
	return lookupID, nil
}

// Verify checks raw against its stored record in constant time.
func (t *Tokens) Verify(tt TokenType, raw secret.Value, rec TokenRecord) error {
	b := raw.Expose()
	defer clear(b)
	if rec.Type != tt.Name {
		return ErrInvalidToken
	}
	lookupID, err := parse(tt, b)
	if err != nil || lookupID != rec.LookupID {
		return ErrInvalidToken
	}
	want, err := t.verifier(tt, rec.KeyVersion, b)
	if err != nil {
		return ErrInvalidToken
	}
	if !hmac.Equal(want, rec.Verifier) {
		return ErrInvalidToken
	}
	return nil
}

// Digest returns a keyed SHA-256 MAC of data for a purpose, using the
// current pepper. It serves values that must be compared but never stored in
// clear and are not bearer tokens on their own, such as CSRF tokens and
// throttle keys. Rotating the pepper invalidates existing digests.
func (t *Tokens) Digest(purpose string, data []byte) []byte {
	p := t.peppers[t.current].Expose()
	defer clear(p)
	key, err := hkdf.Key(sha256.New, p, nil, "qali/digest/"+purpose+"/v"+strconv.FormatUint(uint64(t.current), 10), 32)
	if err != nil {
		panic(err) // unreachable: SHA-256 supports 32-byte HKDF output
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (t *Tokens) verifier(tt TokenType, version uint32, raw []byte) ([]byte, error) {
	pepper, ok := t.peppers[version]
	if !ok {
		return nil, ErrUnknownKeyVersion
	}
	p := pepper.Expose()
	defer clear(p)
	key, err := hkdf.Key(sha256.New, p, nil, "qali/token/"+tt.Name+"/v"+strconv.FormatUint(uint64(version), 10), 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return mac.Sum(nil), nil
}
