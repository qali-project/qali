// Package crypto implements the key-separated protections from ADR-0006:
// envelope encryption for recoverable secrets, keyed verifiers for bearer
// tokens, and peppered Argon2id for passwords. Key material only ever enters
// as secret.Value loaded from mounted files (internal/platform/config).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strconv"

	"github.com/qali-project/qali/internal/platform/secret"
)

// AlgorithmAES256GCM identifies AES-256-GCM with a 96-bit random nonce.
const AlgorithmAES256GCM = "A256GCM"

const keySize = 32

var (
	// ErrDecrypt is returned for any authentication failure. It deliberately
	// does not say which input was wrong.
	ErrDecrypt              = errors.New("crypto: decryption failed")
	ErrUnknownKeyVersion    = errors.New("crypto: unknown key version")
	ErrUnsupportedAlgorithm = errors.New("crypto: unsupported algorithm")
)

// Keyring holds key-encryption keys (KEKs) by version. New DEKs are wrapped
// with the current version; older versions stay usable for unwrapping until
// they are removed after rotation.
type Keyring struct {
	current uint32
	keys    map[uint32]secret.Value
}

// NewKeyring validates and returns a keyring.
func NewKeyring(current uint32, keys map[uint32]secret.Value) (*Keyring, error) {
	if err := validateKeys("KEK", current, keys); err != nil {
		return nil, err
	}
	copied := make(map[uint32]secret.Value, len(keys))
	maps.Copy(copied, keys)
	return &Keyring{current: current, keys: copied}, nil
}

func validateKeys(kind string, current uint32, keys map[uint32]secret.Value) error {
	if len(keys) == 0 {
		return fmt.Errorf("crypto: no %s configured", kind)
	}
	if _, ok := keys[current]; !ok || current == 0 {
		return fmt.Errorf("crypto: current %s version %d is not configured", kind, current)
	}
	seen := make([]secret.Value, 0, len(keys))
	for v, k := range keys {
		switch {
		case v == 0:
			return fmt.Errorf("crypto: %s version 0 is reserved", kind)
		case k.Len() != keySize:
			return fmt.Errorf("crypto: %s v%d must be %d bytes, got %d", kind, v, keySize, k.Len())
		case allZero(k):
			return fmt.Errorf("crypto: %s v%d is all zero bytes", kind, v)
		}
		for _, s := range seen {
			if s.Equal(k) {
				return fmt.Errorf("crypto: %s versions must use distinct keys", kind)
			}
		}
		seen = append(seen, k)
	}
	return nil
}

func allZero(v secret.Value) bool {
	b := v.Expose()
	defer clear(b)
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// Context is bound to a ciphertext as associated data. A ciphertext opens only
// with exactly the context it was sealed with.
type Context struct {
	WorkspaceID   string
	OwnerType     string
	OwnerID       string
	SecretType    string
	SchemaVersion uint32
}

func (c Context) validate() error {
	if c.WorkspaceID == "" || c.OwnerType == "" || c.OwnerID == "" || c.SecretType == "" || c.SchemaVersion == 0 {
		return errors.New("crypto: context requires workspace, owner type, owner, secret type, and schema version")
	}
	return nil
}

// WrappedDEK is a per-workspace data-encryption key wrapped by a KEK. It is
// safe to store in the database.
type WrappedDEK struct {
	ID         string
	KEKVersion uint32
	Nonce      []byte
	Ciphertext []byte
}

// Sealed is an encrypted secret. It is safe to store in the database.
type Sealed struct {
	Algorithm  string
	DEKID      string
	Nonce      []byte
	Ciphertext []byte
}

// NewDEK generates a data-encryption key for a workspace, wrapped with the
// current KEK.
func (k *Keyring) NewDEK(workspaceID string) (WrappedDEK, error) {
	if workspaceID == "" {
		return WrappedDEK{}, errors.New("crypto: workspace is required")
	}
	idBytes := make([]byte, 16)
	dek := make([]byte, keySize)
	defer clear(dek)
	if _, err := rand.Read(idBytes); err != nil {
		return WrappedDEK{}, err
	}
	if _, err := rand.Read(dek); err != nil {
		return WrappedDEK{}, err
	}
	return k.wrap(hex.EncodeToString(idBytes), workspaceID, dek)
}

// Rewrap re-encrypts a DEK under the current KEK without touching the secrets
// sealed with it.
func (k *Keyring) Rewrap(w WrappedDEK, workspaceID string) (WrappedDEK, error) {
	dek, err := k.unwrap(w, workspaceID)
	if err != nil {
		return WrappedDEK{}, err
	}
	defer clear(dek)
	return k.wrap(w.ID, workspaceID, dek)
}

func (k *Keyring) wrap(id, workspaceID string, dek []byte) (WrappedDEK, error) {
	nonce, ciphertext, err := sealGCM(k.keys[k.current], dek, dekAAD(workspaceID, id))
	if err != nil {
		return WrappedDEK{}, err
	}
	return WrappedDEK{ID: id, KEKVersion: k.current, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k *Keyring) unwrap(w WrappedDEK, workspaceID string) ([]byte, error) {
	kek, ok := k.keys[w.KEKVersion]
	if !ok {
		return nil, ErrUnknownKeyVersion
	}
	dek, err := openGCM(kek, w.Nonce, w.Ciphertext, dekAAD(workspaceID, w.ID))
	if err != nil {
		return nil, err
	}
	if len(dek) != keySize {
		clear(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}

// Seal encrypts plaintext with the workspace DEK, bound to ctx.
func (k *Keyring) Seal(w WrappedDEK, ctx Context, plaintext secret.Value) (Sealed, error) {
	if err := ctx.validate(); err != nil {
		return Sealed{}, err
	}
	dek, err := k.unwrap(w, ctx.WorkspaceID)
	if err != nil {
		return Sealed{}, err
	}
	defer clear(dek)
	pt := plaintext.Expose()
	defer clear(pt)
	nonce, ciphertext, err := sealGCM(secret.New(dek), pt, secretAAD(ctx, w.ID))
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Algorithm: AlgorithmAES256GCM, DEKID: w.ID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Open decrypts a sealed secret. Any mismatch in key, DEK, context, or data
// returns ErrDecrypt.
func (k *Keyring) Open(w WrappedDEK, ctx Context, s Sealed) (secret.Value, error) {
	if s.Algorithm != AlgorithmAES256GCM {
		return secret.Value{}, ErrUnsupportedAlgorithm
	}
	if err := ctx.validate(); err != nil {
		return secret.Value{}, err
	}
	if s.DEKID != w.ID {
		return secret.Value{}, ErrDecrypt
	}
	dek, err := k.unwrap(w, ctx.WorkspaceID)
	if err != nil {
		return secret.Value{}, err
	}
	defer clear(dek)
	pt, err := openGCM(secret.New(dek), s.Nonce, s.Ciphertext, secretAAD(ctx, w.ID))
	if err != nil {
		return secret.Value{}, err
	}
	defer clear(pt)
	return secret.New(pt), nil
}

func newGCM(key secret.Value) (cipher.AEAD, error) {
	b := key.Expose()
	defer clear(b)
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealGCM(key secret.Value, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func openGCM(key secret.Value, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func dekAAD(workspaceID, dekID string) []byte {
	return encodeFields("qali/dek/v1", workspaceID, dekID)
}

func secretAAD(c Context, dekID string) []byte {
	return encodeFields("qali/secret/v1", c.WorkspaceID, c.OwnerType, c.OwnerID, c.SecretType,
		strconv.FormatUint(uint64(c.SchemaVersion), 10), dekID)
}

// encodeFields length-prefixes every field so values cannot shift between
// fields and still produce the same associated data.
func encodeFields(fields ...string) []byte {
	var out []byte
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f))) //nolint:gosec // G115: field lengths are far below 4 GiB
		out = append(out, f...)
	}
	return out
}
