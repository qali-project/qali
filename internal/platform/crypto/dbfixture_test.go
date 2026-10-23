package crypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/secret"
)

// dump models the rows a database backup would contain after issuing tokens,
// storing an integration secret, and hashing a password.
type dump struct {
	Tokens      []crypto.TokenRecord
	WrappedDEK  crypto.WrappedDEK
	Integration crypto.Sealed
	Password    string
}

// TestDatabaseShapedFixtureContainsNoUsableSecret proves MVP-02.AC-06: a dump
// without the separately mounted KEK and peppers reveals no plaintext secret
// and cannot be used to authenticate.
func TestDatabaseShapedFixtureContainsNoUsableSecret(t *testing.T) {
	kek, tokenPepper, passwordPepper := randomKey(t), randomKey(t), randomKey(t)
	kr := keyring(t, 1, map[uint32]secret.Value{1: kek})
	tk := tokens(t, 1, map[uint32]secret.Value{1: tokenPepper})
	pws := passwords(t, passwordPepper, testParams)

	var d dump
	var rawTokens []secret.Value
	for _, tt := range crypto.TokenTypes() {
		raw, rec, err := tk.Issue(tt)
		if err != nil {
			t.Fatal(err)
		}
		rawTokens = append(rawTokens, raw)
		d.Tokens = append(d.Tokens, rec)
	}
	providerSecret := secret.New([]byte("jira-api-token-7f3a9c"))
	dek, err := kr.NewDEK(ctx.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	d.WrappedDEK = dek
	if d.Integration, err = kr.Seal(dek, ctx, providerSecret); err != nil {
		t.Fatal(err)
	}
	password := secret.New([]byte("owner passphrase 2026"))
	if d.Password, err = pws.Hash(password); err != nil {
		t.Fatal(err)
	}

	serialized, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}

	// 1. No plaintext secret or key material appears in any encoding.
	sensitive := append([]secret.Value{providerSecret, password, kek, tokenPepper, passwordPepper}, rawTokens...)
	for _, s := range sensitive {
		b := s.Expose()
		for _, form := range [][]byte{b, []byte(base64.StdEncoding.EncodeToString(b)), []byte(base64.RawURLEncoding.EncodeToString(b))} {
			if bytes.Contains(serialized, form) {
				t.Fatal("database fixture contains a plaintext secret or key")
			}
		}
	}

	// 2. Without the original pepper, stored verifiers do not validate even the
	// genuine tokens, so the dump cannot be used to test guesses offline.
	attackerTokens := tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	for i, tt := range crypto.TokenTypes() {
		if err := attackerTokens.Verify(tt, rawTokens[i], d.Tokens[i]); !errors.Is(err, crypto.ErrInvalidToken) {
			t.Fatalf("%s verifier validated without the pepper", tt.Name)
		}
	}

	// 3. Values stored in the dump are not themselves usable bearer tokens.
	for i, tt := range crypto.TokenTypes() {
		for _, candidate := range []string{d.Tokens[i].LookupID, string(d.Tokens[i].Verifier), tt.Prefix + d.Tokens[i].LookupID} {
			if err := tk.Verify(tt, secret.New([]byte(candidate)), d.Tokens[i]); err == nil {
				t.Fatalf("a stored %s field authenticates as a token", tt.Name)
			}
		}
	}

	// 4. Without the KEK the integration secret cannot be decrypted, and without
	// the password pepper the password hash does not verify.
	attackerKeyring := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	if _, err := attackerKeyring.Open(d.WrappedDEK, ctx, d.Integration); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("integration secret opened without the KEK: %v", err)
	}
	if ok, _, _ := passwords(t, randomKey(t), testParams).Verify(password, d.Password); ok {
		t.Fatal("password hash verified without the pepper")
	}
}
