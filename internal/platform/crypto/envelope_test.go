package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/secret"
)

func randomKey(t *testing.T) secret.Value {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return secret.New(b)
}

func keyring(t *testing.T, current uint32, keys map[uint32]secret.Value) *crypto.Keyring {
	t.Helper()
	kr, err := crypto.NewKeyring(current, keys)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

var ctx = crypto.Context{
	WorkspaceID:   "0199f0c2-1111-7000-8000-000000000001",
	OwnerType:     "integration",
	OwnerID:       "0199f0c2-2222-7000-8000-000000000002",
	SecretType:    "jira_api_token",
	SchemaVersion: 1,
}

const plaintext = "provider-api-token-value"

func sealOne(t *testing.T, kr *crypto.Keyring) (crypto.WrappedDEK, crypto.Sealed) {
	t.Helper()
	dek, err := kr.NewDEK(ctx.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := kr.Seal(dek, ctx, secret.New([]byte(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	return dek, sealed
}

func TestEnvelopeRoundTrip(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	dek, sealed := sealOne(t, kr)
	got, err := kr.Open(dek, ctx, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Expose()) != plaintext {
		t.Fatalf("round trip returned %q", got.Expose())
	}
	if sealed.Algorithm != crypto.AlgorithmAES256GCM || dek.KEKVersion != 1 {
		t.Fatalf("metadata = %q kek v%d", sealed.Algorithm, dek.KEKVersion)
	}
}

func TestSealedDataContainsNoPlaintextOrKeys(t *testing.T) {
	key := randomKey(t)
	kr := keyring(t, 1, map[uint32]secret.Value{1: key})
	dek, sealed := sealOne(t, kr)
	stored := bytes.Join([][]byte{sealed.Ciphertext, sealed.Nonce, dek.Ciphertext, dek.Nonce, []byte(dek.ID)}, nil)
	if bytes.Contains(stored, []byte(plaintext)) || bytes.Contains(stored, key.Expose()) {
		t.Fatal("stored envelope contains plaintext or KEK material")
	}
}

func TestSealingTwiceUsesFreshNonces(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	dek, a := sealOne(t, kr)
	b, err := kr.Seal(dek, ctx, secret.New([]byte(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals of the same plaintext must differ")
	}
}

func TestWrongKEKFails(t *testing.T) {
	dek, sealed := sealOne(t, keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)}))
	other := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	if _, err := other.Open(dek, ctx, sealed); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestWrongContextFails(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	dek, sealed := sealOne(t, kr)
	mutations := map[string]func(*crypto.Context){
		"workspace":      func(c *crypto.Context) { c.WorkspaceID = "0199f0c2-1111-7000-8000-000000000009" },
		"owner type":     func(c *crypto.Context) { c.OwnerType = "webhook" },
		"owner":          func(c *crypto.Context) { c.OwnerID = "0199f0c2-2222-7000-8000-000000000009" },
		"secret type":    func(c *crypto.Context) { c.SecretType = "oidc_client_secret" },
		"schema version": func(c *crypto.Context) { c.SchemaVersion = 2 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			wrong := ctx
			mutate(&wrong)
			if _, err := kr.Open(dek, wrong, sealed); !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("err = %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestContextFieldsCannotBeShiftedBetweenEachOther(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	a := ctx
	a.OwnerType, a.OwnerID = "integration|x", "y"
	b := ctx
	b.OwnerType, b.OwnerID = "integration", "x|y"
	dek, err := kr.NewDEK(ctx.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := kr.Seal(dek, a, secret.New([]byte(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Open(dek, b, sealed); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("ambiguous associated data: err = %v", err)
	}
}

func TestTamperingFails(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	cases := map[string]func(*crypto.WrappedDEK, *crypto.Sealed){
		"ciphertext":     func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.Ciphertext[0] ^= 1 },
		"tag":            func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 1 },
		"nonce":          func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.Nonce[0] ^= 1 },
		"truncated":      func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.Ciphertext = s.Ciphertext[:4] },
		"wrapped DEK":    func(d *crypto.WrappedDEK, _ *crypto.Sealed) { d.Ciphertext[0] ^= 1 },
		"wrapped nonce":  func(d *crypto.WrappedDEK, _ *crypto.Sealed) { d.Nonce[0] ^= 1 },
		"DEK ID swapped": func(d *crypto.WrappedDEK, s *crypto.Sealed) { d.ID = "another-dek"; s.DEKID = "another-dek" },
		"sealed DEK ID":  func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.DEKID = "another-dek" },
		"short nonce":    func(_ *crypto.WrappedDEK, s *crypto.Sealed) { s.Nonce = s.Nonce[:8] },
		"empty wrapped":  func(d *crypto.WrappedDEK, _ *crypto.Sealed) { d.Ciphertext = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			dek, sealed := sealOne(t, kr)
			tamper(&dek, &sealed)
			if _, err := kr.Open(dek, ctx, sealed); err == nil {
				t.Fatal("tampered envelope opened successfully")
			}
		})
	}
}

func TestUnknownVersionsAndAlgorithmsFail(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	dek, sealed := sealOne(t, kr)

	unknownKEK := dek
	unknownKEK.KEKVersion = 7
	if _, err := kr.Open(unknownKEK, ctx, sealed); !errors.Is(err, crypto.ErrUnknownKeyVersion) {
		t.Fatalf("err = %v, want ErrUnknownKeyVersion", err)
	}

	unknownAlg := sealed
	unknownAlg.Algorithm = "A128CBC"
	if _, err := kr.Open(dek, ctx, unknownAlg); !errors.Is(err, crypto.ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestKEKRotationRewrapsWithoutReencrypting(t *testing.T) {
	v1, v2 := randomKey(t), randomKey(t)
	old := keyring(t, 1, map[uint32]secret.Value{1: v1})
	dek, sealed := sealOne(t, old)

	rotated := keyring(t, 2, map[uint32]secret.Value{1: v1, 2: v2})
	if _, err := rotated.Open(dek, ctx, sealed); err != nil {
		t.Fatalf("data under the previous KEK must stay readable during rotation: %v", err)
	}
	rewrapped, err := rotated.Rewrap(dek, ctx.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if rewrapped.KEKVersion != 2 || rewrapped.ID != dek.ID {
		t.Fatalf("rewrap produced KEK v%d id %q", rewrapped.KEKVersion, rewrapped.ID)
	}

	retired := keyring(t, 2, map[uint32]secret.Value{2: v2})
	got, err := retired.Open(rewrapped, ctx, sealed)
	if err != nil || string(got.Expose()) != plaintext {
		t.Fatalf("open after rewrap: %v", err)
	}
	if _, err := retired.Open(dek, ctx, sealed); !errors.Is(err, crypto.ErrUnknownKeyVersion) {
		t.Fatalf("retired KEK version must be unknown, err = %v", err)
	}
}

func TestKeyringValidation(t *testing.T) {
	cases := map[string]struct {
		current uint32
		keys    map[uint32]secret.Value
	}{
		"no keys":          {1, map[uint32]secret.Value{}},
		"missing current":  {2, map[uint32]secret.Value{1: randomKey(t)}},
		"short key":        {1, map[uint32]secret.Value{1: secret.New(make([]byte, 16))}},
		"long key":         {1, map[uint32]secret.Value{1: secret.New(make([]byte, 64))}},
		"version zero":     {0, map[uint32]secret.Value{0: randomKey(t)}},
		"all-zero key":     {1, map[uint32]secret.Value{1: secret.New(make([]byte, 32))}},
		"duplicate values": {2, func() map[uint32]secret.Value { k := randomKey(t); return map[uint32]secret.Value{1: k, 2: k} }()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := crypto.NewKeyring(tc.current, tc.keys); err == nil {
				t.Fatal("invalid keyring accepted")
			}
		})
	}
}

func TestIncompleteContextIsRejected(t *testing.T) {
	kr := keyring(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	dek, err := kr.NewDEK(ctx.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	incomplete := ctx
	incomplete.SecretType = ""
	if _, err := kr.Seal(dek, incomplete, secret.New([]byte(plaintext))); err == nil {
		t.Fatal("seal accepted a context without a secret type")
	}
	if _, err := kr.NewDEK(""); err == nil {
		t.Fatal("NewDEK accepted an empty workspace")
	}
}
