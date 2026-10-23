package crypto_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/secret"
)

// Tests use the minimum accepted cost to stay fast; production defaults are
// covered by TestDefaultParamsMatchADR.
var testParams = crypto.MinPasswordParams

func passwords(t *testing.T, pepper secret.Value, p crypto.PasswordParams) *crypto.Passwords {
	t.Helper()
	pw, err := crypto.NewPasswords(pepper, p)
	if err != nil {
		t.Fatal(err)
	}
	return pw
}

func pw(s string) secret.Value { return secret.New([]byte(s)) }

func TestDefaultParamsMatchADR(t *testing.T) {
	d := crypto.DefaultPasswordParams
	if d.MemoryKiB != 64*1024 || d.Time != 3 || d.Threads != 1 {
		t.Fatalf("defaults = %+v, want m=64MiB t=3 p=1 (ADR-0006)", d)
	}
	m := crypto.MinPasswordParams
	if m.MemoryKiB != 19*1024 || m.Time != 2 {
		t.Fatalf("minimum = %+v, want m=19MiB t=2 (ADR-0006)", m)
	}
}

func TestHashVerifies(t *testing.T) {
	p := passwords(t, randomKey(t), testParams)
	hash, err := p.Hash(pw("a long passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash is not a PHC argon2id string: %q", hash)
	}
	if strings.Contains(hash, "a long passphrase") {
		t.Fatal("hash contains the password")
	}
	ok, rehash, err := p.Verify(pw("a long passphrase"), hash)
	if err != nil || !ok || rehash {
		t.Fatalf("Verify = %v, %v, %v", ok, rehash, err)
	}
}

func TestWrongPasswordOrPepperFails(t *testing.T) {
	pepper := randomKey(t)
	p := passwords(t, pepper, testParams)
	hash, err := p.Hash(pw("a long passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := p.Verify(pw("a long passphrasE"), hash); ok || err != nil {
		t.Fatalf("wrong password: ok=%v err=%v", ok, err)
	}
	other := passwords(t, randomKey(t), testParams)
	if ok, _, err := other.Verify(pw("a long passphrase"), hash); ok || err != nil {
		t.Fatalf("database hash must not verify without the original pepper: ok=%v err=%v", ok, err)
	}
}

func TestSaltsAreUnique(t *testing.T) {
	p := passwords(t, randomKey(t), testParams)
	a, _ := p.Hash(pw("same password"))
	b, _ := p.Hash(pw("same password"))
	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestWeakerStoredParametersRequestRehash(t *testing.T) {
	pepper := randomKey(t)
	weak := passwords(t, pepper, testParams)
	hash, err := weak.Hash(pw("a long passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	stronger := testParams
	stronger.Time++
	ok, rehash, err := passwords(t, pepper, stronger).Verify(pw("a long passphrase"), hash)
	if err != nil || !ok || !rehash {
		t.Fatalf("Verify = ok %v, rehash %v, err %v; want ok and rehash", ok, rehash, err)
	}
	if ok, rehash, _ := passwords(t, pepper, stronger).Verify(pw("wrong passphrase"), hash); ok || rehash {
		t.Fatal("a failed verification must not request a rehash")
	}
}

func TestUnicodeNormalization(t *testing.T) {
	p := passwords(t, randomKey(t), testParams)
	composed := "Åsa-pässword"     // precomposed characters
	decomposed := "Åsa-pässword" // combining marks
	hash, err := p.Hash(pw(composed))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := p.Verify(pw(decomposed), hash); !ok || err != nil {
		t.Fatalf("NFKC-equivalent password rejected: ok=%v err=%v", ok, err)
	}
}

func TestMalformedHashesAreErrors(t *testing.T) {
	p := passwords(t, randomKey(t), testParams)
	good, _ := p.Hash(pw("a long passphrase"))
	parts := strings.Split(good, "$")
	for name, h := range map[string]string{
		"empty":         "",
		"bcrypt":        "$2a$10$abcdefghijklmnopqrstuuJ5Z6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6Q6",
		"argon2i":       strings.Replace(good, "argon2id", "argon2i", 1),
		"version":       strings.Replace(good, "v=19", "v=16", 1),
		"params":        strings.Join([]string{"", parts[1], parts[2], "m=x,t=2,p=1", parts[4], parts[5]}, "$"),
		"zero memory":   strings.Join([]string{"", parts[1], parts[2], "m=0,t=2,p=1", parts[4], parts[5]}, "$"),
		"huge memory":   strings.Join([]string{"", parts[1], parts[2], "m=4294967295,t=2,p=1", parts[4], parts[5]}, "$"),
		"salt encoding": strings.Join([]string{"", parts[1], parts[2], parts[3], "!!!", parts[5]}, "$"),
		"short hash":    strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], "AAAA"}, "$"),
		"missing part":  strings.Join(parts[:5], "$"),
	} {
		t.Run(name, func(t *testing.T) {
			ok, _, err := p.Verify(pw("a long passphrase"), h)
			if ok || !errors.Is(err, crypto.ErrInvalidHash) {
				t.Fatalf("ok=%v err=%v, want ErrInvalidHash", ok, err)
			}
		})
	}
}

func TestParamsAndPepperValidation(t *testing.T) {
	below := testParams
	below.MemoryKiB--
	if _, err := crypto.NewPasswords(randomKey(t), below); err == nil {
		t.Fatal("parameters below the ADR-0006 floor accepted")
	}
	if _, err := crypto.NewPasswords(secret.New([]byte("short")), testParams); err == nil {
		t.Fatal("short pepper accepted")
	}
}
