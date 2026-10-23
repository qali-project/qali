package crypto_test

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/crypto"
	"github.com/qali-project/qali/internal/platform/secret"
)

func tokens(t *testing.T, current uint32, peppers map[uint32]secret.Value) *crypto.Tokens {
	t.Helper()
	tk, err := crypto.NewTokens(current, peppers)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

// ADR-0006 format: <prefix><16 base32 lookup chars>_<43 base64url secret chars>.
var ciFormat = regexp.MustCompile(`^qali_ci_[a-z2-7]{16}_[A-Za-z0-9_-]{43}$`)

func TestIssuedTokenMatchesFormatAndVerifies(t *testing.T) {
	tk := tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	raw, rec, err := tk.Issue(crypto.TokenCI)
	if err != nil {
		t.Fatal(err)
	}
	if !ciFormat.Match(raw.Expose()) {
		t.Fatalf("token does not match the ADR-0006 format")
	}
	if rec.Type != "ci" || rec.KeyVersion != 1 || len(rec.LookupID) != 16 || len(rec.Verifier) != 32 {
		t.Fatalf("record = %+v", rec)
	}
	if !strings.HasPrefix(string(raw.Expose()), "qali_ci_"+rec.LookupID+"_") {
		t.Fatal("lookup ID in record does not match the token")
	}
	if err := tk.Verify(crypto.TokenCI, raw, rec); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLookupIDIsParsedWithoutTheSecret(t *testing.T) {
	tk := tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	raw, rec, err := tk.Issue(crypto.TokenMCP)
	if err != nil {
		t.Fatal(err)
	}
	id, err := crypto.LookupID(crypto.TokenMCP, raw)
	if err != nil || id != rec.LookupID {
		t.Fatalf("LookupID = %q, %v; want %q", id, err, rec.LookupID)
	}
}

func TestTokensAreUnique(t *testing.T) {
	tk := tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)})
	seen := map[string]bool{}
	for range 200 {
		raw, rec, err := tk.Issue(crypto.TokenCI)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(raw.Expose())] || seen[rec.LookupID] {
			t.Fatal("duplicate token or lookup ID")
		}
		seen[string(raw.Expose())], seen[rec.LookupID] = true, true
	}
}

func TestVerificationFailures(t *testing.T) {
	pepper := randomKey(t)
	tk := tokens(t, 1, map[uint32]secret.Value{1: pepper})
	raw, rec, err := tk.Issue(crypto.TokenCI)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw.Expose())
	flip := func(i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}

	cases := map[string]struct {
		tt  crypto.TokenType
		raw string
		rec crypto.TokenRecord
		tk  *crypto.Tokens
	}{
		"tampered secret":    {crypto.TokenCI, flip(len(s) - 1), rec, tk},
		"other pepper":       {crypto.TokenCI, s, rec, tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)})},
		"other type":         {crypto.TokenMCP, "qali_mcp_" + strings.TrimPrefix(s, "qali_ci_"), withType(rec, "mcp"), tk},
		"record of type":     {crypto.TokenCI, s, withType(rec, "mcp"), tk},
		"lookup mismatch":    {crypto.TokenCI, s, withLookup(rec, "aaaaaaaaaaaaaaaa"), tk},
		"unknown version":    {crypto.TokenCI, s, withVersion(rec, 9), tk},
		"missing prefix":     {crypto.TokenCI, strings.TrimPrefix(s, "qali_ci_"), rec, tk},
		"truncated":          {crypto.TokenCI, s[:len(s)-1], rec, tk},
		"extra":              {crypto.TokenCI, s + "A", rec, tk},
		"bad lookup charset": {crypto.TokenCI, "qali_ci_" + strings.ToUpper(rec.LookupID) + s[len("qali_ci_")+16:], rec, tk},
		"empty":              {crypto.TokenCI, "", rec, tk},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.tk.Verify(tc.tt, secret.New([]byte(tc.raw)), tc.rec)
			if !errors.Is(err, crypto.ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestPepperRotationKeepsOldTokensValid(t *testing.T) {
	v1, v2 := randomKey(t), randomKey(t)
	raw, rec, err := tokens(t, 1, map[uint32]secret.Value{1: v1}).Issue(crypto.TokenCI)
	if err != nil {
		t.Fatal(err)
	}
	rotated := tokens(t, 2, map[uint32]secret.Value{1: v1, 2: v2})
	if err := rotated.Verify(crypto.TokenCI, raw, rec); err != nil {
		t.Fatalf("token issued under v1 must verify after rotation: %v", err)
	}
	_, rec2, err := rotated.Issue(crypto.TokenCI)
	if err != nil || rec2.KeyVersion != 2 {
		t.Fatalf("new tokens must use the current version, got %d (%v)", rec2.KeyVersion, err)
	}
}

func TestPepperValidation(t *testing.T) {
	for name, peppers := range map[string]map[uint32]secret.Value{
		"short":   {1: secret.New(make([]byte, 16))},
		"missing": {},
		"zero":    {1: secret.New(make([]byte, 32))},
	} {
		if _, err := crypto.NewTokens(1, peppers); err == nil {
			t.Fatalf("%s pepper accepted", name)
		}
	}
}

// The credential types implemented here must be exactly the ones frozen in the
// permission catalog (ADR-0006, ADR-0007).
func TestTokenTypesMatchPermissionCatalog(t *testing.T) {
	data, err := os.ReadFile("../../../docs/rbac/permission-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		CredentialTypes []struct {
			ID          string `json:"id"`
			TokenPrefix string `json:"tokenPrefix"`
		} `json:"credentialTypes"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, c := range catalog.CredentialTypes {
		want[c.ID] = c.TokenPrefix
	}
	got := map[string]string{}
	for _, tt := range crypto.TokenTypes() {
		got[tt.Name] = tt.Prefix
	}
	if len(got) != len(want) {
		t.Fatalf("token types %v, catalog %v", got, want)
	}
	for id, prefix := range want {
		if got[id] != prefix {
			t.Fatalf("type %s: prefix %q, catalog %q", id, got[id], prefix)
		}
	}
}

func withType(r crypto.TokenRecord, typ string) crypto.TokenRecord  { r.Type = typ; return r }
func withLookup(r crypto.TokenRecord, id string) crypto.TokenRecord { r.LookupID = id; return r }
func withVersion(r crypto.TokenRecord, v uint32) crypto.TokenRecord { r.KeyVersion = v; return r }

func TestDigestIsKeyedAndPurposeBound(t *testing.T) {
	pepper := randomKey(t)
	tk := tokens(t, 1, map[uint32]secret.Value{1: pepper})
	a := tk.Digest("csrf", []byte("value"))
	if len(a) != 32 || string(a) != string(tk.Digest("csrf", []byte("value"))) {
		t.Fatal("digest must be a deterministic 32-byte MAC")
	}
	if string(a) == string(tk.Digest("throttle-account", []byte("value"))) {
		t.Fatal("different purposes must produce different digests")
	}
	if string(a) == string(tokens(t, 1, map[uint32]secret.Value{1: randomKey(t)}).Digest("csrf", []byte("value"))) {
		t.Fatal("the digest must depend on the pepper")
	}
	if strings.Contains(string(a), "value") {
		t.Fatal("digest leaks its input")
	}
}
