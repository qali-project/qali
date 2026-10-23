package domain_test

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/identity/domain"
)

// RFC 6238 appendix B uses this ASCII seed for SHA-1. The RFC's 8-digit
// values truncate to the 6 digits used here.
var rfcSecret = []byte("12345678901234567890")

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	vectors := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range vectors {
		step := domain.TOTPStep(time.Unix(unix, 0))
		if got := domain.TOTPCode(rfcSecret, step); got != want {
			t.Fatalf("code at %d = %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPAcceptsOnlyAdjacentStepsOnce(t *testing.T) {
	now := time.Unix(1111111111, 0)
	step := domain.TOTPStep(now)
	code := func(s int64) string { return domain.TOTPCode(rfcSecret, s) }

	for _, offset := range []int64{-1, 0, 1} {
		got, ok := domain.VerifyTOTP(rfcSecret, code(step+offset), now, 0)
		if !ok || got != step+offset {
			t.Fatalf("offset %d rejected", offset)
		}
	}
	for _, offset := range []int64{-2, 2, 10} {
		if _, ok := domain.VerifyTOTP(rfcSecret, code(step+offset), now, 0); ok {
			t.Fatalf("offset %d accepted outside the window", offset)
		}
	}
	// Replay: a step at or before the last accepted step is rejected.
	if _, ok := domain.VerifyTOTP(rfcSecret, code(step), now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := domain.VerifyTOTP(rfcSecret, code(step-1), now, step); ok {
		t.Fatal("older code accepted after a newer one")
	}
	if _, ok := domain.VerifyTOTP(rfcSecret, code(step+1), now, step); !ok {
		t.Fatal("next step rejected after the current one was used")
	}
	for _, malformed := range []string{"", "12345", "1234567", "12345a", " 123456"} {
		if _, ok := domain.VerifyTOTP(rfcSecret, malformed, now, 0); ok {
			t.Fatalf("malformed code %q accepted", malformed)
		}
	}
}

func TestTOTPSecretsAndURI(t *testing.T) {
	a, b := domain.NewTOTPSecret(), domain.NewTOTPSecret()
	if len(a) != 20 || bytes.Equal(a, b) {
		t.Fatal("secrets must be 160 random bits")
	}
	encoded := domain.EncodeTOTPSecret(a)
	if strings.ContainsAny(encoded, "=") || len(encoded) != 32 {
		t.Fatalf("encoded secret %q", encoded)
	}
	uri, err := url.Parse(domain.TOTPURI("Qali", "owner@example.org", a))
	if err != nil {
		t.Fatal(err)
	}
	q := uri.Query()
	if uri.Scheme != "otpauth" || uri.Host != "totp" || q.Get("secret") != encoded || q.Get("issuer") != "Qali" ||
		q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" {
		t.Fatalf("otpauth URI = %s", uri)
	}
	if !strings.HasSuffix(uri.Path, "Qali:owner@example.org") {
		t.Fatalf("label = %s", uri.Path)
	}
}
