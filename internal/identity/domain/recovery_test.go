package domain_test

import (
	"errors"
	"regexp"
	"testing"

	"github.com/qali-project/qali/internal/identity/domain"
)

var displayFormat = regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)

func TestRecoveryCodesAreDistinctAndWellFormed(t *testing.T) {
	codes := domain.NewRecoveryCodes()
	if len(codes) != domain.RecoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), domain.RecoveryCodeCount)
	}
	lookups := map[string]bool{}
	for _, c := range codes {
		if !displayFormat.MatchString(c.Display) {
			t.Fatalf("display %q", c.Display)
		}
		if lookups[c.Lookup] {
			t.Fatal("lookup IDs must be distinct within a set")
		}
		lookups[c.Lookup] = true
		lookup, secret, err := domain.ParseRecoveryCode(c.Display)
		if err != nil || lookup != c.Lookup || secret != c.Secret {
			t.Fatalf("parse(%q) = %q %q %v", c.Display, lookup, secret, err)
		}
	}
}

func TestParseRecoveryCodeIsForgivingAboutFormattingOnly(t *testing.T) {
	lookup, secret, err := domain.ParseRecoveryCode(" abcd efgh-ijkl mnop ")
	if err != nil || lookup != "ABCD" || secret != "EFGHIJKLMNOP" {
		t.Fatalf("got %q %q %v", lookup, secret, err)
	}
	for _, bad := range []string{"", "ABCD-EFGH-IJKL", "ABCD-EFGH-IJKL-MNOP-QRST", "ABC1-EFGH-IJKL-MNOP", "ABCD-EFGH-IJKL-MNO8"} {
		if _, _, err := domain.ParseRecoveryCode(bad); !errors.Is(err, domain.ErrInvalidRecoveryCode) {
			t.Fatalf("ParseRecoveryCode(%q) err = %v", bad, err)
		}
	}
}
