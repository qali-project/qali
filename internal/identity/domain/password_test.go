package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/identity/domain"
)

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"Owner@Example.ORG":       "owner@example.org",
		"  owner@example.org \n":  "owner@example.org",
		"ｏｗｎｅｒ@example.org":       "owner@example.org", // full-width letters (NFKC)
		"first.last+tag@sub.a.io": "first.last+tag@sub.a.io",
	}
	for in, want := range cases {
		got, err := domain.NormalizeEmail(in)
		if err != nil || got != want {
			t.Fatalf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "owner", "@example.org", "owner@", "a@b@c", "own er@example.org", strings.Repeat("a", 250) + "@x.io"} {
		if _, err := domain.NormalizeEmail(bad); !errors.Is(err, domain.ErrInvalidEmail) {
			t.Fatalf("NormalizeEmail(%q) err = %v, want ErrInvalidEmail", bad, err)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	ok := []string{
		"correct horse battery",
		strings.Repeat("a", 12),
		strings.Repeat("ü", 12), // counts characters, not bytes
		strings.Repeat("x", 256),
	}
	for _, p := range ok {
		if err := domain.ValidatePassword(p, "owner@example.org"); err != nil {
			t.Fatalf("ValidatePassword(%q) = %v", p, err)
		}
	}
	bad := map[string]string{
		"too short":             "elevenchars",
		"too long":              strings.Repeat("x", 257),
		"equals email":          "owner@example.org",
		"equals email any case": "OWNER@EXAMPLE.ORG",
		"equals local part":     "ownerownerow" + "",
		"control character":     "valid passwor\x00d",
	}
	for name, p := range bad {
		email := "owner@example.org"
		if name == "equals local part" {
			email = "ownerownerow@example.org"
		}
		if err := domain.ValidatePassword(p, email); !errors.Is(err, domain.ErrWeakPassword) {
			t.Fatalf("%s: err = %v, want ErrWeakPassword", name, err)
		}
	}
}
