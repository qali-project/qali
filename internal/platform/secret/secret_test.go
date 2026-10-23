package secret_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/secret"
)

const plaintext = "correct-horse-battery-staple"

type holder struct {
	Name  string
	Token secret.Value
}

func assertRedacted(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, plaintext) || strings.Contains(out, fmt.Sprintf("%x", plaintext)) {
		t.Fatalf("%s leaked the secret: %q", where, out)
	}
	if !strings.Contains(out, secret.Redacted) {
		t.Fatalf("%s did not show the redaction marker: %q", where, out)
	}
}

func TestFormattingNeverRevealsValue(t *testing.T) {
	v := secret.New([]byte(plaintext))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		assertRedacted(t, verb, fmt.Sprintf(verb, v))
		assertRedacted(t, verb+" in struct", fmt.Sprintf(verb, holder{Name: "n", Token: v}))
		assertRedacted(t, verb+" via pointer", fmt.Sprintf(verb, &v))
	}
	assertRedacted(t, "String", v.String())
	assertRedacted(t, "GoString", v.GoString())
}

func TestSerializationNeverRevealsValue(t *testing.T) {
	v := secret.New([]byte(plaintext))
	b, err := json.Marshal(holder{Name: "n", Token: v})
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, "json", string(b))

	text, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, "text", string(text))
}

func TestLoggingNeverRevealsValue(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	v := secret.New([]byte(plaintext))
	logger.Info("loaded", "token", v, "holder", holder{Token: v}, slog.Any("ptr", &v))
	text := slog.New(slog.NewTextHandler(&buf, nil))
	text.Info("loaded", "token", v)
	if strings.Contains(buf.String(), plaintext) {
		t.Fatalf("log leaked the secret: %s", buf.String())
	}
	if strings.Count(buf.String(), secret.Redacted) < 2 {
		t.Fatalf("log did not redact: %s", buf.String())
	}
}

func TestErrorsNeverRevealValue(t *testing.T) {
	v := secret.New([]byte(plaintext))
	err := fmt.Errorf("connect with %v: %w", v, errors.New("refused"))
	assertRedacted(t, "error", err.Error())
}

func TestExposeReturnsAnIndependentCopy(t *testing.T) {
	input := []byte(plaintext)
	v := secret.New(input)
	input[0] = 'X'
	got := v.Expose()
	if string(got) != plaintext {
		t.Fatalf("New must copy its input; got %q", got)
	}
	got[0] = 'Y'
	if string(v.Expose()) != plaintext {
		t.Fatal("Expose must return a copy that cannot modify the secret")
	}
}

func TestEqualAndZero(t *testing.T) {
	a := secret.New([]byte(plaintext))
	if !a.Equal(secret.New([]byte(plaintext))) {
		t.Fatal("equal values must compare equal")
	}
	if a.Equal(secret.New([]byte(plaintext + "x"))) {
		t.Fatal("different values must not compare equal")
	}
	var zero secret.Value
	if !zero.IsZero() || a.IsZero() || a.Len() != len(plaintext) {
		t.Fatal("IsZero/Len report wrong values")
	}
}
