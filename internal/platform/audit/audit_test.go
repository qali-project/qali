package audit_test

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/audit"
	"github.com/qali-project/qali/internal/platform/secret"
)

func TestRedactRemovesSecretTypesAndSensitiveKeys(t *testing.T) {
	md := map[string]any{
		"name":          "Release 1.0",
		"token":         secret.New([]byte("qali_ci_plaintext-token")),
		"password":      "hunter2-plain",
		"Authorization": "Bearer abc.def",
		"nested": map[string]any{
			"client_secret": "oauth-client-secret",
			"api_key":       "k-123",
			"label":         "visible",
			"list":          []any{map[string]any{"refresh_token": "r-1"}, "plain item"},
		},
		"private_key":   "-----BEGIN KEY",
		"recovery_code": "ABCD-EFGH",
		"count":         3,
	}
	raw, err := audit.Redact(md)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, leaked := range []string{"qali_ci_plaintext-token", "hunter2-plain", "abc.def", "oauth-client-secret", "k-123", "r-1", "BEGIN KEY", "ABCD-EFGH"} { // gitleaks:allow fake fixture values asserted absent
		if strings.Contains(out, leaked) {
			t.Fatalf("redacted metadata leaks %q: %s", leaked, out)
		}
	}
	for _, kept := range []string{"Release 1.0", "visible", "plain item", `"count":3`} {
		if !strings.Contains(out, kept) {
			t.Fatalf("redaction removed non-sensitive %q: %s", kept, out)
		}
	}
	if strings.Count(out, secret.Redacted) != 8 {
		t.Fatalf("want 8 redaction markers, got %s", out)
	}
}

func TestRedactBoundsSize(t *testing.T) {
	if _, err := audit.Redact(map[string]any{"blob": strings.Repeat("x", 20000)}); !errors.Is(err, audit.ErrMetadataTooLarge) {
		t.Fatalf("err = %v, want ErrMetadataTooLarge", err)
	}
	empty, err := audit.Redact(nil)
	if err != nil || string(empty) != "{}" {
		t.Fatalf("nil metadata = %s, %v", empty, err)
	}
}

func TestEntryValidation(t *testing.T) {
	valid := audit.Entry{Action: "project.create", Outcome: audit.Success}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]audit.Entry{
		"no action":      {Outcome: audit.Success},
		"flat action":    {Action: "create", Outcome: audit.Success},
		"upper action":   {Action: "Project.Create", Outcome: audit.Success},
		"bad outcome":    {Action: "project.create", Outcome: "maybe"},
		"long target id": {Action: "project.create", Outcome: audit.Success, TargetID: strings.Repeat("x", 300)},
	} {
		if err := e.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func chainOf(t *testing.T, n int) []audit.Event {
	t.Helper()
	ws := uuid.MustParse("0199f0c2-1111-7000-8000-000000000001")
	var events []audit.Event
	var prev []byte
	for i := range n {
		e := audit.Event{
			ID:          uuid.MustParse("0199f0c2-3333-7000-8000-00000000000" + string(rune('1'+i))),
			Chain:       ws.String(),
			WorkspaceID: &ws,
			OccurredAt:  time.Date(2026, 10, 22, 12, 0, i, 0, time.UTC),
			Actor:       audit.Actor{Type: audit.ActorUser, ID: "user-1"},
			Action:      "case.update",
			TargetType:  "case",
			TargetID:    "case-1",
			Outcome:     audit.Success,
			RequestID:   "req",
			SourceIP:    netip.MustParseAddr("203.0.113.5"),
			Metadata:    json.RawMessage(`{"field":"title"}`),
			PrevHash:    prev,
		}
		e.Hash = audit.ComputeHash(e)
		prev = e.Hash
		events = append(events, e)
	}
	return events
}

func TestHashChainVerifies(t *testing.T) {
	if err := audit.VerifyChain(chainOf(t, 4)); err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyChain(nil); err != nil {
		t.Fatal(err)
	}
}

func TestHashChainDetectsTampering(t *testing.T) {
	cases := map[string]func([]audit.Event) []audit.Event{
		"edited field":      func(e []audit.Event) []audit.Event { e[1].Action = "case.delete"; return e },
		"edited metadata":   func(e []audit.Event) []audit.Event { e[2].Metadata = json.RawMessage(`{"field":"body"}`); return e },
		"edited actor":      func(e []audit.Event) []audit.Event { e[0].Actor.ID = "user-2"; return e },
		"edited time":       func(e []audit.Event) []audit.Event { e[3].OccurredAt = e[3].OccurredAt.Add(time.Second); return e },
		"deleted middle":    func(e []audit.Event) []audit.Event { return append(e[:1], e[2:]...) },
		"reordered":         func(e []audit.Event) []audit.Event { e[1], e[2] = e[2], e[1]; return e },
		"first not genesis": func(e []audit.Event) []audit.Event { return e[1:] },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			err := audit.VerifyChain(tamper(chainOf(t, 4)))
			if !errors.Is(err, audit.ErrChainBroken) {
				t.Fatalf("err = %v, want ErrChainBroken", err)
			}
		})
	}
}

func TestHashFieldsAreUnambiguous(t *testing.T) {
	a := chainOf(t, 1)[0]
	b := a
	a.TargetType, a.TargetID = "case", "x|y"
	b.TargetType, b.TargetID = "case|x", "y"
	if string(audit.ComputeHash(a)) == string(audit.ComputeHash(b)) {
		t.Fatal("shifting text between fields must change the hash")
	}
}

func TestActorValidation(t *testing.T) {
	if err := (audit.Actor{Type: audit.ActorOperator, ID: "ops"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (audit.Actor{Type: "robot"}).Validate(); err == nil {
		t.Fatal("unknown actor type accepted")
	}
	if err := (audit.Actor{Type: audit.ActorUser, ID: strings.Repeat("x", 300)}).Validate(); err == nil {
		t.Fatal("over-long actor ID accepted")
	}
}

func TestRedactHandlesSecretPointers(t *testing.T) {
	v := secret.New([]byte("pointer-secret"))
	raw, err := audit.Redact(map[string]any{"value": &v})
	if err != nil || strings.Contains(string(raw), "pointer-secret") {
		t.Fatalf("redact pointer: %s, %v", raw, err)
	}
	if _, err := audit.Redact(map[string]any{"bad": func() {}}); err == nil {
		t.Fatal("unencodable metadata accepted")
	}
}

func TestHashTreatsEmptyMetadataAsEmptyObject(t *testing.T) {
	e := chainOf(t, 1)[0]
	e.Metadata = nil
	withNil := audit.ComputeHash(e)
	e.Metadata = json.RawMessage(`{}`)
	if string(withNil) != string(audit.ComputeHash(e)) {
		t.Fatal("nil and empty metadata must hash identically")
	}
	e.Metadata = json.RawMessage(`{"b": 1, "a": 2}`)
	spaced := audit.ComputeHash(e)
	e.Metadata = json.RawMessage(`{"a":2,"b":1}`)
	if string(spaced) != string(audit.ComputeHash(e)) {
		t.Fatal("key order and whitespace must not change the hash (jsonb round trip)")
	}
}

// TestRedactInspectsEveryValueShape proves REVIEW-004: sensitive keys are
// redacted however the metadata is typed — typed maps, structs, slices of
// structs, raw JSON, and pointers — because redaction runs over the
// normalized JSON tree.
func TestRedactInspectsEveryValueShape(t *testing.T) {
	type creds struct {
		User        string `json:"user"`
		AccessToken string `json:"access_token"`
		Inner       struct {
			Password string
		} `json:"inner"`
	}
	c := creds{User: "visible-user", AccessToken: "leak-struct-token"}
	c.Inner.Password = "leak-struct-password"
	md := map[string]any{
		"details":  map[string]string{"token": "leak-typed-map", "note": "visible-note"},
		"struct":   c,
		"pointer":  &c,
		"list":     []creds{c},
		"nested":   map[string]map[string]any{"a": {"client_secret": "leak-deep"}},
		"raw":      json.RawMessage(`{"session_id":"leak-raw","ok":1}`),
		"rawArray": json.RawMessage(`[{"Authorization":"leak-raw-array"}]`),
	}
	raw, err := audit.Redact(md)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, leaked := range []string{"leak-typed-map", "leak-struct-token", "leak-struct-password", "leak-deep", "leak-raw", "leak-raw-array"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redacted metadata leaks %q: %s", leaked, out)
		}
	}
	for _, kept := range []string{"visible-user", "visible-note", `"ok":1`} {
		if !strings.Contains(out, kept) {
			t.Fatalf("redaction removed non-sensitive %q: %s", kept, out)
		}
	}
	if _, err := audit.Redact(map[string]any{"raw": json.RawMessage(`{not json`)}); err == nil {
		t.Fatal("unparseable raw JSON accepted")
	}
}
