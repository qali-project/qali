// Package audit records append-only, attributable events
// (docs/SECURITY_ARCHITECTURE.md section 9). Metadata is redacted before it is
// stored, and every chain (one per workspace, plus "system") is hash-linked so
// edits, deletions, and reordering are detectable.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/secret"
)

// ActorType identifies the kind of principal (RBAC.md section 2).
type ActorType string

const (
	ActorUser        ActorType = "user"
	ActorCI          ActorType = "ci"
	ActorMCP         ActorType = "mcp"
	ActorIntegration ActorType = "integration"
	ActorSystem      ActorType = "system"
	ActorOperator    ActorType = "operator"
)

// Actor is the principal an event is attributed to.
type Actor struct {
	Type ActorType
	ID   string
}

// Validate checks the actor type.
func (a Actor) Validate() error {
	switch a.Type {
	case ActorUser, ActorCI, ActorMCP, ActorIntegration, ActorSystem, ActorOperator:
	default:
		return fmt.Errorf("audit: unknown actor type %q", a.Type)
	}
	if len(a.ID) > maxField {
		return errors.New("audit: actor ID too long")
	}
	return nil
}

// Outcome is the result of the audited action.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

const (
	maxField    = 255
	maxMetadata = 16 << 10
	// SystemChain holds events that belong to no workspace.
	SystemChain = "system"
)

var (
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

	ErrMetadataTooLarge = errors.New("audit: metadata exceeds 16 KiB")
	ErrChainBroken      = errors.New("audit: hash chain broken")
)

// Entry is what a caller records; the writer adds attribution and hashing.
type Entry struct {
	Action     string
	TargetType string
	TargetID   string
	Outcome    Outcome
	Metadata   map[string]any
}

// Validate checks the entry's shape.
func (e Entry) Validate() error {
	if !actionPattern.MatchString(e.Action) {
		return fmt.Errorf("audit: action %q must look like resource.verb", e.Action)
	}
	switch e.Outcome {
	case Success, Failure, Denied:
	default:
		return fmt.Errorf("audit: unknown outcome %q", e.Outcome)
	}
	if len(e.TargetType) > maxField || len(e.TargetID) > maxField {
		return errors.New("audit: target fields too long")
	}
	return nil
}

// Event is a stored audit record.
type Event struct {
	ID          uuid.UUID
	Chain       string
	WorkspaceID *uuid.UUID
	OccurredAt  time.Time
	Actor       Actor
	Action      string
	TargetType  string
	TargetID    string
	Outcome     Outcome
	RequestID   string
	SourceIP    netip.Addr
	Metadata    json.RawMessage
	PrevHash    []byte
	Hash        []byte
}

// sensitiveKeyParts mark metadata keys whose values are never stored.
var sensitiveKeyParts = []string{
	"password", "passphrase", "secret", "token", "authorization", "cookie",
	"api_key", "apikey", "private_key", "credential", "pepper", "recovery_code",
	"otp", "totp", "session", "signature",
}

func sensitiveKey(k string) bool {
	k = strings.ReplaceAll(strings.ToLower(k), "-", "_")
	for _, part := range sensitiveKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// Redact returns metadata as compact JSON with secret values and the values of
// sensitive keys replaced by secret.Redacted. The metadata is first encoded
// and decoded into a plain JSON tree, so every object key is inspected
// whatever Go type carried it (typed maps, structs, raw JSON); secret.Value
// encodes as the redaction marker (REVIEW-004).
func Redact(md map[string]any) (json.RawMessage, error) {
	if md == nil {
		md = map[string]any{}
	}
	encoded, err := json.Marshal(md)
	if err != nil {
		return nil, fmt.Errorf("audit: encode metadata: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("audit: normalize metadata: %w", err)
	}
	b, err := json.Marshal(redactTree(tree))
	if err != nil {
		return nil, fmt.Errorf("audit: encode metadata: %w", err)
	}
	if len(b) > maxMetadata {
		return nil, ErrMetadataTooLarge
	}
	return b, nil
}

// redactTree walks a decoded JSON value; only objects and arrays nest.
func redactTree(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if sensitiveKey(k) {
				out[k] = secret.Redacted
			} else {
				out[k] = redactTree(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = redactTree(val)
		}
		return out
	default:
		return v
	}
}

// ComputeHash returns SHA-256 over the event's fields and previous hash.
// Fields are length-prefixed and metadata is canonicalized so the hash is
// stable across a database round trip.
func ComputeHash(e Event) []byte {
	ws := ""
	if e.WorkspaceID != nil {
		ws = e.WorkspaceID.String()
	}
	ip := ""
	if e.SourceIP.IsValid() {
		ip = e.SourceIP.String()
	}
	h := sha256.New()
	for _, f := range []string{
		"qali/audit/v1", e.ID.String(), e.Chain, ws,
		e.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		string(e.Actor.Type), e.Actor.ID, e.Action, e.TargetType, e.TargetID,
		string(e.Outcome), e.RequestID, ip, string(canonical(e.Metadata)), hex.EncodeToString(e.PrevHash),
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f))) //nolint:gosec // G115: fields are bounded far below 4 GiB
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return h.Sum(nil)
}

// canonical re-encodes JSON with sorted keys and no insignificant whitespace.
func canonical(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// VerifyChain checks that events form an unbroken chain from its first event.
func VerifyChain(events []Event) error {
	var prev []byte
	for i, e := range events {
		if !bytes.Equal(e.PrevHash, prev) {
			return fmt.Errorf("%w at position %d: previous hash does not match", ErrChainBroken, i)
		}
		if !bytes.Equal(ComputeHash(e), e.Hash) {
			return fmt.Errorf("%w at position %d: content does not match its hash", ErrChainBroken, i)
		}
		prev = e.Hash
	}
	return nil
}
