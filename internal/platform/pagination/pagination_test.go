package pagination_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qali-project/qali/internal/platform/pagination"
)

func mac(key string) func(string, []byte) []byte {
	return func(purpose string, data []byte) []byte {
		h := hmac.New(sha256.New, []byte(key+purpose))
		h.Write(data)
		return h.Sum(nil)
	}
}

func TestCursorRoundTripAndBinding(t *testing.T) {
	c := pagination.NewCodec(mac("k1"))
	after := uuid.New()
	cur := c.Encode("members|ws|user", after)
	got, err := c.Decode("members|ws|user", cur)
	if err != nil || got != after {
		t.Fatalf("round trip: %v %v", got, err)
	}
	if got, err := c.Decode("anything", ""); err != nil || got != uuid.Nil {
		t.Fatalf("empty cursor starts at the beginning: %v %v", got, err)
	}
	for name, bad := range map[string]func() (uuid.UUID, error){
		"other binding": func() (uuid.UUID, error) { return c.Decode("projects|ws|user", cur) },
		"other key":     func() (uuid.UUID, error) { return pagination.NewCodec(mac("k2")).Decode("members|ws|user", cur) },
		"not base64":    func() (uuid.UUID, error) { return c.Decode("members|ws|user", "***") },
		"short":         func() (uuid.UUID, error) { return c.Decode("members|ws|user", cur[:10]) },
		"flipped":       func() (uuid.UUID, error) { return c.Decode("members|ws|user", "A"+cur[1:]) },
	} {
		if _, err := bad(); !errors.Is(err, pagination.ErrInvalidCursor) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLimit(t *testing.T) {
	n := func(v int) *int { return &v }
	for _, c := range []struct {
		in   *int
		want int
		ok   bool
	}{{nil, 50, true}, {n(1), 1, true}, {n(200), 200, true}, {n(0), 0, false}, {n(201), 0, false}, {n(-1), 0, false}} {
		got, err := pagination.Limit(c.in)
		if (err == nil) != c.ok || (c.ok && got != c.want) {
			t.Errorf("Limit(%v) = %d, %v", c.in, got, err)
		}
	}
}

func TestPage(t *testing.T) {
	c := pagination.NewCodec(mac("k"))
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	items, next := pagination.Page(c, "b", ids, 2, func(id uuid.UUID) uuid.UUID { return id })
	if len(items) != 2 || next == nil {
		t.Fatalf("a full page has a next cursor: %d %v", len(items), next)
	}
	if after, _ := c.Decode("b", *next); after != ids[1] {
		t.Fatal("the cursor points after the last item")
	}
	items, next = pagination.Page(c, "b", ids[:2], 2, func(id uuid.UUID) uuid.UUID { return id })
	if len(items) != 2 || next != nil {
		t.Fatal("the last page has no cursor")
	}
}
