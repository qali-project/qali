package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/db"
)

// A client that goes away is not a server failure: it must not be logged
// as an error that hides real ones.
func TestClientCancellationIsNotAnError(t *testing.T) {
	var logs bytes.Buffer
	h := &Handler{logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	w := httptest.NewRecorder()
	h.fail(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), fmt.Errorf("query: %w", db.MapError(context.Canceled)))
	if w.Code != 499 || strings.Contains(logs.String(), `"level":"ERROR"`) {
		t.Fatalf("status %d, logs %s", w.Code, logs.String())
	}

	logs.Reset()
	w = httptest.NewRecorder()
	h.fail(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), errors.New("boom"))
	if w.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), `"cause":"boom"`) {
		t.Fatalf("status %d, logs %s", w.Code, logs.String())
	}
}
