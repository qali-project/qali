package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
)

func readiness(t *testing.T, check func(context.Context) error) (int, openapi.Readiness, string) {
	t.Helper()
	var logs bytes.Buffer
	opts := options(t)
	opts.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	opts.Ready = check
	rec := do(t, httpserver.NewHandler(opts), http.MethodGet, "/health/ready", nil, nil)
	var body openapi.Readiness
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("readiness body does not match the contract: %v", err)
	}
	return rec.Code, body, logs.String()
}

func TestReadyWhenChecksPass(t *testing.T) {
	var hadDeadline bool
	code, body, _ := readiness(t, func(ctx context.Context) error {
		_, hadDeadline = ctx.Deadline()
		return nil
	})
	if code != http.StatusOK || body.Status != openapi.Ready {
		t.Fatalf("status %d body %+v", code, body)
	}
	if !hadDeadline {
		t.Fatal("readiness checks must run with a deadline")
	}
}

func TestNotReadyExposesOnlyABoolean(t *testing.T) {
	reason := errors.New("database qali_app:hunter2@db unavailable: migrations pending at version 2")
	code, body, logs := readiness(t, func(context.Context) error { return reason })
	if code != http.StatusServiceUnavailable || body.Status != openapi.NotReady {
		t.Fatalf("status %d body %+v", code, body)
	}
	if !strings.Contains(logs, "migrations pending") {
		t.Fatalf("the reason must be logged for operators: %s", logs)
	}
}

func TestReadyWithoutChecks(t *testing.T) {
	code, body, _ := readiness(t, nil)
	if code != http.StatusOK || body.Status != openapi.Ready {
		t.Fatalf("status %d body %+v", code, body)
	}
}
