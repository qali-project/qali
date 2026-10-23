package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/qali-project/qali/internal/platform/config"
)

func TestStartupFailsClosedWithoutConfiguration(t *testing.T) {
	src := config.Source{
		Getenv:   func(string) (string, bool) { return "", false },
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
	err := run(t.Context(), slog.New(slog.DiscardHandler), src)
	var cerr *config.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("run returned %v, want a configuration error before listening", err)
	}
	if !strings.Contains(err.Error(), "QALI_KEK_FILE") {
		t.Fatalf("error should name missing settings: %v", err)
	}
}

func TestLogTimestampsAreUTC(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: utcTime}))
	plus5 := time.FixedZone("UTC+5", 5*60*60)
	record := slog.NewRecord(time.Date(2026, 10, 22, 7, 3, 0, 0, plus5), slog.LevelInfo, "listening", 0)
	if err := logger.Handler().Handle(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	var line struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line.Time != "2026-10-22T02:03:00Z" {
		t.Fatalf("time = %q, want 2026-10-22T02:03:00Z", line.Time)
	}
}

func emptySource() config.Source {
	return config.Source{
		Getenv:   func(string) (string, bool) { return "", false },
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
}
