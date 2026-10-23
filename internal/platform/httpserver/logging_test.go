package httpserver_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/metrics"
)

type logLine struct {
	Msg        string  `json:"msg"`
	RequestID  string  `json:"request_id"`
	Method     string  `json:"method"`
	Route      string  `json:"route"`
	Status     int     `json:"status"`
	DurationMS float64 `json:"duration_ms"`
}

func requestLogs(t *testing.T, raw string) []logLine {
	t.Helper()
	var out []logLine
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		var l logLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		if l.Msg == "http request" {
			out = append(out, l)
		}
	}
	return out
}

func TestRequestLogsCarryAttributionButNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	opts := options(t)
	opts.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	h := httpserver.NewHandler(opts)

	get := do(t, h, http.MethodGet, "/api/v1/projects?token=supersecret-query", map[string]string{
		"Authorization": "Bearer topsecret-bearer",
		"Cookie":        "__Host-qali_session=cookie-secret",
	}, nil)
	post := do(t, h, http.MethodPost, "/api/v1/projects", map[string]string{"Origin": "https://evil.example"},
		strings.NewReader(`{"password":"body-secret"}`))

	raw := buf.String()
	for _, leak := range []string{"supersecret-query", "token=", "topsecret-bearer", "cookie-secret", "body-secret", "/api/v1/projects?"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("request log leaked %q: %s", leak, raw)
		}
	}
	lines := requestLogs(t, raw)
	if len(lines) != 2 {
		t.Fatalf("want 2 request log lines, got %d: %s", len(lines), raw)
	}
	first, second := lines[0], lines[1]
	if first.RequestID != get.Header().Get("X-Request-ID") || first.Method != http.MethodGet || first.Status != 404 || first.Route != "unmatched" {
		t.Fatalf("first line = %+v", first)
	}
	if second.RequestID != post.Header().Get("X-Request-ID") || second.Status != 403 || second.DurationMS < 0 {
		t.Fatalf("second line = %+v (requests rejected by middleware must be logged too)", second)
	}
}

func TestProbesAreNotLoggedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	opts := options(t)
	opts.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	do(t, httpserver.NewHandler(opts), http.MethodGet, "/health/live", nil, nil)
	if lines := requestLogs(t, buf.String()); len(lines) != 0 {
		t.Fatalf("probe logged at info level: %+v", lines)
	}
}

func TestHTTPMetricsUseRoutePatterns(t *testing.T) {
	m := metrics.NewMemory()
	opts := options(t)
	opts.Metrics = m
	h := httpserver.NewHandler(opts)
	do(t, h, http.MethodGet, "/health/live", nil, nil)
	do(t, h, http.MethodGet, "/health/live", nil, nil)
	do(t, h, http.MethodGet, "/api/v1/projects/0199f0c2-1111-7000-8000-000000000001", nil, nil)

	if got := m.Counter("http_requests_total", metrics.Labels{"method": "GET", "route": "/health/live", "status": "200"}); got != 2 {
		t.Fatalf("liveness counter = %d, want 2", got)
	}
	if got := m.Counter("http_requests_total", metrics.Labels{"method": "GET", "route": "unmatched", "status": "404"}); got != 1 {
		t.Fatalf("unmatched counter = %d; identifiers must never become label values", got)
	}
	if n, _ := m.Observations("http_request_duration_seconds", metrics.Labels{"route": "/health/live"}); n != 2 {
		t.Fatalf("duration observations = %d", n)
	}
}
