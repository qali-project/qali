package httpserver_test

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/qali-project/qali/internal/platform/clock"
	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
)

const publicOrigin = "https://qali.example.org"

func options(t *testing.T) httpserver.Options {
	t.Helper()
	u, err := url.Parse(publicOrigin)
	if err != nil {
		t.Fatal(err)
	}
	return httpserver.Options{
		UI:           fstest.MapFS{"index.html": {Data: []byte(indexHTML)}},
		PublicURL:    u,
		Clock:        clock.NewManual(time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)),
		MaxBodyBytes: 1024,
		RateLimit:    httpserver.RateLimit{PerSecond: 1000, Burst: 1000},
		Logger:       slog.New(slog.DiscardHandler),
	}
}

// strictOptions allows a burst of three requests per client.
func strictOptions(t *testing.T) httpserver.Options {
	t.Helper()
	opts := options(t)
	opts.RateLimit = httpserver.RateLimit{PerSecond: 1, Burst: 3}
	return opts
}

// do sends a request through the real handler and returns the recorder.
func do(t *testing.T, h http.Handler, method, path string, headers map[string]string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, body)
	req.RemoteAddr = "203.0.113.10:51000"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder) openapi.Problem {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var p openapi.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body %q: %v", rec.Body.String(), err)
	}
	if p.Status != rec.Code || p.Code == "" || p.RequestId == "" || p.RequestId != rec.Header().Get("X-Request-ID") {
		t.Fatalf("problem = %+v, status %d, header id %q", p, rec.Code, rec.Header().Get("X-Request-ID"))
	}
	return p
}

var requestID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestEveryResponseHasAFreshRequestID(t *testing.T) {
	h := httpserver.NewHandler(options(t))
	a := do(t, h, http.MethodGet, "/health/live", map[string]string{"X-Request-ID": "attacker-chosen"}, nil)
	b := do(t, h, http.MethodGet, "/health/live", nil, nil)
	idA, idB := a.Header().Get("X-Request-ID"), b.Header().Get("X-Request-ID")
	if !requestID.MatchString(idA) || !requestID.MatchString(idB) || idA == idB {
		t.Fatalf("request IDs %q and %q must be distinct server-generated values", idA, idB)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := httpserver.NewHandler(options(t))
	for _, path := range []string{"/", "/health/live", "/api/v1/unknown"} {
		rec := do(t, h, http.MethodGet, path, nil, nil)
		want := map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"X-Frame-Options":              "DENY",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Strict-Transport-Security":    "max-age=63072000; includeSubDomains",
		}
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Fatalf("%s %s = %q, want %q", path, k, got, v)
			}
		}
		csp := rec.Header().Get("Content-Security-Policy")
		for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'", "script-src 'self'"} {
			if !strings.Contains(csp, directive) {
				t.Fatalf("%s CSP %q lacks %q", path, csp, directive)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Fatalf("CSP must not allow inline or eval: %q", csp)
		}
		if rec.Header().Get("Permissions-Policy") == "" {
			t.Fatalf("%s lacks Permissions-Policy", path)
		}
	}
}

func TestHSTSIsOnlySentForHTTPSOrigins(t *testing.T) {
	opts := options(t)
	opts.PublicURL, _ = url.Parse("http://localhost:8080")
	rec := do(t, httpserver.NewHandler(opts), http.MethodGet, "/health/live", nil, nil)
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent for an http development origin")
	}
}

func TestAPIResponsesAreNotCached(t *testing.T) {
	rec := do(t, httpserver.NewHandler(options(t)), http.MethodGet, "/api/v1/unknown", nil, nil)
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
}

func TestUnknownAPIRouteIsAProblem(t *testing.T) {
	rec := do(t, httpserver.NewHandler(options(t)), http.MethodGet, "/api/v1/unknown", nil, nil)
	if rec.Code != http.StatusNotFound || decodeProblem(t, rec).Code != "not_found" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestUnsafeCrossSiteBrowserRequestsAreRejected(t *testing.T) {
	h := httpserver.NewHandler(options(t))
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"same origin passes to routing", map[string]string{"Origin": publicOrigin, "Sec-Fetch-Site": "same-origin"}, http.StatusNotFound},
		{"same origin without fetch metadata", map[string]string{"Origin": publicOrigin}, http.StatusNotFound},
		{"same origin via referer", map[string]string{"Referer": publicOrigin + "/projects"}, http.StatusNotFound},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"origin null", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"scheme downgrade", map[string]string{"Origin": "http://qali.example.org"}, http.StatusForbidden},
		{"cross-site fetch metadata", map[string]string{"Origin": publicOrigin, "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site sibling", map[string]string{"Origin": publicOrigin, "Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"foreign referer", map[string]string{"Referer": "https://evil.example/x"}, http.StatusForbidden},
		{"no origin evidence", nil, http.StatusForbidden},
		{"bearer credential", map[string]string{"Authorization": "Bearer qali_ci_x"}, http.StatusNotFound},
	}
	for _, tc := range cases {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			t.Run(tc.name+" "+method, func(t *testing.T) {
				rec := do(t, h, method, "/api/v1/anything", tc.headers, nil)
				if rec.Code != tc.want {
					t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
				}
				if tc.want == http.StatusForbidden && decodeProblem(t, rec).Code != "cross_site_request" {
					t.Fatal("wrong problem code")
				}
			})
		}
	}
	if rec := do(t, h, http.MethodGet, "/health/live", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("safe methods are not blocked, got %d", rec.Code)
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	h := httpserver.NewHandler(options(t))
	same := map[string]string{"Origin": publicOrigin}
	big := do(t, h, http.MethodPost, "/api/v1/anything", same, strings.NewReader(strings.Repeat("x", 1025)))
	if big.Code != http.StatusRequestEntityTooLarge || decodeProblem(t, big).Code != "body_too_large" {
		t.Fatalf("status %d body %s", big.Code, big.Body)
	}
	small := do(t, h, http.MethodPost, "/api/v1/anything", same, strings.NewReader(strings.Repeat("x", 1024)))
	if small.Code != http.StatusNotFound {
		t.Fatalf("a body at the limit must pass, got %d", small.Code)
	}
}

func TestBodyLimitAppliesWhileReading(t *testing.T) {
	// A body without Content-Length is limited by the reader itself.
	limited := httpserver.LimitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			httpserver.WriteBodyError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), 16)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", io.NopCloser(strings.NewReader(strings.Repeat("x", 17))))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	limited.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestRateLimitPerClient(t *testing.T) {
	opts := strictOptions(t)
	manual := opts.Clock.(*clock.Manual)
	h := httpserver.NewHandler(opts)
	get := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/x", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := range 3 {
		if rec := get("203.0.113.10:1"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d within burst was limited", i+1)
		}
	}
	limited := get("203.0.113.10:2")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d Retry-After %q", limited.Code, limited.Header().Get("Retry-After"))
	}
	if decodeProblem(t, limited).Code != "rate_limited" {
		t.Fatal("wrong problem code")
	}
	if rec := get("198.51.100.7:1"); rec.Code == http.StatusTooManyRequests {
		t.Fatal("another client must have its own budget")
	}
	manual.Advance(time.Second)
	if rec := get("203.0.113.10:3"); rec.Code == http.StatusTooManyRequests {
		t.Fatal("budget must refill over time")
	}
}

func TestProbesAreNotRateLimited(t *testing.T) {
	h := httpserver.NewHandler(strictOptions(t))
	for range 10 {
		if rec := do(t, h, http.MethodGet, "/health/live", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("probe status %d", rec.Code)
		}
	}
}

func TestForwardedForIsTrustedOnlyFromConfiguredProxies(t *testing.T) {
	opts := strictOptions(t)
	opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	h := httpserver.NewHandler(opts)
	send := func(remote, xff string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/x", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Through the trusted proxy, distinct clients get distinct budgets.
	for range 3 {
		send("10.0.0.2:1", "198.51.100.1")
	}
	if send("10.0.0.2:1", "198.51.100.1") != http.StatusTooManyRequests {
		t.Fatal("client behind the proxy was not limited")
	}
	if send("10.0.0.2:1", "198.51.100.2") == http.StatusTooManyRequests {
		t.Fatal("a different client behind the proxy shares the budget")
	}
	// From an untrusted peer, a spoofed header does not create new budgets.
	for range 3 {
		send("203.0.113.50:1", "192.0.2.1")
	}
	if send("203.0.113.50:1", "192.0.2.99") != http.StatusTooManyRequests {
		t.Fatal("spoofed X-Forwarded-For from an untrusted peer bypassed the limit")
	}
}

type panickingFS struct{}

func (panickingFS) Open(string) (fs.File, error) { panic("disk exploded at /var/lib/secret/path") }

func TestPanicsBecomeSafeProblems(t *testing.T) {
	opts := options(t)
	opts.UI = panickingFS{}
	rec := do(t, httpserver.NewHandler(opts), http.MethodGet, "/projects", nil, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	p := decodeProblem(t, rec)
	if p.Code != "internal_error" || strings.Contains(rec.Body.String(), "exploded") || strings.Contains(rec.Body.String(), "goroutine") {
		t.Fatalf("unsafe error body: %s", rec.Body)
	}
}
