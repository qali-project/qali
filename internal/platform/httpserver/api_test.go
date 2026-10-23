package httpserver_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/qali-project/qali/internal/platform/httpserver"
	"github.com/qali-project/qali/internal/platform/httpserver/openapi"
)

// stubAPI implements one operation and inherits 501 for the rest.
type stubAPI struct {
	openapi.Unimplemented
	called *bool
}

func (s stubAPI) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	*s.called = true
	httpserver.WriteJSON(w, http.StatusOK, openapi.SetupStatus{BootstrapRequired: true})
}

func TestFeatureAPIAndMiddlewaresAreMounted(t *testing.T) {
	called := false
	var seenRoute string
	opts := options(t)
	opts.API = stubAPI{called: &called}
	opts.APIMiddlewares = []openapi.MiddlewareFunc{func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenRoute = httpserver.Route(r)
			next.ServeHTTP(w, r)
		})
	}}
	h := httpserver.NewHandler(opts)

	rec := do(t, h, http.MethodGet, "/api/v1/setup", nil, nil)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("feature operation not served: %d", rec.Code)
	}
	if seenRoute != "GET /api/v1/setup" {
		t.Fatalf("middleware saw route %q", seenRoute)
	}
	if rec := do(t, h, http.MethodGet, "/health/live", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("health must stay served by the platform, got %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/v1/auth/logout", map[string]string{"Origin": publicOrigin}, nil); rec.Code != http.StatusNotImplemented {
		t.Fatalf("unimplemented operations answer 501, got %d", rec.Code)
	}
}

func TestDefaultAPIIsUnimplemented(t *testing.T) {
	rec := do(t, httpserver.NewHandler(options(t)), http.MethodGet, "/api/v1/setup", nil, nil)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func decodeInto(t *testing.T, body string, contentLength int64) (*httptest.ResponseRecorder, bool, openapi.LoginRequest) {
	t.Helper()
	var dst openapi.LoginRequest
	var ok bool
	h := httpserver.LimitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok = httpserver.DecodeJSON(w, r, &dst)
	}), 64)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(body))
	req.ContentLength = contentLength
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, ok, dst
}

func TestDecodeJSON(t *testing.T) {
	rec, ok, dst := decodeInto(t, `{"email":"a@b.io","password":"x"}`, -1)
	if !ok || dst.Email != "a@b.io" || rec.Code != http.StatusOK {
		t.Fatalf("valid body rejected: %d %+v", rec.Code, dst)
	}
	for name, body := range map[string]string{
		"unknown field": `{"email":"a@b.io","password":"x","admin":true}`,
		"trailing data": `{"email":"a@b.io","password":"x"} {}`,
		"not json":      `email=a@b.io`,
		"empty":         ``,
	} {
		rec, ok, _ := decodeInto(t, body, -1)
		if ok || rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_body"`) {
			t.Fatalf("%s: ok=%v status=%d body=%s", name, ok, rec.Code, rec.Body)
		}
	}
	rec, ok, _ = decodeInto(t, `{"email":"`+strings.Repeat("a", 100)+`"}`, -1)
	if ok || rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: ok=%v status=%d", ok, rec.Code)
	}
}

func TestClientAddrIsAvailableToHandlers(t *testing.T) {
	var addr netip.Addr
	opts := options(t)
	opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	opts.APIMiddlewares = []openapi.MiddlewareFunc{func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr = httpserver.ClientAddr(r.Context())
			next.ServeHTTP(w, r)
		})
	}}
	do(t, httpserver.NewHandler(opts), http.MethodGet, "/api/v1/setup", map[string]string{"X-Forwarded-For": "198.51.100.23"}, nil)
	if addr.String() != "198.51.100.23" {
		t.Fatalf("client address = %v", addr)
	}
}
